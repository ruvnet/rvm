//! The instance: one execution of one verified package, under one adapter.
//!
//! # Ordering rules that are not negotiable
//!
//! **Verification precedes creation.** [`Instance::create`] takes a
//! [`VerifiedPackage`], whose only constructor rejects a failed verification
//! report. There is no path from raw bytes to a running instance that skips
//! `rvm-rvf`.
//!
//! **Isolation precedes execution.** `create` prepares the isolation context
//! and applies the capability set; [`Instance::start`] is the only method that
//! admits a module. An instance in [`InstanceState::Created`] has a boundary
//! and no code inside it.
//!
//! **The witness record precedes the effect.** Every refusal — an illegal
//! transition, a lineage mismatch, a capability the adapter cannot enforce —
//! is written to the log before the error is returned, so a caller that drops
//! the error still leaves the refusal in the chain.

use alloc::vec::Vec;
use rvm_host::{HostAdapter, IsolationContext, Placement, VerifiedPackage};
use rvm_types::{fnv1a_32, WitnessRecord};
use rvm_wasm::agent::{AgentId, AgentManager};
use rvm_witness::WitnessLog;

use crate::checkpoint::Checkpoint;
use crate::context::ContextLaunchAuthorization;
use crate::error::{LaunchError, LaunchResult};
use crate::state::{is_legal, InstanceId, InstanceState, LifecycleOp};
use crate::witness::{emit, emit_illegal, LaunchEvent, LaunchWitnessContext};

/// A half-open span of witness sequence numbers.
type SeqRange = (u64, u64);

/// One execution of one verified package.
#[derive(Debug)]
pub struct Instance<A: HostAdapter> {
    id: InstanceId,
    adapter: A,
    package: VerifiedPackage,
    isolation: IsolationContext,
    state: InstanceState,
    agent: Option<AgentId>,
    checkpoints: u32,
    ranges: Vec<SeqRange>,
    context_authorization: Option<ContextLaunchAuthorization>,
}

impl<A: HostAdapter> Instance<A> {
    /// Prepare isolation for `package` and apply its capability set.
    ///
    /// Nothing executes: this allocates the boundary, records every capability
    /// decision, and stops. The returned instance is in
    /// [`InstanceState::Created`].
    ///
    /// # Errors
    ///
    /// [`LaunchError::Host`] when the adapter refuses — most often because the
    /// package declares a capability class the adapter cannot enforce, which
    /// ADR-286 §3 makes a refusal rather than a narrowed start. The refusal is
    /// already in the witness chain by then.
    pub fn create<const N: usize>(
        id: InstanceId,
        adapter: A,
        package: VerifiedPackage,
        placement: Placement,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<Self> {
        let start = log.total_emitted();
        let isolation = adapter.prepare(&package, placement, log, timestamp_ns)?;

        let ctx = LaunchWitnessContext {
            instance: id,
            rvf_identity: *package.identity(),
            partition: placement.partition,
            timestamp_ns,
        };
        emit(
            log,
            LaunchEvent::InstanceCreated,
            &ctx,
            InstanceState::Created,
            u32::try_from(isolation.granted.len()).unwrap_or(u32::MAX),
        );

        Ok(Self {
            id,
            adapter,
            package,
            isolation,
            state: InstanceState::Created,
            agent: None,
            checkpoints: 0,
            ranges: alloc::vec![(start, log.total_emitted())],
            context_authorization: None,
        })
    }

    /// This instance's identifier.
    #[must_use]
    pub const fn id(&self) -> InstanceId {
        self.id
    }

    /// The current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> InstanceState {
        self.state
    }

    /// The isolation context the adapter prepared, including the claim it
    /// obtained and the mechanisms it engaged.
    #[must_use]
    pub const fn isolation(&self) -> &IsolationContext {
        &self.isolation
    }

    /// The verified package this instance runs.
    #[must_use]
    pub const fn package(&self) -> &VerifiedPackage {
        &self.package
    }

    /// Governed context authorization consumed during creation, when present.
    #[must_use]
    pub const fn context_authorization(&self) -> Option<&ContextLaunchAuthorization> {
        self.context_authorization.as_ref()
    }

    pub(crate) fn attach_context_authorization(
        &mut self,
        authorization: ContextLaunchAuthorization,
    ) {
        self.context_authorization = Some(authorization);
    }

    /// The adapter providing the boundary.
    #[must_use]
    pub const fn adapter(&self) -> &A {
        &self.adapter
    }

    /// The agent identifier, once execution has begun.
    #[must_use]
    pub const fn agent(&self) -> Option<AgentId> {
        self.agent
    }

    /// Admit `module` and begin execution.
    ///
    /// # Errors
    ///
    /// [`LaunchError::IllegalTransition`] unless the instance is
    /// [`InstanceState::Created`], [`LaunchError::Host`] when the module fails
    /// admission, and [`LaunchError::Backend`] when the agent registry refuses.
    pub fn start<const M: usize, const N: usize>(
        &mut self,
        module: &[u8],
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        self.guard(LifecycleOp::Start, log, timestamp_ns)?;
        let start = log.total_emitted();
        self.guard_executable(module, log, timestamp_ns, start)?;

        let agent = self
            .adapter
            .spawn(&self.isolation, module, agents, log, timestamp_ns)?;
        agents.activate(agent).map_err(LaunchError::Backend)?;

        self.agent = Some(agent);
        self.state = InstanceState::Running;
        emit(
            log,
            LaunchEvent::InstanceStarted,
            &self.witness_context(timestamp_ns),
            self.state,
            u32::try_from(module.len()).unwrap_or(u32::MAX),
        );
        self.record_range(start, log.total_emitted());
        Ok(())
    }

    /// Halt at an instruction boundary, preserving state in place.
    ///
    /// # Errors
    ///
    /// [`LaunchError::IllegalTransition`] unless the instance is running.
    pub fn suspend<const M: usize, const N: usize>(
        &mut self,
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        self.guard(LifecycleOp::Suspend, log, timestamp_ns)?;
        let start = log.total_emitted();

        if let Some(agent) = self.agent {
            agents.suspend(agent, log).map_err(LaunchError::Backend)?;
        }
        self.state = InstanceState::Suspended;
        emit(
            log,
            LaunchEvent::InstanceSuspended,
            &self.witness_context(timestamp_ns),
            self.state,
            0,
        );
        self.record_range(start, log.total_emitted());
        Ok(())
    }

    /// Continue a suspended instance.
    ///
    /// # Errors
    ///
    /// [`LaunchError::IllegalTransition`] unless the instance is suspended —
    /// including the case of an instance that was never suspended at all.
    pub fn resume<const M: usize, const N: usize>(
        &mut self,
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        self.guard(LifecycleOp::Resume, log, timestamp_ns)?;
        let start = log.total_emitted();

        if let Some(agent) = self.agent {
            agents.resume(agent, log).map_err(LaunchError::Backend)?;
        }
        self.state = InstanceState::Running;
        emit(
            log,
            LaunchEvent::InstanceResumed,
            &self.witness_context(timestamp_ns),
            self.state,
            0,
        );
        self.record_range(start, log.total_emitted());
        Ok(())
    }

    /// Capture a resumable snapshot bound to the base RVF identity.
    ///
    /// The instance does not change state: a checkpoint observes it.
    ///
    /// # Errors
    ///
    /// [`LaunchError::IllegalTransition`] unless the instance is running or
    /// suspended. A `Created` instance has nothing to snapshot, and a
    /// terminated one no longer exists.
    pub fn checkpoint<const N: usize>(
        &mut self,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<Checkpoint> {
        self.guard(LifecycleOp::Checkpoint, log, timestamp_ns)?;
        let start = log.total_emitted();

        let checkpoint = Checkpoint::new(
            *self.package.identity(),
            self.id,
            self.checkpoints,
            self.state,
            self.isolation.placement.max_memory_pages,
            start,
        );
        self.checkpoints = self.checkpoints.saturating_add(1);

        emit(
            log,
            LaunchEvent::CheckpointTaken,
            &self.witness_context(timestamp_ns),
            self.state,
            checkpoint.sequence(),
        );
        self.record_range(start, log.total_emitted());
        Ok(checkpoint)
    }

    /// How many checkpoints this instance has taken.
    #[must_use]
    pub const fn checkpoint_count(&self) -> u32 {
        self.checkpoints
    }

    /// Reconstruct from `checkpoint` and continue.
    ///
    /// The lineage check runs first, before the state machine and before
    /// anything is handed to a runtime: state from another base RVF is refused
    /// outright (ADR-288 §4), so execution never begins with partial state
    /// from a foreign lineage. A checkpoint from a *different instance* of the
    /// *same* base is accepted, which is what makes cross-adapter resume
    /// possible; the origin is recorded in the restore record.
    ///
    /// # Errors
    ///
    /// [`LaunchError::LineageMismatch`] when the checkpoint belongs to another
    /// base RVF, and [`LaunchError::IllegalTransition`] unless the instance is
    /// created or suspended. Both are witnessed before they are returned.
    pub fn restore<const M: usize, const N: usize>(
        &mut self,
        checkpoint: &Checkpoint,
        module: &[u8],
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        let start = log.total_emitted();
        if !checkpoint.belongs_to(self.package.identity()) {
            emit(
                log,
                LaunchEvent::CheckpointRejected,
                &self.witness_context(timestamp_ns),
                self.state,
                checkpoint.lineage_tag(),
            );
            self.record_range(start, log.total_emitted());
            return Err(LaunchError::LineageMismatch);
        }
        self.guard(LifecycleOp::Restore, log, timestamp_ns)?;

        if self.state == InstanceState::Created {
            self.guard_executable(module, log, timestamp_ns, start)?;
        }

        match self.state {
            InstanceState::Created => {
                let agent =
                    self.adapter
                        .spawn(&self.isolation, module, agents, log, timestamp_ns)?;
                agents.activate(agent).map_err(LaunchError::Backend)?;
                self.agent = Some(agent);
            }
            _ => {
                if let Some(agent) = self.agent {
                    agents.resume(agent, log).map_err(LaunchError::Backend)?;
                }
            }
        }

        self.state = InstanceState::Running;
        emit(
            log,
            LaunchEvent::CheckpointRestored,
            &self.witness_context(timestamp_ns),
            self.state,
            u32::try_from(checkpoint.origin().as_u64()).unwrap_or(u32::MAX),
        );
        self.record_range(start, log.total_emitted());
        Ok(())
    }

    /// Destroy the instance and free its agent slot.
    ///
    /// # Errors
    ///
    /// [`LaunchError::IllegalTransition`] when the instance is already
    /// terminated. Termination is not idempotent here on purpose: a second
    /// terminate means the caller lost track of the instance, and hiding that
    /// would hide a real bug.
    pub fn terminate<const M: usize, const N: usize>(
        &mut self,
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        self.guard(LifecycleOp::Terminate, log, timestamp_ns)?;
        let start = log.total_emitted();

        if let Some(agent) = self.agent.take() {
            agents.terminate(agent, log).map_err(LaunchError::Backend)?;
        }
        self.state = InstanceState::Terminated;
        emit(
            log,
            LaunchEvent::InstanceTerminated,
            &self.witness_context(timestamp_ns),
            self.state,
            self.checkpoints,
        );
        self.record_range(start, log.total_emitted());
        Ok(())
    }

    /// The witness chain this instance produced, in sequence order.
    ///
    /// Selected by the sequence spans this instance's operations occupied, so
    /// the result includes everything written inside them — the `rvm-host`
    /// capability decisions, the `rvm-wasm` agent transitions, and this
    /// crate's lifecycle records alike. Keeping the spans whole rather than
    /// filtering by layer is what lets the result be *chain*-verified:
    /// ADR-289 criterion 8 asks for a complete, cryptographically verifiable
    /// chain, and a subset with holes in it would satisfy neither adjective.
    ///
    /// Two instances sharing a log occupy disjoint spans, so their chains do
    /// not overlap. An instance whose own log has wrapped past its earliest
    /// span gets back only what survives, which is a property of the log's
    /// capacity rather than of this method.
    #[must_use]
    pub fn witness<const N: usize>(&self, log: &WitnessLog<N>) -> Vec<WitnessRecord> {
        let mut records: Vec<WitnessRecord> = (0..log.len())
            .filter_map(|i| log.get(i))
            .filter(|r| {
                self.ranges
                    .iter()
                    .any(|(start, end)| r.sequence >= *start && r.sequence < *end)
            })
            .collect();
        records.sort_unstable_by_key(|r| r.sequence);
        records
    }

    /// Whether `record` is bound to this instance's base RVF.
    ///
    /// The binding is the FNV-1a fold of the container identity that
    /// `rvm-rvf`, `rvm-host`, and this crate all write into
    /// `capability_hash`, so it holds across every layer that touched the
    /// artifact.
    #[must_use]
    pub fn binds_to_package(&self, record: &WitnessRecord) -> bool {
        record.capability_hash == fnv1a_32(self.package.identity())
    }

    fn witness_context(&self, timestamp_ns: u64) -> LaunchWitnessContext {
        LaunchWitnessContext {
            instance: self.id,
            rvf_identity: *self.package.identity(),
            partition: self.isolation.placement.partition,
            timestamp_ns,
        }
    }

    /// Refuse an operation the state machine does not allow, witnessing the
    /// refusal first.
    fn guard<const N: usize>(
        &mut self,
        op: LifecycleOp,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        if is_legal(self.state, op) {
            return Ok(());
        }
        let start = log.total_emitted();
        emit_illegal(log, &self.witness_context(timestamp_ns), self.state, op);
        self.record_range(start, log.total_emitted());
        Err(LaunchError::IllegalTransition {
            from: self.state,
            op,
        })
    }

    fn record_range(&mut self, start: u64, end: u64) {
        if end > start {
            self.ranges.push((start, end));
        }
    }

    fn guard_executable<const N: usize>(
        &mut self,
        module: &[u8],
        log: &WitnessLog<N>,
        timestamp_ns: u64,
        start: u64,
    ) -> LaunchResult<()> {
        if self.package.accepts_wasm(module) {
            return Ok(());
        }
        emit(
            log,
            LaunchEvent::ExecutableRejected,
            &self.witness_context(timestamp_ns),
            self.state,
            fnv1a_32(module),
        );
        self.record_range(start, log.total_emitted());
        Err(LaunchError::ExecutableMismatch)
    }
}

#[cfg(test)]
#[path = "instance_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "instance_lineage_tests.rs"]
mod lineage_tests;

#[cfg(test)]
#[path = "instance_context_tests.rs"]
mod context_tests;
