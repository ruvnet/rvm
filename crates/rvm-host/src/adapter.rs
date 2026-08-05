//! The host adapter interface: prepare isolation, apply the capability set,
//! spawn the execution, and report what boundary was actually obtained.
//!
//! # Two passes over the capability set
//!
//! [`HostAdapter::prepare`] checks every declared class for enforceability
//! *before* it records a single grant. That ordering is the difference between
//! an audit trail that reflects reality and one that does not: if grants were
//! emitted as they were checked, a package whose fourth class turned out to be
//! unenforceable would leave three `CapabilityGrant` records describing
//! capabilities that never existed. ADR-286 §3 requires refusal rather than a
//! narrowed start, so the refusal is witnessed and nothing else is.
//!
//! # Why the trait is not object safe
//!
//! The witness log and the agent registry are const-generic over their
//! capacities, which makes the methods that touch them generic and the trait
//! unusable behind `dyn`. That is the same trade `rvm-wasm` and `rvm-security`
//! already make: fixed-capacity storage with no allocator, at the cost of
//! static dispatch. Callers name their adapter type; `rvm-launch` is generic
//! over it.

use rvm_rvf::CapabilityClass;
use rvm_types::PartitionId;
use rvm_wasm::agent::{AgentConfig, AgentId, AgentManager};
use rvm_wasm::MAX_MODULE_SIZE;
use rvm_witness::WitnessLog;

use crate::error::{HostError, HostResult};
use crate::isolation::{HostEnvironment, IsolationClaim};
use crate::mechanism::MechanismSet;
use crate::package::VerifiedPackage;
use crate::witness::{emit, HostEvent, HostWitnessContext};

/// The runtime-selection ladder of ADR-289 §2 (FR004).
///
/// Strongest boundary first. Selection walks the order and takes the first
/// entry the host can actually provide; [`Unsupported`](Self::Unsupported) is
/// terminal, meaning refuse rather than fall back to something weaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeClass {
    /// Bare-metal RVM.
    NativeRvm,
    /// Operating-system confinement composed under WASM.
    OsIsolationWasm,
    /// WASM alone.
    Wasm,
    /// A Linux microVM boundary.
    LinuxMicroVm,
    /// Nothing compatible; execution is refused.
    Unsupported,
}

impl RuntimeClass {
    /// The fixed preference order.
    ///
    /// A `const` with no setter, and deliberately so: ADR-289 §2 makes the
    /// order changeable only by signed policy, because a reorder is an
    /// isolation downgrade. There is no flag, environment variable, or
    /// constructor here that can permute it — a signed override arrives as a
    /// policy artifact through `rvm-policy`, not as a parameter to this crate.
    pub const PREFERENCE_ORDER: [Self; 4] = [
        Self::NativeRvm,
        Self::OsIsolationWasm,
        Self::Wasm,
        Self::LinuxMicroVm,
    ];

    /// Position in the preference order; lower is stronger.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::NativeRvm => 0,
            Self::OsIsolationWasm => 1,
            Self::Wasm => 2,
            Self::LinuxMicroVm => 3,
            Self::Unsupported => 4,
        }
    }

    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeRvm => "native-rvm",
            Self::OsIsolationWasm => "os-isolation+wasm",
            Self::Wasm => "wasm",
            Self::LinuxMicroVm => "linux-microvm",
            Self::Unsupported => "unsupported",
        }
    }
}

/// What an adapter is and what it admits, without preparing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterDescriptor {
    /// Stable adapter name.
    pub name: &'static str,
    /// Which rung of the selection ladder this adapter occupies.
    pub runtime: RuntimeClass,
    /// The largest module this adapter admits.
    ///
    /// Never above [`rvm_wasm::MAX_MODULE_SIZE`], which is the executor's own
    /// backstop; an adapter may be stricter, never laxer.
    pub max_module_bytes: usize,
}

/// Where the agent goes and what it may consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// The partition that will host the agent.
    pub partition: PartitionId,
    /// The capability epoch to issue under.
    pub epoch: u32,
    /// The memory-page quota for the agent.
    pub max_memory_pages: u32,
}

impl Placement {
    /// A placement in `partition` at `epoch` with `max_memory_pages`.
    #[must_use]
    pub const fn new(partition: PartitionId, epoch: u32, max_memory_pages: u32) -> Self {
        Self {
            partition,
            epoch,
            max_memory_pages,
        }
    }
}

/// A prepared isolation context: the boundary an agent will run inside, and
/// the honest description of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationContext {
    /// The adapter that prepared it.
    pub adapter: &'static str,
    /// Where that adapter runs.
    pub environment: HostEnvironment,
    /// The isolation class obtained, derived rather than asserted.
    pub claim: IsolationClaim,
    /// Every mechanism declared, engaged or not.
    pub mechanisms: MechanismSet,
    /// Where the agent was placed.
    pub placement: Placement,
    /// The artifact this context is for.
    pub rvf_identity: [u8; 32],
    /// The classes that became live capabilities.
    pub granted: alloc::vec::Vec<CapabilityClass>,
}

impl IsolationContext {
    /// The witness context for events inside this isolation boundary.
    #[must_use]
    pub const fn witness_context(&self, timestamp_ns: u64) -> HostWitnessContext {
        HostWitnessContext::new(
            self.rvf_identity,
            self.placement.partition,
            self.environment,
            self.claim,
            timestamp_ns,
        )
    }

    /// Whether `class` is live in this context.
    #[must_use]
    pub fn is_granted(&self, class: CapabilityClass) -> bool {
        self.granted.contains(&class)
    }
}

/// A host adapter: isolation for one verified RVF.
pub trait HostAdapter {
    /// What this adapter is and what it admits.
    fn descriptor(&self) -> AdapterDescriptor;

    /// Where this adapter runs.
    ///
    /// The bare-metal variant requires [`crate::PartitionEvidence`], so an
    /// adapter running as a desktop process cannot return it.
    fn environment(&self) -> HostEnvironment;

    /// Every mechanism this adapter declares, with whether it engaged.
    fn mechanisms(&self) -> MechanismSet;

    /// Whether this adapter can hold `class` to its declared bounds.
    ///
    /// "Can enforce" means there is a boundary, not that there is an intent.
    /// An adapter with no filesystem confinement cannot enforce
    /// [`CapabilityClass::Filesystem`], and saying otherwise would make the
    /// declaration decorative.
    fn enforces(&self, class: CapabilityClass) -> bool;

    /// The isolation class this adapter obtained.
    ///
    /// Derived from [`environment`](Self::environment) and
    /// [`mechanisms`](Self::mechanisms); see [`IsolationClaim::derive`] for why
    /// a hosted adapter has no reachable path to
    /// [`IsolationClaim::Partition`].
    fn isolation_claim(&self) -> IsolationClaim {
        IsolationClaim::derive(self.environment(), &self.mechanisms())
    }

    /// Prepare an isolation context for `package` and apply its capability set.
    ///
    /// Emits one record per capability class — a grant for each declared class
    /// and a denial for each closed one — followed by the isolation-prepared
    /// record carrying the obtained claim.
    ///
    /// # Errors
    ///
    /// [`HostError::CapabilityUnenforceable`] when the package declares a
    /// class this adapter cannot hold to its bounds. The refusal is witnessed
    /// and no grant record is written, so a refused package never appears in
    /// the chain as a partially started one.
    fn prepare<const N: usize>(
        &self,
        package: &VerifiedPackage,
        placement: Placement,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> HostResult<IsolationContext> {
        let environment = self.environment();
        let mechanisms = self.mechanisms();
        let claim = IsolationClaim::derive(environment, &mechanisms);
        let ctx = HostWitnessContext::new(
            *package.identity(),
            placement.partition,
            environment,
            claim,
            timestamp_ns,
        );

        // Pass one: refuse before granting anything.
        for class in package.granted_classes() {
            if !self.enforces(class) {
                emit(log, HostEvent::CapabilityRefused, &ctx, Some(class), 0);
                return Err(HostError::CapabilityUnenforceable(class));
            }
        }

        // Pass two: the set is enforceable, so record every decision.
        let granted = package.granted_classes();
        for class in &granted {
            emit(log, HostEvent::CapabilityGranted, &ctx, Some(*class), 0);
        }
        for class in package.denied_classes() {
            emit(log, HostEvent::CapabilityDenied, &ctx, Some(*class), 0);
        }
        emit(
            log,
            HostEvent::IsolationPrepared,
            &ctx,
            None,
            u32::from(claim.witness_code()),
        );

        Ok(IsolationContext {
            adapter: self.descriptor().name,
            environment,
            claim,
            mechanisms,
            placement,
            rvf_identity: *package.identity(),
            granted,
        })
    }

    /// Admit `module` and start it inside `isolation`.
    ///
    /// Admission is size, then structural validation, then the spawn. Nothing
    /// interprets the module: [`rvm_wasm::validate_module`] reads the header
    /// and section table, and the agent registry allocates a slot. The badge
    /// is derived from the RVF identity, so an agent slot is traceable to the
    /// artifact that filled it.
    ///
    /// # Errors
    ///
    /// [`HostError::ModuleTooLarge`] or [`HostError::ModuleRejected`] when the
    /// module fails admission, and [`HostError::SpawnFailed`] when the
    /// registry has no room. Each is witnessed before it is returned.
    fn spawn<const M: usize, const N: usize>(
        &self,
        isolation: &IsolationContext,
        module: &[u8],
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> HostResult<AgentId> {
        let ctx = isolation.witness_context(timestamp_ns);
        let limit = self.descriptor().max_module_bytes.min(MAX_MODULE_SIZE);

        if module.len() > limit {
            emit(
                log,
                HostEvent::ModuleRefused,
                &ctx,
                None,
                u32::try_from(module.len()).unwrap_or(u32::MAX),
            );
            return Err(HostError::ModuleTooLarge);
        }
        if let Err(e) = rvm_wasm::validate_module(module) {
            emit(log, HostEvent::ModuleRefused, &ctx, None, 0);
            return Err(HostError::ModuleRejected(e));
        }

        let badge = rvm_types::fnv1a_32(&isolation.rvf_identity);
        let config = AgentConfig {
            badge,
            partition_id: isolation.placement.partition,
            max_memory_pages: isolation.placement.max_memory_pages,
        };
        let id = agents
            .spawn(&config, log)
            .map_err(HostError::SpawnFailed)?;

        emit(
            log,
            HostEvent::ModuleAdmitted,
            &ctx,
            None,
            u32::try_from(module.len()).unwrap_or(u32::MAX),
        );
        Ok(id)
    }
}

/// The strongest adapter among `candidates`, by the fixed preference order.
///
/// Returns `None` when every candidate is [`RuntimeClass::Unsupported`], which
/// ADR-289 §2 makes a terminal outcome: refuse rather than run under something
/// the ladder does not allow.
#[must_use]
pub fn strongest(candidates: &[AdapterDescriptor]) -> Option<&AdapterDescriptor> {
    candidates
        .iter()
        .filter(|d| d.runtime != RuntimeClass::Unsupported)
        .min_by_key(|d| d.runtime.rank())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn descriptor(name: &'static str, runtime: RuntimeClass) -> AdapterDescriptor {
        AdapterDescriptor {
            name,
            runtime,
            max_module_bytes: MAX_MODULE_SIZE,
        }
    }

    #[test]
    fn the_preference_order_is_strongest_first() {
        let ranks: vec::Vec<u8> = RuntimeClass::PREFERENCE_ORDER
            .iter()
            .map(|r| r.rank())
            .collect();
        assert_eq!(ranks, [0, 1, 2, 3]);
        assert!(RuntimeClass::Unsupported.rank() > RuntimeClass::LinuxMicroVm.rank());
    }

    #[test]
    fn selection_takes_the_strongest_available_adapter() {
        let candidates = [
            descriptor("wasm", RuntimeClass::Wasm),
            descriptor("bare-metal", RuntimeClass::NativeRvm),
            descriptor("hosted", RuntimeClass::OsIsolationWasm),
        ];
        assert_eq!(strongest(&candidates).unwrap().name, "bare-metal");
    }

    #[test]
    fn selection_ignores_the_order_the_candidates_arrived_in() {
        let forward = [
            descriptor("hosted", RuntimeClass::OsIsolationWasm),
            descriptor("wasm", RuntimeClass::Wasm),
        ];
        let reversed = [
            descriptor("wasm", RuntimeClass::Wasm),
            descriptor("hosted", RuntimeClass::OsIsolationWasm),
        ];
        assert_eq!(strongest(&forward).unwrap().name, "hosted");
        assert_eq!(strongest(&reversed).unwrap().name, "hosted");
    }

    #[test]
    fn unsupported_is_terminal_rather_than_a_fallback() {
        let candidates = [descriptor("nothing", RuntimeClass::Unsupported)];
        assert!(strongest(&candidates).is_none());
        assert!(strongest(&[]).is_none());
    }

    #[test]
    fn every_runtime_class_has_a_distinct_rank_and_name() {
        let all = [
            RuntimeClass::NativeRvm,
            RuntimeClass::OsIsolationWasm,
            RuntimeClass::Wasm,
            RuntimeClass::LinuxMicroVm,
            RuntimeClass::Unsupported,
        ];
        let mut ranks: vec::Vec<u8> = all.iter().map(|r| r.rank()).collect();
        ranks.sort_unstable();
        ranks.dedup();
        assert_eq!(ranks.len(), 5);

        let mut names: vec::Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 5);
    }
}
