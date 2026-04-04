//! Agent migration protocol (ADR-140).
//!
//! Implements a 7-step migration protocol for moving WASM agents between
//! partitions. DC-7 constrains total migration time to 100 ms; exceeding
//! this budget causes an automatic abort.

use rvm_types::{ActionKind, PartitionId, RvmError, RvmResult, WitnessRecord};
use rvm_witness::WitnessLog;

use crate::agent::AgentId;

/// Describes a planned migration from one partition to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationPlan {
    /// The agent being migrated.
    pub agent_id: AgentId,
    /// Source partition.
    pub source_partition: PartitionId,
    /// Destination partition.
    pub dest_partition: PartitionId,
    /// Deadline in nanoseconds from epoch start (DC-7: 100 ms).
    pub deadline_ns: u64,
}

/// Current state of an in-progress migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// Step 1: Serializing agent state to a portable format.
    Serializing,
    /// Step 2: Pausing inter-partition communication.
    PausingComms,
    /// Step 3: Transferring memory regions to the destination.
    TransferringRegions,
    /// Step 4: Updating communication edges in the coherence graph.
    UpdatingEdges,
    /// Step 5: Updating the coherence graph topology.
    UpdatingGraph,
    /// Step 6: Verifying state integrity at the destination.
    Verifying,
    /// Step 7: Resuming the agent at the destination.
    Resuming,
    /// Migration completed successfully.
    Complete,
    /// Migration was aborted (timeout or error).
    Aborted,
}

impl MigrationState {
    /// Return the next step in the protocol, or `None` if terminal.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Serializing => Some(Self::PausingComms),
            Self::PausingComms => Some(Self::TransferringRegions),
            Self::TransferringRegions => Some(Self::UpdatingEdges),
            Self::UpdatingEdges => Some(Self::UpdatingGraph),
            Self::UpdatingGraph => Some(Self::Verifying),
            Self::Verifying => Some(Self::Resuming),
            Self::Resuming => Some(Self::Complete),
            Self::Complete | Self::Aborted => None,
        }
    }

    /// Check whether this is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Aborted)
    }
}

/// DC-7: Maximum migration time in nanoseconds (100 ms).
pub const MIGRATION_TIMEOUT_NS: u64 = 100_000_000;

/// Tracks the progress of an agent migration.
#[derive(Debug, Clone, Copy)]
pub struct MigrationTracker {
    /// The migration plan.
    pub plan: MigrationPlan,
    /// Current migration state.
    pub state: MigrationState,
    /// Nanosecond timestamp when migration started.
    pub start_ns: u64,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
}

impl MigrationTracker {
    /// Begin a new migration. Sets the state to `Serializing`.
    #[must_use]
    pub const fn begin(plan: MigrationPlan, now_ns: u64) -> Self {
        Self {
            plan,
            state: MigrationState::Serializing,
            start_ns: now_ns,
            bytes_transferred: 0,
        }
    }

    /// Advance to the next migration step.
    ///
    /// Checks DC-7 timeout: if `current_ns - start_ns > deadline_ns`,
    /// the migration is aborted with `MigrationTimeout`.
    pub fn advance<const W: usize>(
        &mut self,
        current_ns: u64,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<MigrationState> {
        if self.state.is_terminal() {
            return Err(RvmError::InvalidPartitionState);
        }

        // DC-7: enforce timeout.
        let elapsed = current_ns.saturating_sub(self.start_ns);
        if elapsed > self.plan.deadline_ns {
            self.state = MigrationState::Aborted;
            emit_migration_witness(
                witness_log,
                ActionKind::MigrationTimeout,
                &self.plan,
            );
            return Err(RvmError::MigrationTimeout);
        }

        match self.state.next() {
            Some(next_state) => {
                self.state = next_state;
                if next_state == MigrationState::Complete {
                    emit_migration_witness(
                        witness_log,
                        ActionKind::PartitionMigrate,
                        &self.plan,
                    );
                }
                Ok(next_state)
            }
            None => Err(RvmError::InvalidPartitionState),
        }
    }

    /// Force-abort the migration.
    pub fn abort<const W: usize>(&mut self, witness_log: &WitnessLog<W>) {
        if !self.state.is_terminal() {
            self.state = MigrationState::Aborted;
            emit_migration_witness(
                witness_log,
                ActionKind::MigrationTimeout,
                &self.plan,
            );
        }
    }

    /// Check whether the migration has completed successfully.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, MigrationState::Complete)
    }

    /// Check whether the migration was aborted.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self.state, MigrationState::Aborted)
    }
}

/// Emit a witness record for a migration event.
fn emit_migration_witness<const W: usize>(
    log: &WitnessLog<W>,
    action: ActionKind,
    plan: &MigrationPlan,
) {
    let mut record = WitnessRecord::zeroed();
    record.action_kind = action as u8;
    record.actor_partition_id = plan.source_partition.as_u32();
    record.target_object_id = plan.agent_id.as_u32() as u64;
    record.proof_tier = 2;

    // Encode source/dest in payload.
    let src_bytes = plan.source_partition.as_u32().to_le_bytes();
    let dst_bytes = plan.dest_partition.as_u32().to_le_bytes();
    record.payload[0..4].copy_from_slice(&src_bytes);
    record.payload[4..8].copy_from_slice(&dst_bytes);

    log.append(record);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_plan() -> MigrationPlan {
        MigrationPlan {
            agent_id: AgentId::from_badge(1),
            source_partition: PartitionId::new(10),
            dest_partition: PartitionId::new(20),
            deadline_ns: MIGRATION_TIMEOUT_NS,
        }
    }

    #[test]
    fn test_full_migration_protocol() {
        let log = WitnessLog::<32>::new();
        let plan = make_plan();
        let mut tracker = MigrationTracker::begin(plan, 0);
        assert_eq!(tracker.state, MigrationState::Serializing);

        // Advance through all 7 steps.
        let expected = [
            MigrationState::PausingComms,
            MigrationState::TransferringRegions,
            MigrationState::UpdatingEdges,
            MigrationState::UpdatingGraph,
            MigrationState::Verifying,
            MigrationState::Resuming,
            MigrationState::Complete,
        ];

        for (i, &expected_state) in expected.iter().enumerate() {
            let ns = (i as u64 + 1) * 1_000_000; // 1 ms per step
            let state = tracker.advance(ns, &log).unwrap();
            assert_eq!(state, expected_state);
        }

        assert!(tracker.is_complete());
    }

    #[test]
    fn test_migration_timeout() {
        let log = WitnessLog::<32>::new();
        let plan = make_plan();
        let mut tracker = MigrationTracker::begin(plan, 0);

        // Advance once.
        tracker.advance(1_000, &log).unwrap();

        // Now exceed the deadline.
        let result = tracker.advance(MIGRATION_TIMEOUT_NS + 1, &log);
        assert_eq!(result, Err(RvmError::MigrationTimeout));
        assert!(tracker.is_aborted());
    }

    #[test]
    fn test_abort() {
        let log = WitnessLog::<32>::new();
        let plan = make_plan();
        let mut tracker = MigrationTracker::begin(plan, 0);

        tracker.abort(&log);
        assert!(tracker.is_aborted());

        // Cannot advance after abort.
        assert_eq!(tracker.advance(1, &log), Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_cannot_advance_past_complete() {
        let log = WitnessLog::<32>::new();
        let plan = make_plan();
        let mut tracker = MigrationTracker::begin(plan, 0);

        for i in 0..7 {
            tracker.advance((i + 1) * 1000, &log).unwrap();
        }
        assert!(tracker.is_complete());

        assert_eq!(tracker.advance(100_000, &log), Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_witness_on_complete() {
        let log = WitnessLog::<32>::new();
        let plan = make_plan();
        let mut tracker = MigrationTracker::begin(plan, 0);

        for i in 0..7 {
            tracker.advance((i + 1) * 1000, &log).unwrap();
        }

        // Should have emitted a witness record on completion.
        assert!(log.total_emitted() > 0);
    }

    #[test]
    fn test_migration_state_next() {
        assert_eq!(MigrationState::Serializing.next(), Some(MigrationState::PausingComms));
        assert_eq!(MigrationState::Complete.next(), None);
        assert_eq!(MigrationState::Aborted.next(), None);
    }
}
