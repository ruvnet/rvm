//! Witness emission for lifecycle events.
//!
//! # Mapping onto `ActionKind`
//!
//! | [`LaunchEvent`] | [`ActionKind`] | Tier | Reading |
//! |---|---|---|---|
//! | `InstanceCreated` | `ProofVerifiedP2` | 2 | a verified package became an instance; nothing ran |
//! | `InstanceStarted` | `TaskSpawn` | 1 | execution began |
//! | `InstanceSuspended` | `PartitionSuspend` | 1 | halted at an instruction boundary |
//! | `InstanceResumed` | `PartitionResume` | 1 | continued |
//! | `CheckpointTaken` | `PartitionHibernate` | 2 | a resumable snapshot was captured |
//! | `CheckpointRestored` | `PartitionReconstruct` | 2 | state was reconstructed from a snapshot |
//! | `CheckpointRejected` | `ProofRejected` | 2 | a snapshot from another lineage was refused |
//! | `InstanceTerminated` | `TaskTerminate` | 1 | destroyed |
//! | `IllegalTransition` | `ProofRejected` | 1 | an operation the state machine does not allow |
//!
//! # Why the log has two records for a suspend
//!
//! [`rvm_wasm::agent::AgentManager`] emits its own record for every agent
//! transition it performs, and this crate emits one for the instance-level
//! decision that drove it. They are not redundant: the agent record says a
//! WASM agent halted, and the instance record says an operator suspended a
//! particular RVF instance and which one. `aux[0]` tells them apart —
//! [`event_of`] returns `None` for a record this module did not write.

use crate::state::{InstanceId, InstanceState, LifecycleOp};
use rvm_types::{fnv1a_32, ActionKind, PartitionId, WitnessRecord};
use rvm_witness::WitnessLog;

/// A lifecycle event worth a witness record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LaunchEvent {
    /// A verified package became an instance. Nothing ran.
    InstanceCreated = 1,
    /// Execution began.
    InstanceStarted = 2,
    /// Halted at an instruction boundary.
    InstanceSuspended = 3,
    /// Continued from suspension.
    InstanceResumed = 4,
    /// A resumable snapshot was captured.
    CheckpointTaken = 5,
    /// State was reconstructed from a snapshot.
    CheckpointRestored = 6,
    /// A snapshot from another lineage was refused.
    CheckpointRejected = 7,
    /// The instance was destroyed.
    InstanceTerminated = 8,
    /// An operation the state machine does not allow.
    IllegalTransition = 9,
}

impl LaunchEvent {
    /// Every event, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::InstanceCreated,
        Self::InstanceStarted,
        Self::InstanceSuspended,
        Self::InstanceResumed,
        Self::CheckpointTaken,
        Self::CheckpointRestored,
        Self::CheckpointRejected,
        Self::InstanceTerminated,
        Self::IllegalTransition,
    ];

    /// The `ActionKind` this event is recorded under.
    #[must_use]
    pub const fn action_kind(self) -> ActionKind {
        match self {
            Self::InstanceCreated => ActionKind::ProofVerifiedP2,
            Self::InstanceStarted => ActionKind::TaskSpawn,
            Self::InstanceSuspended => ActionKind::PartitionSuspend,
            Self::InstanceResumed => ActionKind::PartitionResume,
            Self::CheckpointTaken => ActionKind::PartitionHibernate,
            Self::CheckpointRestored => ActionKind::PartitionReconstruct,
            Self::CheckpointRejected | Self::IllegalTransition => ActionKind::ProofRejected,
            Self::InstanceTerminated => ActionKind::TaskTerminate,
        }
    }

    /// The proof tier this event is discharged at.
    #[must_use]
    pub const fn proof_tier(self) -> u8 {
        match self {
            Self::InstanceCreated
            | Self::CheckpointTaken
            | Self::CheckpointRestored
            | Self::CheckpointRejected => 2,
            _ => 1,
        }
    }

    /// Whether this event records a refusal.
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        matches!(self, Self::CheckpointRejected | Self::IllegalTransition)
    }
}

/// Who is emitting, about which instance and artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchWitnessContext {
    /// The instance the event is about.
    pub instance: InstanceId,
    /// SHA-256 of the base RVF.
    pub rvf_identity: [u8; 32],
    /// The partition the instance is placed in.
    pub partition: PartitionId,
    /// Nanosecond timestamp, supplied rather than sampled.
    pub timestamp_ns: u64,
}

/// Build the record for one lifecycle event.
///
/// `target_object_id` carries the instance identifier, so the chain can be
/// scoped to one execution even when several share a log. `capability_hash`
/// and `payload` bind the record to the base RVF the way `rvm-rvf` and
/// `rvm-host` do.
#[must_use]
pub fn build_record(
    event: LaunchEvent,
    ctx: &LaunchWitnessContext,
    state: InstanceState,
    detail: u32,
) -> WitnessRecord {
    let mut r = WitnessRecord::zeroed();
    r.action_kind = event.action_kind() as u8;
    r.proof_tier = event.proof_tier();
    r.flags = event as u8;
    r.actor_partition_id = ctx.partition.as_u32();
    r.target_object_id = ctx.instance.as_u64();
    r.capability_hash = fnv1a_32(&ctx.rvf_identity);
    r.timestamp_ns = ctx.timestamp_ns;
    r.payload.copy_from_slice(&ctx.rvf_identity[..8]);

    r.aux[0] = event as u8;
    r.aux[1] = state as u8;
    r.aux[2] = 0;
    r.aux[3] = 0;
    r.aux[4..8].copy_from_slice(&detail.to_le_bytes());
    r
}

/// Append one lifecycle event, returning the sequence the log assigned.
pub fn emit<const N: usize>(
    log: &WitnessLog<N>,
    event: LaunchEvent,
    ctx: &LaunchWitnessContext,
    state: InstanceState,
    detail: u32,
) -> u64 {
    log.append(build_record(event, ctx, state, detail))
}

/// Append the refusal of an illegal transition.
///
/// Called before the error is returned, so an operator mistake and a genuine
/// state divergence are both visible in the chain rather than only in a return
/// value the caller may drop.
pub fn emit_illegal<const N: usize>(
    log: &WitnessLog<N>,
    ctx: &LaunchWitnessContext,
    state: InstanceState,
    op: LifecycleOp,
) -> u64 {
    emit(
        log,
        LaunchEvent::IllegalTransition,
        ctx,
        state,
        u32::from(op as u8),
    )
}

/// Read the [`LaunchEvent`] back out of a record this module wrote.
///
/// Returns `None` for records from another subsystem, including the
/// `rvm-host` and `rvm-wasm` records interleaved in the same log.
#[must_use]
pub const fn event_of(record: &WitnessRecord) -> Option<LaunchEvent> {
    // A launch record is identified by both its action kind and its aux tag,
    // because `rvm-host` uses the same aux[0] byte range for its own events.
    let tagged = match record.aux[0] {
        1 => LaunchEvent::InstanceCreated,
        2 => LaunchEvent::InstanceStarted,
        3 => LaunchEvent::InstanceSuspended,
        4 => LaunchEvent::InstanceResumed,
        5 => LaunchEvent::CheckpointTaken,
        6 => LaunchEvent::CheckpointRestored,
        7 => LaunchEvent::CheckpointRejected,
        8 => LaunchEvent::InstanceTerminated,
        9 => LaunchEvent::IllegalTransition,
        _ => return None,
    };
    if record.action_kind == tagged.action_kind() as u8 && record.aux[2] == 0 && record.aux[3] == 0
    {
        Some(tagged)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn ctx() -> LaunchWitnessContext {
        LaunchWitnessContext {
            instance: InstanceId::new(9),
            rvf_identity: [3u8; 32],
            partition: PartitionId::new(1),
            timestamp_ns: 500,
        }
    }

    #[test]
    fn every_event_has_a_distinct_tag_that_round_trips() {
        let mut tags: Vec<u8> = Vec::new();
        for event in LaunchEvent::ALL {
            let r = build_record(event, &ctx(), InstanceState::Created, 0);
            assert_eq!(event_of(&r), Some(event), "{event:?} did not round trip");
            tags.push(event as u8);
        }
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), LaunchEvent::ALL.len());
    }

    #[test]
    fn a_launch_record_carries_the_instance_it_is_about() {
        let r = build_record(
            LaunchEvent::InstanceStarted,
            &ctx(),
            InstanceState::Running,
            0,
        );
        assert_eq!(r.target_object_id, 9);
        assert_eq!(r.aux[1], InstanceState::Running as u8);
        assert_eq!(r.actor_partition_id, 1);
        assert_eq!(r.timestamp_ns, 500);
    }

    #[test]
    fn no_launch_record_is_ever_read_as_a_host_record_or_the_reverse() {
        // Both layers number their events from 1, so `aux[0]` collides across
        // the whole overlapping range. Reading a lifecycle record as a
        // capability decision would silently inflate an audit of capability
        // grants, so every pairing is checked rather than a representative one.
        let host_ctx = rvm_host::HostWitnessContext::new(
            [3u8; 32],
            PartitionId::new(1),
            rvm_host::HostEnvironment::portable(),
            rvm_host::IsolationClaim::WasmOnly,
            0,
        );

        for event in LaunchEvent::ALL {
            let r = build_record(event, &ctx(), InstanceState::Running, 0);
            assert_eq!(event_of(&r), Some(event));
            assert_eq!(
                rvm_host::event_of(&r),
                None,
                "{event:?} read as a host event"
            );
            assert_eq!(rvm_host::claim_of(&r), None);
        }

        for event in rvm_host::HostEvent::ALL {
            let r = rvm_host::build_record(event, &host_ctx, None, 0);
            assert_eq!(rvm_host::event_of(&r), Some(event));
            assert_eq!(event_of(&r), None, "{event:?} read as a launch event");
        }
    }

    #[test]
    fn an_agent_record_from_rvm_wasm_belongs_to_neither_layer() {
        // `rvm-wasm` emits its own transition records into the same log with
        // an all-zero aux; they are neither layer's to interpret.
        let mut agent = WitnessRecord::zeroed();
        agent.action_kind = ActionKind::TaskSpawn as u8;
        assert_eq!(event_of(&agent), None);
        assert_eq!(rvm_host::event_of(&agent), None);
    }

    #[test]
    fn refusals_are_the_events_recorded_as_rejected() {
        for event in LaunchEvent::ALL {
            let rejected = event.action_kind() == ActionKind::ProofRejected;
            assert_eq!(rejected, event.is_refusal(), "{event:?}");
        }
    }

    #[test]
    fn an_illegal_transition_records_which_operation_was_attempted() {
        let log = WitnessLog::<8>::new();
        emit_illegal(&log, &ctx(), InstanceState::Terminated, LifecycleOp::Resume);
        let r = log.get(0).unwrap();
        assert_eq!(event_of(&r), Some(LaunchEvent::IllegalTransition));
        assert_eq!(r.aux[1], InstanceState::Terminated as u8);
        assert_eq!(
            u32::from_le_bytes(r.aux[4..8].try_into().unwrap()),
            u32::from(LifecycleOp::Resume as u8)
        );
    }

    #[test]
    fn records_bind_to_the_base_artifact() {
        let mut other = ctx();
        other.rvf_identity = [4u8; 32];
        let a = build_record(
            LaunchEvent::CheckpointTaken,
            &ctx(),
            InstanceState::Running,
            0,
        );
        let b = build_record(
            LaunchEvent::CheckpointTaken,
            &other,
            InstanceState::Running,
            0,
        );
        assert_ne!(a.capability_hash, b.capability_hash);
        assert_ne!(a.payload, b.payload);
    }

    #[test]
    fn emitted_records_chain() {
        let log = WitnessLog::<32>::new();
        for event in LaunchEvent::ALL {
            emit(&log, event, &ctx(), InstanceState::Running, 0);
        }
        let records: Vec<_> = (0..LaunchEvent::ALL.len())
            .filter_map(|i| log.get(i))
            .collect();
        assert!(rvm_witness::verify_chain(&records).is_ok());
    }
}
