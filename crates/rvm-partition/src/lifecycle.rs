//! Partition lifecycle state transitions.

use crate::partition::PartitionState;

/// Check whether a state transition is valid.
#[must_use]
pub fn valid_transition(from: PartitionState, to: PartitionState) -> bool {
    matches!(
        (from, to),
        (PartitionState::Created, PartitionState::Running)
            | (PartitionState::Running, PartitionState::Suspended)
            | (PartitionState::Suspended, PartitionState::Running)
            | (PartitionState::Running, PartitionState::Destroyed)
            | (PartitionState::Suspended, PartitionState::Destroyed)
            | (PartitionState::Created, PartitionState::Destroyed)
            | (PartitionState::Running, PartitionState::Hibernated)
            | (PartitionState::Suspended, PartitionState::Hibernated)
            | (PartitionState::Hibernated, PartitionState::Created)
    )
}
