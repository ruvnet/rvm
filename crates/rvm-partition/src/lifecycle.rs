//! Partition lifecycle state transitions.

use crate::partition::PartitionState;

/// Check whether a state transition is valid.
#[must_use]
pub fn valid_transition(from: PartitionState, to: PartitionState) -> bool {
    matches!(
        (from, to),
        (
            PartitionState::Created | PartitionState::Suspended,
            PartitionState::Running
        ) | (PartitionState::Running, PartitionState::Suspended)
            | (
                PartitionState::Created
                    | PartitionState::Running
                    | PartitionState::Suspended,
                PartitionState::Destroyed
            )
            | (
                PartitionState::Running | PartitionState::Suspended,
                PartitionState::Hibernated
            )
            | (PartitionState::Hibernated, PartitionState::Created)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Full lifecycle paths
    // ---------------------------------------------------------------

    #[test]
    fn test_full_lifecycle_created_to_running_to_suspended_to_running_to_hibernated_to_created_to_running_to_destroyed() {
        // Created -> Running
        assert!(valid_transition(PartitionState::Created, PartitionState::Running));
        // Running -> Suspended
        assert!(valid_transition(PartitionState::Running, PartitionState::Suspended));
        // Suspended -> Running
        assert!(valid_transition(PartitionState::Suspended, PartitionState::Running));
        // Running -> Hibernated
        assert!(valid_transition(PartitionState::Running, PartitionState::Hibernated));
        // Hibernated -> Created
        assert!(valid_transition(PartitionState::Hibernated, PartitionState::Created));
        // Created -> Running (again)
        assert!(valid_transition(PartitionState::Created, PartitionState::Running));
        // Running -> Destroyed
        assert!(valid_transition(PartitionState::Running, PartitionState::Destroyed));
    }

    // ---------------------------------------------------------------
    // All valid transitions
    // ---------------------------------------------------------------

    #[test]
    fn test_created_to_running() {
        assert!(valid_transition(PartitionState::Created, PartitionState::Running));
    }

    #[test]
    fn test_created_to_destroyed() {
        assert!(valid_transition(PartitionState::Created, PartitionState::Destroyed));
    }

    #[test]
    fn test_running_to_suspended() {
        assert!(valid_transition(PartitionState::Running, PartitionState::Suspended));
    }

    #[test]
    fn test_running_to_destroyed() {
        assert!(valid_transition(PartitionState::Running, PartitionState::Destroyed));
    }

    #[test]
    fn test_running_to_hibernated() {
        assert!(valid_transition(PartitionState::Running, PartitionState::Hibernated));
    }

    #[test]
    fn test_suspended_to_running() {
        assert!(valid_transition(PartitionState::Suspended, PartitionState::Running));
    }

    #[test]
    fn test_suspended_to_destroyed() {
        assert!(valid_transition(PartitionState::Suspended, PartitionState::Destroyed));
    }

    #[test]
    fn test_suspended_to_hibernated() {
        assert!(valid_transition(PartitionState::Suspended, PartitionState::Hibernated));
    }

    #[test]
    fn test_hibernated_to_created() {
        assert!(valid_transition(PartitionState::Hibernated, PartitionState::Created));
    }

    // ---------------------------------------------------------------
    // Invalid transitions
    // ---------------------------------------------------------------

    #[test]
    fn test_created_to_suspended_invalid() {
        assert!(!valid_transition(PartitionState::Created, PartitionState::Suspended));
    }

    #[test]
    fn test_created_to_hibernated_invalid() {
        assert!(!valid_transition(PartitionState::Created, PartitionState::Hibernated));
    }

    #[test]
    fn test_created_to_created_invalid() {
        assert!(!valid_transition(PartitionState::Created, PartitionState::Created));
    }

    #[test]
    fn test_running_to_running_invalid() {
        assert!(!valid_transition(PartitionState::Running, PartitionState::Running));
    }

    #[test]
    fn test_running_to_created_invalid() {
        assert!(!valid_transition(PartitionState::Running, PartitionState::Created));
    }

    #[test]
    fn test_suspended_to_suspended_invalid() {
        assert!(!valid_transition(PartitionState::Suspended, PartitionState::Suspended));
    }

    #[test]
    fn test_suspended_to_created_invalid() {
        assert!(!valid_transition(PartitionState::Suspended, PartitionState::Created));
    }

    #[test]
    fn test_destroyed_to_anything_invalid() {
        assert!(!valid_transition(PartitionState::Destroyed, PartitionState::Created));
        assert!(!valid_transition(PartitionState::Destroyed, PartitionState::Running));
        assert!(!valid_transition(PartitionState::Destroyed, PartitionState::Suspended));
        assert!(!valid_transition(PartitionState::Destroyed, PartitionState::Hibernated));
        assert!(!valid_transition(PartitionState::Destroyed, PartitionState::Destroyed));
    }

    #[test]
    fn test_hibernated_to_running_invalid() {
        assert!(!valid_transition(PartitionState::Hibernated, PartitionState::Running));
    }

    #[test]
    fn test_hibernated_to_destroyed_invalid() {
        assert!(!valid_transition(PartitionState::Hibernated, PartitionState::Destroyed));
    }

    #[test]
    fn test_hibernated_to_suspended_invalid() {
        assert!(!valid_transition(PartitionState::Hibernated, PartitionState::Suspended));
    }

    #[test]
    fn test_hibernated_to_hibernated_invalid() {
        assert!(!valid_transition(PartitionState::Hibernated, PartitionState::Hibernated));
    }
}
