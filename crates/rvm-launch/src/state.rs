//! Instance identity and the lifecycle state machine.
//!
//! The table below is the whole contract. Everything absent from it is
//! illegal, and [`Instance`](crate::Instance) raises
//! [`LaunchError::IllegalTransition`](crate::LaunchError::IllegalTransition)
//! rather than treating an out-of-order call as a no-op — "resume an instance
//! that was never suspended" is a caller bug, and swallowing it would let a
//! host lose track of whether an agent is running.
//!
//! | From | `Start` | `Suspend` | `Resume` | `Checkpoint` | `Restore` | `Terminate` |
//! |---|---|---|---|---|---|---|
//! | `Created` | yes | no | no | no | yes | yes |
//! | `Running` | no | yes | no | yes | no | yes |
//! | `Suspended` | no | no | yes | yes | yes | yes |
//! | `Terminated` | no | no | no | no | no | no |
//!
//! `Terminated` is absorbing. Reuse means a new instance from the same
//! verified package, which keeps "this identifier ran this artifact" a fact
//! about one execution rather than about a slot.

use core::fmt;

/// An instance identifier.
///
/// Opaque to callers and never derived from the artifact: two instances of the
/// same RVF are different executions and must be distinguishable in the
/// witness chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct InstanceId(u64);

impl InstanceId {
    /// An identifier with the given value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instance-{}", self.0)
    }
}

/// Where an instance is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InstanceState {
    /// Isolation is prepared and capabilities are applied; nothing has run.
    Created = 0,
    /// The agent is executing.
    Running = 1,
    /// The agent is halted at an instruction boundary, state preserved.
    Suspended = 2,
    /// The instance is destroyed. Absorbing.
    Terminated = 3,
}

impl InstanceState {
    /// Every state, in lifecycle order.
    pub const ALL: [Self; 4] = [
        Self::Created,
        Self::Running,
        Self::Suspended,
        Self::Terminated,
    ];

    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Terminated => "terminated",
        }
    }

    /// Whether the instance can still change state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

impl fmt::Display for InstanceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleOp {
    /// Admit the module and begin execution.
    Start = 0,
    /// Halt at an instruction boundary.
    Suspend = 1,
    /// Continue a suspended instance.
    Resume = 2,
    /// Capture a resumable snapshot.
    Checkpoint = 3,
    /// Reconstruct from a snapshot.
    Restore = 4,
    /// Destroy the instance.
    Terminate = 5,
}

impl LifecycleOp {
    /// Every operation, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Start,
        Self::Suspend,
        Self::Resume,
        Self::Checkpoint,
        Self::Restore,
        Self::Terminate,
    ];

    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Checkpoint => "checkpoint",
            Self::Restore => "restore",
            Self::Terminate => "terminate",
        }
    }

    /// The state `self` leaves the instance in, or `None` when it does not
    /// change state.
    ///
    /// [`Checkpoint`](Self::Checkpoint) is the `None` case: capturing a
    /// snapshot observes the instance, it does not move it.
    #[must_use]
    pub const fn resulting_state(self) -> Option<InstanceState> {
        match self {
            Self::Start | Self::Resume | Self::Restore => Some(InstanceState::Running),
            Self::Suspend => Some(InstanceState::Suspended),
            Self::Terminate => Some(InstanceState::Terminated),
            Self::Checkpoint => None,
        }
    }
}

impl fmt::Display for LifecycleOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `op` is legal from `state`.
#[must_use]
pub const fn is_legal(state: InstanceState, op: LifecycleOp) -> bool {
    match op {
        LifecycleOp::Start => matches!(state, InstanceState::Created),
        LifecycleOp::Suspend => matches!(state, InstanceState::Running),
        LifecycleOp::Resume => matches!(state, InstanceState::Suspended),
        LifecycleOp::Checkpoint => {
            matches!(state, InstanceState::Running | InstanceState::Suspended)
        }
        LifecycleOp::Restore => matches!(state, InstanceState::Created | InstanceState::Suspended),
        LifecycleOp::Terminate => !state.is_terminal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn legal_ops(state: InstanceState) -> Vec<LifecycleOp> {
        LifecycleOp::ALL
            .into_iter()
            .filter(|op| is_legal(state, *op))
            .collect()
    }

    #[test]
    fn a_fresh_instance_can_only_start_restore_or_be_destroyed() {
        assert_eq!(
            legal_ops(InstanceState::Created),
            [
                LifecycleOp::Start,
                LifecycleOp::Restore,
                LifecycleOp::Terminate
            ]
        );
    }

    #[test]
    fn a_running_instance_cannot_start_again_or_resume() {
        assert_eq!(
            legal_ops(InstanceState::Running),
            [
                LifecycleOp::Suspend,
                LifecycleOp::Checkpoint,
                LifecycleOp::Terminate
            ]
        );
        assert!(!is_legal(InstanceState::Running, LifecycleOp::Start));
        assert!(!is_legal(InstanceState::Running, LifecycleOp::Resume));
    }

    #[test]
    fn only_a_suspended_instance_can_resume() {
        for state in InstanceState::ALL {
            assert_eq!(
                is_legal(state, LifecycleOp::Resume),
                state == InstanceState::Suspended,
                "{state} disagreed about resume"
            );
        }
    }

    #[test]
    fn a_terminated_instance_accepts_nothing_at_all() {
        assert!(legal_ops(InstanceState::Terminated).is_empty());
        assert!(InstanceState::Terminated.is_terminal());
    }

    #[test]
    fn a_checkpoint_needs_something_to_snapshot() {
        assert!(!is_legal(InstanceState::Created, LifecycleOp::Checkpoint));
        assert!(is_legal(InstanceState::Running, LifecycleOp::Checkpoint));
        assert!(is_legal(InstanceState::Suspended, LifecycleOp::Checkpoint));
        assert!(!is_legal(InstanceState::Terminated, LifecycleOp::Checkpoint));
    }

    #[test]
    fn a_checkpoint_observes_rather_than_moves_the_instance() {
        assert_eq!(LifecycleOp::Checkpoint.resulting_state(), None);
        for op in LifecycleOp::ALL {
            if op != LifecycleOp::Checkpoint {
                assert!(op.resulting_state().is_some(), "{op} moves nowhere");
            }
        }
    }

    #[test]
    fn restore_lands_in_running_from_either_of_its_legal_origins() {
        assert_eq!(
            LifecycleOp::Restore.resulting_state(),
            Some(InstanceState::Running)
        );
        assert!(is_legal(InstanceState::Created, LifecycleOp::Restore));
        assert!(is_legal(InstanceState::Suspended, LifecycleOp::Restore));
        assert!(!is_legal(InstanceState::Running, LifecycleOp::Restore));
    }

    #[test]
    fn every_state_and_operation_has_a_distinct_name() {
        let mut names: Vec<&str> = InstanceState::ALL
            .iter()
            .map(|s| s.as_str())
            .chain(LifecycleOp::ALL.iter().map(|o| o.as_str()))
            .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
    }

    #[test]
    fn instance_identifiers_round_trip_and_render() {
        use alloc::string::ToString;
        let id = InstanceId::new(42);
        assert_eq!(id.as_u64(), 42);
        assert_eq!(id.to_string(), "instance-42");
        assert_ne!(id, InstanceId::new(43));
    }
}
