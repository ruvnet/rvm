//! Lifecycle errors.

use crate::state::{InstanceState, LifecycleOp};
use core::fmt;
use rvm_host::HostError;
use rvm_rvf::RvfError;
use rvm_types::RvmError;

/// Why a lifecycle operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    /// The operation is not legal from the instance's current state.
    IllegalTransition {
        /// The state the instance was in.
        from: InstanceState,
        /// The operation that was attempted.
        op: LifecycleOp,
    },
    /// The checkpoint belongs to a different base RVF.
    ///
    /// ADR-288 §4: state carries the base identity it was produced under, and
    /// a mismatch is refused rather than replayed. This is what stops state
    /// copied between agents, state carried across an unrelated RVF with the
    /// same application name, and state surviving a base-artifact
    /// substitution.
    LineageMismatch,
    /// A context execution permit names another RVF or partition.
    ContextPermitMismatch,
    /// Runtime bytes do not match any executable segment that was verified.
    ExecutableMismatch,
    /// The host adapter refused.
    Host(HostError),
    /// The execution backend refused.
    Backend(RvmError),
    /// The container is not a well-formed RVF.
    Rvf(RvfError),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition { from, op } => {
                write!(f, "cannot {op} an instance that is {from}")
            }
            Self::LineageMismatch => {
                f.write_str("checkpoint belongs to a different base RVF identity")
            }
            Self::ContextPermitMismatch => {
                f.write_str("context execution permit does not match package and placement")
            }
            Self::ExecutableMismatch => {
                f.write_str("module does not match a verified executable segment")
            }
            Self::Host(e) => write!(f, "{e}"),
            Self::Backend(e) => write!(f, "{e}"),
            Self::Rvf(e) => write!(f, "{e}"),
        }
    }
}

impl From<HostError> for LaunchError {
    fn from(e: HostError) -> Self {
        Self::Host(e)
    }
}

impl From<RvfError> for LaunchError {
    fn from(e: RvfError) -> Self {
        Self::Rvf(e)
    }
}

impl From<LaunchError> for RvmError {
    fn from(e: LaunchError) -> Self {
        match e {
            LaunchError::IllegalTransition { .. } => RvmError::InvalidPartitionState,
            LaunchError::LineageMismatch
            | LaunchError::ContextPermitMismatch
            | LaunchError::ExecutableMismatch => {
                RvmError::ProofInvalid
            }
            LaunchError::Host(inner) => inner.into(),
            LaunchError::Backend(inner) => inner,
            LaunchError::Rvf(inner) => inner.into(),
        }
    }
}

/// Shorthand result type for lifecycle operations.
pub type LaunchResult<T> = core::result::Result<T, LaunchError>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::fmt::Write;

    #[test]
    fn every_error_renders_without_panicking() {
        let all = [
            LaunchError::IllegalTransition {
                from: InstanceState::Terminated,
                op: LifecycleOp::Start,
            },
            LaunchError::LineageMismatch,
            LaunchError::ContextPermitMismatch,
            LaunchError::ExecutableMismatch,
            LaunchError::Host(HostError::Unverified),
            LaunchError::Backend(RvmError::ResourceLimitExceeded),
            LaunchError::Rvf(RvfError::BadMagic),
        ];
        for e in all {
            let mut s = String::new();
            write!(&mut s, "{e}").unwrap();
            assert!(!s.is_empty(), "{e:?} rendered empty");
        }
    }

    #[test]
    fn an_illegal_transition_names_both_the_state_and_the_operation() {
        let mut s = String::new();
        write!(
            &mut s,
            "{}",
            LaunchError::IllegalTransition {
                from: InstanceState::Terminated,
                op: LifecycleOp::Resume,
            }
        )
        .unwrap();
        assert_eq!(s, "cannot resume an instance that is terminated");
    }

    #[test]
    fn a_lineage_mismatch_maps_to_proof_invalid() {
        let mapped: RvmError = LaunchError::LineageMismatch.into();
        assert_eq!(mapped, RvmError::ProofInvalid);
    }

    #[test]
    fn an_illegal_transition_maps_to_invalid_partition_state() {
        let mapped: RvmError = LaunchError::IllegalTransition {
            from: InstanceState::Created,
            op: LifecycleOp::Resume,
        }
        .into();
        assert_eq!(mapped, RvmError::InvalidPartitionState);
    }

    #[test]
    fn a_host_refusal_keeps_the_hosts_own_classification() {
        let mapped: RvmError = LaunchError::Host(HostError::ModuleTooLarge).into();
        assert_eq!(mapped, RvmError::ResourceLimitExceeded);
    }
}
