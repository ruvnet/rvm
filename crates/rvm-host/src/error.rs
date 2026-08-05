//! Host adapter errors.
//!
//! Every variant here is a *refusal*, and every refusal is witnessed before it
//! is returned (ADR-285 acceptance criterion 2, ADR-286 §2). There is no
//! variant meaning "started anyway with less": ADR-286 §3 requires that a
//! capability class the host cannot enforce stops the start rather than
//! quietly narrowing it, because an agent silently running without a
//! capability it declared is indistinguishable from one that is working.

use core::fmt;
use rvm_rvf::{CapabilityClass, RvfError};
use rvm_types::RvmError;

/// Why a host adapter refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// A [`crate::VerifiedPackage`] was asked for from a report that failed
    /// verification. Nothing executes on the strength of a failed report.
    Unverified,
    /// The adapter cannot enforce a capability class the package declared.
    ///
    /// Carries the first such class. The refusal is witnessed and no grant is
    /// recorded, so the audit trail never shows a partially applied set.
    CapabilityUnenforceable(CapabilityClass),
    /// A mechanism this adapter requires did not engage.
    MechanismUnavailable(crate::IsolationMechanism),
    /// The mechanism does not belong to this adapter's operating system.
    MechanismNotInStack(crate::IsolationMechanism),
    /// The module is larger than the adapter admits.
    ModuleTooLarge,
    /// The module is not a well-formed WASM module.
    ModuleRejected(RvmError),
    /// The execution backend refused to start the agent.
    SpawnFailed(RvmError),
    /// The container is not a well-formed RVF.
    Rvf(RvfError),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverified => f.write_str("package did not pass verification"),
            Self::CapabilityUnenforceable(c) => {
                write!(f, "adapter cannot enforce capability class {c}")
            }
            Self::MechanismUnavailable(m) => {
                write!(f, "required isolation mechanism {m} did not engage")
            }
            Self::MechanismNotInStack(m) => {
                write!(
                    f,
                    "isolation mechanism {m} is not part of this adapter's stack"
                )
            }
            Self::ModuleTooLarge => f.write_str("module exceeds the adapter's maximum size"),
            Self::ModuleRejected(_) => f.write_str("module is not a well-formed WASM module"),
            Self::SpawnFailed(_) => f.write_str("backend refused to start the agent"),
            Self::Rvf(e) => write!(f, "{e}"),
        }
    }
}

impl From<RvfError> for HostError {
    fn from(e: RvfError) -> Self {
        Self::Rvf(e)
    }
}

impl From<HostError> for RvmError {
    fn from(e: HostError) -> Self {
        match e {
            HostError::Unverified | HostError::Rvf(_) | HostError::ModuleRejected(_) => {
                RvmError::ProofInvalid
            }
            HostError::CapabilityUnenforceable(_) | HostError::MechanismUnavailable(_) => {
                RvmError::Unsupported
            }
            HostError::MechanismNotInStack(_) => RvmError::Unsupported,
            HostError::ModuleTooLarge => RvmError::ResourceLimitExceeded,
            HostError::SpawnFailed(inner) => inner,
        }
    }
}

/// Shorthand result type for host adapter operations.
pub type HostResult<T> = core::result::Result<T, HostError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IsolationMechanism;
    use alloc::string::String;
    use core::fmt::Write;

    #[test]
    fn every_error_renders_without_panicking() {
        let all = [
            HostError::Unverified,
            HostError::CapabilityUnenforceable(CapabilityClass::Network),
            HostError::MechanismUnavailable(IsolationMechanism::LinuxSeccomp),
            HostError::MechanismNotInStack(IsolationMechanism::MacosNotarization),
            HostError::ModuleTooLarge,
            HostError::ModuleRejected(RvmError::ProofInvalid),
            HostError::SpawnFailed(RvmError::ResourceLimitExceeded),
            HostError::Rvf(RvfError::BadMagic),
        ];
        for e in all {
            let mut s = String::new();
            write!(&mut s, "{e}").unwrap();
            assert!(!s.is_empty(), "{e:?} rendered empty");
        }
    }

    #[test]
    fn an_unenforceable_capability_maps_to_unsupported_not_invalid_parameter() {
        let mapped: RvmError = HostError::CapabilityUnenforceable(CapabilityClass::Gpu).into();
        assert_eq!(mapped, RvmError::Unsupported);
    }

    #[test]
    fn a_failed_verification_maps_to_proof_invalid() {
        let mapped: RvmError = HostError::Unverified.into();
        assert_eq!(mapped, RvmError::ProofInvalid);
    }

    #[test]
    fn a_spawn_failure_preserves_the_backend_error() {
        let mapped: RvmError = HostError::SpawnFailed(RvmError::ResourceLimitExceeded).into();
        assert_eq!(mapped, RvmError::ResourceLimitExceeded);
    }
}
