//! Error types for the capability subsystem.
//!
//! [`CapError`] covers table and derivation tree operations.
//! [`ProofError`] covers the three-layer proof verification (ADR-135).

use core::fmt;
use rvm_types::RvmError;

/// Errors from capability table and derivation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The capability handle does not resolve to a valid entry.
    InvalidHandle,
    /// The generation counter does not match -- handle is stale.
    StaleHandle,
    /// The capability table is full.
    TableFull,
    /// The capability has been revoked.
    Revoked,
    /// Delegation depth limit exceeded.
    DelegationDepthExceeded,
    /// The source capability lacks GRANT rights.
    GrantNotPermitted,
    /// Attempted rights escalation (derived rights not a subset of parent).
    RightsEscalation,
    /// The derivation tree is full.
    TreeFull,
    /// Capability type mismatch.
    TypeMismatch,
    /// The capability has been consumed (`GRANT_ONCE`).
    Consumed,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle => write!(f, "invalid capability handle"),
            Self::StaleHandle => write!(f, "stale capability handle (generation mismatch)"),
            Self::TableFull => write!(f, "capability table full"),
            Self::Revoked => write!(f, "capability revoked"),
            Self::DelegationDepthExceeded => write!(f, "delegation depth limit exceeded"),
            Self::GrantNotPermitted => write!(f, "GRANT right not held"),
            Self::RightsEscalation => write!(f, "rights escalation attempted"),
            Self::TreeFull => write!(f, "derivation tree full"),
            Self::TypeMismatch => write!(f, "capability type mismatch"),
            Self::Consumed => write!(f, "capability consumed (GRANT_ONCE)"),
        }
    }
}

impl From<CapError> for RvmError {
    fn from(e: CapError) -> Self {
        match e {
            CapError::InvalidHandle
            | CapError::GrantNotPermitted
            | CapError::RightsEscalation => RvmError::InsufficientCapability,
            CapError::StaleHandle | CapError::Revoked => RvmError::StaleCapability,
            CapError::TableFull | CapError::TreeFull => RvmError::ResourceLimitExceeded,
            CapError::DelegationDepthExceeded => RvmError::DelegationDepthExceeded,
            CapError::TypeMismatch => RvmError::CapabilityTypeMismatch,
            CapError::Consumed => RvmError::CapabilityConsumed,
        }
    }
}

/// Shorthand result type for capability operations.
pub type CapResult<T> = core::result::Result<T, CapError>;

/// Errors from proof verification (ADR-135 three-layer system).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// P1: Handle does not resolve to a valid capability.
    InvalidHandle,
    /// P1: Capability epoch does not match (revoked).
    StaleCapability,
    /// P1: Capability does not carry the required rights.
    InsufficientRights,
    /// P2: One or more structural invariant checks failed.
    ///
    /// Deliberately does not specify which check failed to prevent
    /// timing side-channel leakage (ADR-135).
    PolicyViolation,
    /// P3: Deep proof verification not implemented in v1.
    P3NotImplemented,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle => write!(f, "P1: invalid capability handle"),
            Self::StaleCapability => write!(f, "P1: stale capability (epoch mismatch)"),
            Self::InsufficientRights => write!(f, "P1: insufficient rights"),
            Self::PolicyViolation => write!(f, "P2: policy violation"),
            Self::P3NotImplemented => write!(f, "P3: not implemented in v1"),
        }
    }
}

impl From<ProofError> for RvmError {
    fn from(e: ProofError) -> Self {
        match e {
            ProofError::InvalidHandle
            | ProofError::InsufficientRights => RvmError::InsufficientCapability,
            ProofError::StaleCapability => RvmError::StaleCapability,
            ProofError::PolicyViolation => RvmError::ProofInvalid,
            ProofError::P3NotImplemented => RvmError::Unsupported,
        }
    }
}
