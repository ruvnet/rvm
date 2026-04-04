//! # RVM Security Policy
//!
//! Security policy enforcement for the RVM microhypervisor. This crate
//! provides the policy decision point that combines capability checks,
//! proof verification, and witness logging into a unified security gate.
//!
//! ## Security Model
//!
//! Every hypercall passes through a three-stage gate:
//!
//! 1. **Capability check** -- Does the caller hold the required rights?
//! 2. **Proof verification** -- Is the state transition properly attested?
//! 3. **Witness logging** -- Record the decision for future audit
//!
//! Only after all three stages pass does the hypercall proceed.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use rvm_types::{CapRights, CapToken, CapType, RvmError, RvmResult, WitnessHash};

/// The result of a security policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied with a reason.
    Deny(RvmError),
}

/// A security gate request combining all required inputs.
#[derive(Debug, Clone, Copy)]
pub struct GateRequest<'a> {
    /// The capability token presented by the caller.
    pub token: &'a CapToken,
    /// The required capability type.
    pub required_type: CapType,
    /// The required access rights.
    pub required_rights: CapRights,
    /// Optional proof commitment (required for state-mutating operations).
    pub proof_commitment: Option<&'a WitnessHash>,
}

/// Evaluate a security gate request against the policy.
///
/// Returns `Allow` only if the capability check and (optional) proof
/// commitment are satisfied. The caller is responsible for witness
/// logging after the decision.
pub fn evaluate(request: &GateRequest<'_>) -> PolicyDecision {
    // Stage 1: Capability type check.
    if request.token.cap_type() != request.required_type {
        return PolicyDecision::Deny(RvmError::CapabilityTypeMismatch);
    }

    // Stage 2: Rights check.
    if !request.token.has_rights(request.required_rights) {
        return PolicyDecision::Deny(RvmError::InsufficientCapability);
    }

    // Stage 3: Proof commitment presence check (if required).
    // Actual proof verification is handled by rvm-proof; here we
    // only ensure the commitment was provided.
    if let Some(commitment) = request.proof_commitment {
        if commitment.is_zero() {
            return PolicyDecision::Deny(RvmError::ProofInvalid);
        }
    }

    PolicyDecision::Allow
}

/// Convenience function: evaluate and return `RvmResult<()>`.
pub fn enforce(request: &GateRequest<'_>) -> RvmResult<()> {
    match evaluate(request) {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Deny(e) => Err(e),
    }
}
