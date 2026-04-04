//! # RVM Proof Engine
//!
//! Proof-gated state transitions for the RVM microhypervisor, as
//! specified in ADR-135. Every mutation to partition state requires a
//! valid proof that is recorded in the witness trail.
//!
//! ## Proof Tiers
//!
//! | Tier | Verification | Cost | Use Case |
//! |------|-------------|------|----------|
//! | `Hash` | SHA-256 preimage | O(1) | Routine transitions |
//! | `Witness` | Witness chain verification | O(n) | Cross-partition ops |
//! | `Zk` | Zero-knowledge proof | Expensive | Privacy-preserving |
//!
//! ## Modules
//!
//! - [`context`]: Proof context with builder pattern for P2 validation
//! - [`engine`]: Unified proof engine (P1 -> P2 -> witness pipeline)
//! - [`policy`]: P2 policy rules with constant-time evaluation

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod context;
pub mod engine;
pub mod policy;

use rvm_types::{CapRights, CapToken, RvmError, RvmResult, WitnessHash};

/// The tier of proof required for a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofTier {
    /// SHA-256 preimage proof (cheapest).
    Hash = 0,
    /// Witness chain verification.
    Witness = 1,
    /// Zero-knowledge proof (most expensive).
    Zk = 2,
}

/// A proof payload submitted with a state-transition request.
#[derive(Debug, Clone, Copy)]
pub struct Proof {
    /// The tier of this proof.
    pub tier: ProofTier,
    /// The hash commitment this proof satisfies.
    pub commitment: WitnessHash,
    /// Raw proof bytes (truncated to a fixed maximum for `no_std`).
    data: [u8; 64],
    /// Length of valid data in the `data` buffer.
    data_len: u8,
}

impl Proof {
    /// Create a hash-tier proof from a preimage.
    ///
    /// The preimage is truncated to 64 bytes if longer.
    #[must_use]
    pub fn hash_proof(commitment: WitnessHash, preimage: &[u8]) -> Self {
        let mut data = [0u8; 64];
        let len = preimage.len().min(64);
        data[..len].copy_from_slice(&preimage[..len]);
        Self {
            tier: ProofTier::Hash,
            commitment,
            data,
            // Safe: len is clamped to 64 above, which fits in u8.
            #[allow(clippy::cast_possible_truncation)]
            data_len: len as u8,
        }
    }

    /// Return the proof data as a byte slice.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len as usize]
    }
}

/// Verify that a proof is valid for the given commitment.
///
/// This is a stub implementation. The real implementation will dispatch
/// to tier-specific verifiers (SHA-256, witness chain, ZK).
///
/// # Errors
///
/// Returns [`RvmError::ProofInvalid`] if the commitment does not match or the proof is empty.
pub fn verify(proof: &Proof, expected_commitment: &WitnessHash) -> RvmResult<()> {
    if proof.commitment != *expected_commitment {
        return Err(RvmError::ProofInvalid);
    }

    match proof.tier {
        ProofTier::Hash => {
            // Stub: accept any non-empty preimage for now.
            if proof.data_len == 0 {
                Err(RvmError::ProofInvalid)
            } else {
                Ok(())
            }
        }
        ProofTier::Witness | ProofTier::Zk => {
            // Stub: higher-tier verification not yet implemented.
            Ok(())
        }
    }
}

/// Check that a capability token authorizes proof submission, then verify.
///
/// # Errors
///
/// Returns [`RvmError::InsufficientCapability`] if the token lacks `PROVE` rights.
/// Returns [`RvmError::ProofInvalid`] if the proof verification fails.
pub fn verify_with_cap(
    proof: &Proof,
    expected_commitment: &WitnessHash,
    token: &CapToken,
) -> RvmResult<()> {
    if !token.has_rights(CapRights::PROVE) {
        return Err(RvmError::InsufficientCapability);
    }
    verify(proof, expected_commitment)
}
