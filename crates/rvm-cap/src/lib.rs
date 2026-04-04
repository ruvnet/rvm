//! Capability system for the RVM coherence-native microhypervisor.
//!
//! Implements the three-layer proof system specified in ADR-135:
//!
//! | Layer | Name | Budget | v1 Status |
//! |-------|------|--------|-----------|
//! | **P1** | Capability Check | < 1 us | Ship |
//! | **P2** | Policy Validation | < 100 us | Ship |
//! | **P3** | Deep Proof | < 10 ms | Deferred |
//!
//! # Core Concepts
//!
//! - **Capability**: Unforgeable kernel-managed token with rights bitmap.
//! - **Derivation Tree**: Parent-child relationships with monotonic attenuation.
//! - **Delegation Depth**: Max 8 levels to prevent unbounded chains.
//! - **Epoch-based revocation**: Stale handles detected via epoch counter.
//!
//! # Design Principles (ADR-135)
//!
//! 1. A partition can only grant capabilities it holds
//! 2. Granted rights must be equal or fewer than held rights
//! 3. Revocation propagates through the derivation tree
//! 4. `GRANT_ONCE` provides non-transitive delegation
//! 5. Epoch-based invalidation detects stale handles

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod derivation;
mod error;
mod grant;
mod manager;
mod revoke;
mod table;
mod verify;

pub use derivation::{DerivationNode, DerivationTree};
pub use error::{CapError, CapResult, ProofError};
pub use grant::GrantPolicy;
pub use manager::{CapManagerConfig, CapabilityManager, ManagerStats};
pub use revoke::{RevokeResult, revoke_single};
pub use table::{CapSlot, CapabilityTable};
pub use verify::ProofVerifier;

// Re-export commonly used types from rvm-types.
pub use rvm_types::{CapRights, CapToken, CapType};

/// Default maximum delegation depth (ADR-135 Section: Capability Derivation Tree).
pub const DEFAULT_MAX_DELEGATION_DEPTH: u8 = 8;

/// Default capability table capacity per partition.
pub const DEFAULT_CAP_TABLE_CAPACITY: usize = 256;
