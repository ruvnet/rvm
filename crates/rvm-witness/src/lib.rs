//! Witness logging subsystem for the RVM microhypervisor.
//!
//! Implements ADR-134: 64-byte fixed witness records with FNV-1a hash
//! chain for tamper-evident audit trail.
//!
//! # Core Invariant
//!
//! **No witness, no mutation.** Every privileged action emits a witness
//! record before the mutation is committed. If emission fails, the
//! mutation does not proceed.
//!
//! # Record Format
//!
//! Each record is exactly 64 bytes, cache-line aligned:
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 8 | sequence (u64) |
//! | 8 | 8 | timestamp_ns (u64) |
//! | 16 | 1 | action_kind (u8) |
//! | 17 | 1 | proof_tier (u8) |
//! | 18 | 2 | flags (u16) |
//! | 20 | 4 | actor_partition_id (u32) |
//! | 24 | 4 | target_object_id (u32) |
//! | 28 | 4 | capability_hash (u32) |
//! | 32 | 8 | payload (u64) |
//! | 40 | 8 | prev_hash (u64) |
//! | 48 | 8 | record_hash (u64) |
//! | 56 | 8 | aux (u64) |

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod emit;
mod hash;
mod log;
mod record;
mod replay;
mod signer;

pub use emit::WitnessEmitter;
pub use hash::{fnv1a_64, compute_chain_hash, compute_record_hash};
pub use log::WitnessLog;
pub use record::{ActionKind, WitnessRecord};
pub use replay::{
    ChainIntegrityError, verify_chain, query_by_partition, query_by_action_kind,
    query_by_time_range,
};
#[cfg(any(test, feature = "null-signer"))]
#[allow(deprecated)]
pub use signer::NullSigner;
pub use signer::{DefaultSigner, StrictSigner, WitnessSigner, default_signer};
#[cfg(feature = "crypto-sha256")]
pub use signer::{HmacWitnessSigner, record_to_digest};

/// Default ring buffer capacity: 262,144 records (16 MB / 64 bytes).
pub const DEFAULT_RING_CAPACITY: usize = 262_144;
