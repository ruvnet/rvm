//! # RVM WebAssembly Guest Runtime
//!
//! Optional WebAssembly execution environment for RVM partitions.
//! When enabled, partitions can host Wasm modules as an alternative
//! to native AArch64/RISC-V/x86-64 guests.
//!
//! ## Design
//!
//! - Wasm modules execute in a sandboxed interpreter within a partition
//! - Host functions are exposed through the capability system
//! - All Wasm state transitions are witness-logged
//! - Agent lifecycle follows ADR-140 state machine
//! - Per-partition resource quotas are enforced per epoch
//! - Migration uses a 7-step protocol with DC-7 timeout
//!
//! This crate is a compile-time optional feature; disabling it
//! removes all Wasm-related code from the final binary.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::needless_range_loop,
    clippy::manual_flatten,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::new_without_default,
    clippy::explicit_iter_loop
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod agent;
pub mod host_functions;
pub mod migration;
pub mod quota;

use rvm_types::{PartitionId, RvmError, RvmResult};

/// Maximum Wasm module size in bytes (1 MiB default).
pub const MAX_MODULE_SIZE: usize = 1024 * 1024;

/// Status of a Wasm module within a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmModuleState {
    /// The module has been loaded but not yet validated.
    Loaded,
    /// The module has been validated and is ready to execute.
    Validated,
    /// The module is currently executing.
    Running,
    /// The module has been terminated.
    Terminated,
}

/// Metadata for a loaded Wasm module.
#[derive(Debug, Clone, Copy)]
pub struct WasmModuleInfo {
    /// The partition hosting this module.
    pub partition: PartitionId,
    /// Current module state.
    pub state: WasmModuleState,
    /// Size of the module in bytes.
    pub size_bytes: u32,
    /// Number of exported functions.
    pub export_count: u16,
    /// Number of imported (host) functions.
    pub import_count: u16,
}

/// Validate a Wasm module header (magic number and version).
///
/// This is a minimal stub that checks the 8-byte Wasm preamble.
pub fn validate_header(bytes: &[u8]) -> RvmResult<()> {
    if bytes.len() < 8 {
        return Err(RvmError::ProofInvalid);
    }
    // Wasm magic: \0asm
    if bytes[0..4] != [0x00, 0x61, 0x73, 0x6D] {
        return Err(RvmError::ProofInvalid);
    }
    // Wasm version 1
    if bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        return Err(RvmError::Unsupported);
    }
    Ok(())
}
