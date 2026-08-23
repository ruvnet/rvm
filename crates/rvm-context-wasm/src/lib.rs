//! WebAssembly bindings for the RVM `ruv://` context namespace.
//!
//! # The wasm module is its own authority
//!
//! Read this before using anything below. This module hosts a complete
//! governed context runtime: its own capability table, grant table, witness
//! ring, and deterministic logical clock. Every capability it issues is an
//! index and a generation into *its own* live table. Handles are not signed,
//! not serializable, and **not portable** across a process boundary; a handle
//! minted by a Rust-side service is just two integers that would index a
//! different table here.
//!
//! A decision this module renders binds only to the scope table the host
//! provisioned into it. It is a faithful, deterministic policy simulator,
//! correct for shadow-mode evaluation, and it is **not** evidence about a
//! separate Rust-side authority unless that authority provisioned the same
//! scopes. Anyone promoting it to enforcement must provision the grant table
//! from the same authority that issues real capabilities.
//!
//! Two consequences worth stating plainly:
//!
//! - "Verify a capability issued elsewhere" is not implementable and is not
//!   offered. The module either owns its authority or authorizes nothing.
//! - Receipt signatures are HMAC-SHA256, which is symmetric. Verifying one
//!   requires the key that signed it, so a caller able to check a receipt is
//!   equally able to forge one. See [`receipt`] for what that does and does
//!   not establish. The keyless witness-chain and record-digest checks are the
//!   ones that survive a trust boundary.
//!
//! # Layers
//!
//! The naming layer stands alone and needs none of the above: [`RuvUri`]
//! parses and canonically formats names, and [`ContextScope`] compares regions
//! of the namespace. Scope containment answers "would `ruv://` have allowed
//! this reach?" with no capability and no runtime involved.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod profile;
pub mod receipt;
pub mod rights;
pub mod runtime;
pub mod scope;
pub mod uri;

pub use profile::{ContextProfile, DerivedView, ProfileView};
pub use receipt::SignedReceipt;
pub use rights::Rights;
pub use runtime::{
    AliasSnapshot, CapabilityHandle, ContextHit, ContextRuntime, EpochCommitments, ExecutionPermit,
    ReadResult, ResolvedContext,
};
pub use scope::{ContextScope, ViewMask};
pub use uri::{is_ruv_uri, ruv_uri_error, RuvUri, RuvUriBuilder};

use wasm_bindgen::prelude::*;

/// Version of the RVM `ruv://` namespace contract this binding implements.
#[wasm_bindgen(js_name = contractVersion)]
#[must_use]
pub fn contract_version() -> u32 {
    rvm_context::RUV_CONTEXT_CONTRACT_VERSION
}
