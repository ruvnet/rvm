//! WebAssembly bindings for the RVM `ruv://` context namespace.
//!
//! This crate exposes the naming and validation layer of `rvm-context` to
//! JavaScript: canonical URI parsing and formatting, component construction,
//! pure scope arithmetic, and the context profile codec.
//!
//! It deliberately does not expose the governed runtime, the resolver, grant
//! issuance, or receipt sealing. Those require an authenticated partition, a
//! clock, and live capability state; a JavaScript-side actor supplying them
//! would be exactly the forgery the design prevents. A parsed `ruv://` URI is
//! a name, never an authorization.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod profile;
pub mod scope;
pub mod uri;

pub use profile::{ContextProfile, DerivedView, ProfileView};
pub use scope::{ContextScope, ViewMask};
pub use uri::{is_ruv_uri, ruv_uri_error, RuvUri, RuvUriBuilder};

use wasm_bindgen::prelude::*;

/// Version of the RVM `ruv://` namespace contract this binding implements.
#[wasm_bindgen(js_name = contractVersion)]
#[must_use]
pub fn contract_version() -> u32 {
    rvm_context::RUV_CONTEXT_CONTRACT_VERSION
}
