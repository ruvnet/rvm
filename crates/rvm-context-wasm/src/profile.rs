//! Decoding and re-encoding of the deterministic context profile payload.
//!
//! This is the fixed-record codec only. Binding a profile to a verified RVF
//! identity is a separate, key-dependent operation that stays in the kernel.

use crate::error::profile_error;
use crate::error::uri_error;
use rvm_context::profile as core_profile;
use rvm_context::uri::ProgressiveView;
use wasm_bindgen::prelude::*;

/// The provenance binding a derived representation to its content.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct DerivedView {
    inner: core_profile::DerivedView,
}

#[wasm_bindgen]
impl DerivedView {
    /// Digest of the full content bytes this view summarizes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn source(&self) -> String {
        self.inner.source().to_string()
    }

    /// Identity of the deterministic generator implementation.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn generator(&self) -> String {
        self.inner.generator().to_string()
    }

    /// Identity of the model or algorithm weights.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn model(&self) -> String {
        self.inner.model().to_string()
    }

    /// Digest of the exact prompt or transformation configuration.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn prompt(&self) -> String {
        self.inner.prompt().to_string()
    }

    /// Digest of the policy governing generation and disclosure.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn policy(&self) -> String {
        self.inner.policy().to_string()
    }
}

/// One progressive representation mapped to an RVF segment.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct ProfileView {
    inner: core_profile::ProfileView,
}

#[wasm_bindgen]
impl ProfileView {
    /// The representation: `abstract`, `overview`, or `content`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn view(&self) -> String {
        self.inner.view().as_str().into()
    }

    /// The RVF segment holding this representation.
    #[wasm_bindgen(getter, js_name = segmentId)]
    #[must_use]
    pub fn segment_id(&self) -> u64 {
        self.inner.segment_id()
    }

    /// The SHA-256 digest of the segment payload.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn payload(&self) -> String {
        self.inner.payload().to_string()
    }

    /// The provenance of a derived view, or undefined for the content view.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn provenance(&self) -> Option<DerivedView> {
        self.inner.provenance().map(|inner| DerivedView { inner })
    }
}

/// A decoded, validated set of progressive view mappings.
#[wasm_bindgen]
#[derive(Clone)]
pub struct ContextProfile {
    inner: core_profile::ContextProfile,
}

#[wasm_bindgen]
impl ContextProfile {
    /// Decodes and validates a profile payload.
    ///
    /// # Errors
    ///
    /// Throws a `ContextProfileError` whose `code` names the rejection reason,
    /// such as `Encoding`, `DuplicateView`, or `ContentViewRequired`.
    pub fn decode(bytes: &[u8]) -> Result<ContextProfile, JsValue> {
        core_profile::ContextProfile::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(profile_error)
    }

    /// Re-encodes the canonical payload.
    #[wasm_bindgen(js_name = toBytes)]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// The view mappings in canonical abstract, overview, content order.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn views(&self) -> Vec<ProfileView> {
        self.inner
            .views()
            .iter()
            .map(|view| ProfileView { inner: *view })
            .collect()
    }

    /// One view mapping by name, or undefined when the profile omits it.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `name` is not a registered progressive view.
    pub fn view(&self, name: &str) -> Result<Option<ProfileView>, JsValue> {
        let requested: ProgressiveView = name.parse().map_err(uri_error)?;
        Ok(self
            .inner
            .view(requested)
            .map(|view| ProfileView { inner: *view }))
    }
}
