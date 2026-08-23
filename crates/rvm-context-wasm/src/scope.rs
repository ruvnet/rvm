//! Pure scope arithmetic: view masks and name containment.
//!
//! Nothing here decides access. These are predicates over names, exposed so
//! that JavaScript callers reuse the kernel's own comparison instead of
//! hand-rolling a prefix match that drifts from it.

use crate::error::uri_error;
use crate::uri::RuvUri;
use rvm_context::capability::ContextScope as CoreScope;
use rvm_context::capability::ContextViewMask;
use rvm_context::uri::ProgressiveView;
use wasm_bindgen::prelude::*;

/// A bit mask over the progressive representations a scope may disclose.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct ViewMask {
    inner: ContextViewMask,
}

#[wasm_bindgen]
impl ViewMask {
    /// The mask permitting every v1 representation.
    #[must_use]
    pub fn all() -> ViewMask {
        Self {
            inner: ContextViewMask::ALL,
        }
    }

    /// The mask permitting manifest metadata only.
    #[must_use]
    pub fn manifest() -> ViewMask {
        Self {
            inner: ContextViewMask::MANIFEST,
        }
    }

    /// The mask permitting exactly one progressive view.
    ///
    /// `name` is `abstract`, `overview`, or `content`.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `name` is not a registered progressive view.
    pub fn view(name: &str) -> Result<ViewMask, JsValue> {
        let view: ProgressiveView = name.parse().map_err(uri_error)?;
        let inner = match view {
            ProgressiveView::Abstract => ContextViewMask::ABSTRACT,
            ProgressiveView::Overview => ContextViewMask::OVERVIEW,
            ProgressiveView::Content => ContextViewMask::CONTENT,
        };
        Ok(Self { inner })
    }

    /// Rebuilds a mask from its stable bit representation.
    ///
    /// # Errors
    ///
    /// Throws `ViewMaskError` when `bits` is zero or sets a reserved bit.
    #[wasm_bindgen(js_name = fromBits)]
    pub fn from_bits(bits: u8) -> Result<ViewMask, JsValue> {
        ContextViewMask::from_bits(bits)
            .map(|inner| Self { inner })
            .ok_or_else(|| {
                let error = js_sys::Error::new("view mask bits are zero or reserved");
                error.set_name("ViewMaskError");
                let _ = js_sys::Reflect::set(
                    error.as_ref(),
                    &JsValue::from_str("code"),
                    &JsValue::from_str("InvalidViewMask"),
                );
                error.into()
            })
    }

    /// The stable bit representation.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bits(&self) -> u8 {
        self.inner.bits()
    }

    /// Combines two masks.
    #[must_use]
    pub fn union(&self, other: &ViewMask) -> ViewMask {
        Self {
            inner: self.inner.union(other.inner),
        }
    }

    /// Whether this mask permits a named progressive view.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `name` is not a registered progressive view.
    pub fn allows(&self, name: &str) -> Result<bool, JsValue> {
        let view: ProgressiveView = name.parse().map_err(uri_error)?;
        Ok(self.inner.allows(view))
    }

    /// Whether `other` is equal to or narrower than this mask.
    #[must_use]
    pub fn contains(&self, other: &ViewMask) -> bool {
        self.inner.contains(other.inner)
    }
}

impl ContextScope {
    pub(crate) fn inner(&self) -> &CoreScope {
        &self.inner
    }
}

impl ViewMask {
    pub(crate) fn from_inner(inner: ContextViewMask) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(self) -> ContextViewMask {
        self.inner
    }
}

/// A namespace and path-prefix region, derived from a URI.
///
/// A scope is a description of a region of the namespace. Comparing scopes
/// tells you how two names relate; it does not tell you what a caller may do.
#[wasm_bindgen]
#[derive(Clone)]
pub struct ContextScope {
    inner: CoreScope,
}

#[wasm_bindgen]
impl ContextScope {
    /// Derives the scope rooted at `uri` disclosing `views`.
    ///
    /// A revision or view on `uri` is not part of the region.
    #[wasm_bindgen(js_name = fromUri)]
    #[must_use]
    pub fn from_uri(uri: &RuvUri, views: &ViewMask) -> ContextScope {
        Self {
            inner: CoreScope::from_uri(uri.inner(), views.inner()),
        }
    }

    /// The bound authority.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn authority(&self) -> String {
        self.inner.authority().as_str().into()
    }

    /// The bound tenant.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tenant(&self) -> String {
        self.inner.tenant().as_str().into()
    }

    /// The bound subject category.
    #[wasm_bindgen(getter, js_name = subjectKind)]
    #[must_use]
    pub fn subject_kind(&self) -> String {
        self.inner.subject().kind().as_str().into()
    }

    /// The bound subject identifier.
    #[wasm_bindgen(getter, js_name = subjectId)]
    #[must_use]
    pub fn subject_id(&self) -> String {
        self.inner.subject().id().as_str().into()
    }

    /// The bound collection.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn collection(&self) -> String {
        self.inner.collection().as_str().into()
    }

    /// The path segments every name in this region starts with.
    #[wasm_bindgen(getter, js_name = pathPrefix)]
    #[must_use]
    pub fn path_prefix(&self) -> Vec<String> {
        self.inner
            .path_prefix()
            .iter()
            .map(|segment| segment.as_str().into())
            .collect()
    }

    /// The representations this region discloses.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn views(&self) -> ViewMask {
        ViewMask::from_inner(self.inner.views())
    }

    /// Whether `child` is equal to or narrower than this region.
    ///
    /// This is a comparison of names, not an authorization decision.
    #[wasm_bindgen(js_name = containsScope)]
    #[must_use]
    pub fn contains_scope(&self, child: &ContextScope) -> bool {
        self.inner.contains_scope(&child.inner)
    }

    /// Whether `uri` names something inside this region.
    ///
    /// This is the shadow-mode question — "would `ruv://` have allowed this
    /// reach?" — answered with no capability, no runtime, and no witness
    /// record. It compares the authority, tenant, subject, collection, and
    /// path prefix.
    ///
    /// It is name containment only. It is **not** an access check: it does not
    /// consult rights, and it cannot tell you whether any caller holds a
    /// capability over this region. Only the kernel decides that.
    #[wasm_bindgen(js_name = containsUri)]
    #[must_use]
    pub fn contains_uri(&self, uri: &RuvUri) -> bool {
        let target = CoreScope::from_uri(uri.inner(), self.inner.views());
        self.inner.contains_scope(&target)
    }
}
