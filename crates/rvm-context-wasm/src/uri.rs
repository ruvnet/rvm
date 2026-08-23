//! Canonical `ruv://` URI parsing, construction, and formatting for JavaScript.

use crate::error::{uri_error, uri_error_code};
use rvm_context::uri as core_uri;
use wasm_bindgen::prelude::*;

/// A validated canonical `ruv://` URI.
///
/// Holding one grants nothing. It is a name that has been proven well formed,
/// not a token that authorizes access to what it names.
#[wasm_bindgen]
#[derive(Clone)]
pub struct RuvUri {
    inner: core_uri::RuvUri,
}

impl RuvUri {
    pub(crate) fn from_inner(inner: core_uri::RuvUri) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &core_uri::RuvUri {
        &self.inner
    }
}

#[wasm_bindgen]
impl RuvUri {
    /// Parses a URI, rejecting every noncanonical spelling.
    ///
    /// # Errors
    ///
    /// Throws a `RuvUriError` whose `code` names the exact rejection reason,
    /// such as `InvalidTenant`, `TrailingSlash`, or `DotSegment`.
    pub fn parse(text: &str) -> Result<RuvUri, JsValue> {
        core_uri::RuvUri::parse(text)
            .map(Self::from_inner)
            .map_err(uri_error)
    }

    /// The canonical lowercase DNS authority.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn authority(&self) -> String {
        self.inner.authority().as_str().into()
    }

    /// The canonical tenant slug.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tenant(&self) -> String {
        self.inner.tenant().as_str().into()
    }

    /// The subject category: `agent`, `user`, `service`, or `team`.
    #[wasm_bindgen(getter, js_name = subjectKind)]
    #[must_use]
    pub fn subject_kind(&self) -> String {
        self.inner.subject().kind().as_str().into()
    }

    /// The canonical subject slug.
    #[wasm_bindgen(getter, js_name = subjectId)]
    #[must_use]
    pub fn subject_id(&self) -> String {
        self.inner.subject().id().as_str().into()
    }

    /// The top-level collection: `memory`, `resources`, or `skills`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn collection(&self) -> String {
        self.inner.collection().as_str().into()
    }

    /// The case-sensitive path segments below the collection.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        self.inner
            .path()
            .iter()
            .map(|segment| segment.as_str().into())
            .collect()
    }

    /// The pinned revision as `sha256:<64 hex digits>`, or undefined when the
    /// URI is a mutable alias.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn revision(&self) -> Option<String> {
        self.inner.revision().map(|rev| rev.to_string())
    }

    /// The requested progressive view, or undefined when none was requested.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn view(&self) -> Option<String> {
        self.inner.view().map(|view| view.as_str().into())
    }

    /// Whether this URI names an immutable revision rather than an alias.
    #[wasm_bindgen(getter, js_name = isPinned)]
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        self.inner.is_pinned()
    }

    /// Renders the one canonical spelling of this URI.
    #[wasm_bindgen(js_name = toString)]
    #[must_use]
    pub fn render(&self) -> String {
        self.inner.to_string()
    }

    /// Returns a copy pinned to `revision`, given as `sha256:<64 hex digits>`.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `revision` is malformed or the result would
    /// exceed the URI byte limit.
    #[wasm_bindgen(js_name = withRevision)]
    pub fn with_revision(&self, revision: &str) -> Result<RuvUri, JsValue> {
        let parsed: core_uri::Revision = revision.parse().map_err(uri_error)?;
        self.inner
            .clone()
            .with_revision(parsed)
            .map(|pinned| Self::from_inner(pinned.into_uri()))
            .map_err(uri_error)
    }

    /// Returns a copy requesting `view`: `abstract`, `overview`, or `content`.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `view` is unregistered or the result would
    /// exceed the URI byte limit.
    #[wasm_bindgen(js_name = withView)]
    pub fn with_view(&self, view: &str) -> Result<RuvUri, JsValue> {
        let parsed: core_uri::ProgressiveView = view.parse().map_err(uri_error)?;
        self.inner
            .clone()
            .with_view(parsed)
            .map(Self::from_inner)
            .map_err(uri_error)
    }

    /// Whether two URIs name exactly the same thing.
    #[must_use]
    pub fn equals(&self, other: &RuvUri) -> bool {
        self.inner == other.inner
    }
}

/// Reports why `text` is not a canonical `ruv://` URI without throwing.
///
/// Returns the error code, or undefined when `text` parses.
#[wasm_bindgen(js_name = ruvUriError)]
#[must_use]
pub fn ruv_uri_error(text: &str) -> Option<String> {
    core_uri::RuvUri::parse(text)
        .err()
        .map(|error| uri_error_code(error).into())
}

/// Whether `text` is a canonical `ruv://` URI.
#[wasm_bindgen(js_name = isRuvUri)]
#[must_use]
pub fn is_ruv_uri(text: &str) -> bool {
    core_uri::RuvUri::parse(text).is_ok()
}

/// Builds a canonical `ruv://` URI from validated components.
///
/// Every method returns a new builder, so a builder value can be reused safely.
#[wasm_bindgen]
#[derive(Clone)]
pub struct RuvUriBuilder {
    authority: core_uri::Authority,
    tenant: core_uri::TenantId,
    subject: core_uri::Subject,
    collection: core_uri::Collection,
    path: Vec<core_uri::PathSegment>,
    revision: Option<core_uri::Revision>,
    view: Option<core_uri::ProgressiveView>,
}

#[wasm_bindgen]
impl RuvUriBuilder {
    /// Validates the five required components of every `ruv://` name.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` naming the component that failed validation.
    #[wasm_bindgen(constructor)]
    pub fn new(
        authority: &str,
        tenant: &str,
        subject_kind: &str,
        subject_id: &str,
        collection: &str,
    ) -> Result<RuvUriBuilder, JsValue> {
        let authority = core_uri::Authority::new(authority).map_err(uri_error)?;
        let tenant = core_uri::TenantId::new(tenant).map_err(uri_error)?;
        let kind: core_uri::SubjectKind = subject_kind.parse().map_err(uri_error)?;
        let id = core_uri::SubjectId::new(subject_id).map_err(uri_error)?;
        let collection: core_uri::Collection = collection.parse().map_err(uri_error)?;
        Ok(Self {
            authority,
            tenant,
            subject: core_uri::Subject::new(kind, id),
            collection,
            path: Vec::new(),
            revision: None,
            view: None,
        })
    }

    /// Appends one validated path segment below the collection.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `segment` is empty, a dot segment, too long,
    /// or contains a character outside the unreserved set.
    pub fn segment(&self, segment: &str) -> Result<RuvUriBuilder, JsValue> {
        let segment = core_uri::PathSegment::new(segment).map_err(uri_error)?;
        let mut next = self.clone();
        next.path.push(segment);
        Ok(next)
    }

    /// Pins the name to `revision`, given as `sha256:<64 hex digits>`.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `revision` is not `sha256:` followed by 64
    /// lowercase hexadecimal digits.
    pub fn revision(&self, revision: &str) -> Result<RuvUriBuilder, JsValue> {
        let revision = revision.parse().map_err(uri_error)?;
        let mut next = self.clone();
        next.revision = Some(revision);
        Ok(next)
    }

    /// Requests `view`: `abstract`, `overview`, or `content`.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when `view` is not a registered progressive view.
    pub fn view(&self, view: &str) -> Result<RuvUriBuilder, JsValue> {
        let view = view.parse().map_err(uri_error)?;
        let mut next = self.clone();
        next.view = Some(view);
        Ok(next)
    }

    /// Validates aggregate limits and produces the URI.
    ///
    /// # Errors
    ///
    /// Throws `RuvUriError` when the path or complete URI exceeds its limit.
    pub fn build(&self) -> Result<RuvUri, JsValue> {
        let mut builder = core_uri::RuvUri::builder(
            self.authority.clone(),
            self.tenant.clone(),
            self.subject.clone(),
            self.collection,
        )
        .path(self.path.clone());
        if let Some(revision) = self.revision {
            builder = builder.revision(revision);
        }
        if let Some(view) = self.view {
            builder = builder.view(view);
        }
        builder.build().map(RuvUri::from_inner).map_err(uri_error)
    }
}
