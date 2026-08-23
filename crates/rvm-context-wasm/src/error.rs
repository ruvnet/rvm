//! JavaScript error construction carrying the originating Rust variant name.

use rvm_context::profile::ContextProfileError;
use rvm_context::uri::UriError;
use wasm_bindgen::prelude::*;

/// Builds a JS `Error` whose `name` and `code` identify the failure precisely.
fn js_error(name: &str, code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name(name);
    let _ = js_sys::Reflect::set(
        error.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    error.into()
}

/// Returns the stable code for a URI failure.
///
/// The code is the Rust variant name so that JS callers can branch on the exact
/// rejection reason instead of matching on message text.
#[must_use]
pub fn uri_error_code(error: UriError) -> &'static str {
    match error {
        UriError::UriTooLong => "UriTooLong",
        UriError::NonAscii => "NonAscii",
        UriError::InvalidScheme => "InvalidScheme",
        UriError::PercentEncodingNotAllowed => "PercentEncodingNotAllowed",
        UriError::FragmentNotAllowed => "FragmentNotAllowed",
        UriError::CredentialsNotAllowed => "CredentialsNotAllowed",
        UriError::PortNotAllowed => "PortNotAllowed",
        UriError::InvalidAuthority => "InvalidAuthority",
        UriError::InvalidTenant => "InvalidTenant",
        UriError::InvalidSubjectKind => "InvalidSubjectKind",
        UriError::InvalidSubjectId => "InvalidSubjectId",
        UriError::InvalidCollection => "InvalidCollection",
        UriError::MissingComponent => "MissingComponent",
        UriError::EmptyPathSegment => "EmptyPathSegment",
        UriError::TrailingSlash => "TrailingSlash",
        UriError::DotSegment => "DotSegment",
        UriError::InvalidPathSegment => "InvalidPathSegment",
        UriError::TooManyPathSegments => "TooManyPathSegments",
        UriError::PathTooLong => "PathTooLong",
        UriError::InvalidQuery => "InvalidQuery",
        UriError::UnknownQueryKey => "UnknownQueryKey",
        UriError::DuplicateQueryKey => "DuplicateQueryKey",
        UriError::QueryOrder => "QueryOrder",
        UriError::InvalidRevision => "InvalidRevision",
        UriError::InvalidView => "InvalidView",
        UriError::RevisionRequired => "RevisionRequired",
    }
}

/// Converts a URI failure into a thrown `RuvUriError`.
#[must_use]
pub fn uri_error(error: UriError) -> JsValue {
    js_error("RuvUriError", uri_error_code(error), &error.to_string())
}

/// Returns the stable code for a context profile failure.
#[must_use]
pub fn profile_error_code(error: ContextProfileError) -> &'static str {
    match error {
        ContextProfileError::Encoding(_) => "Encoding",
        ContextProfileError::ContentViewRequired => "ContentViewRequired",
        ContextProfileError::DuplicateView => "DuplicateView",
        ContextProfileError::DuplicateSegment => "DuplicateSegment",
        ContextProfileError::InvalidProvenance => "InvalidProvenance",
        ContextProfileError::ZeroDigest => "ZeroDigest",
        ContextProfileError::UnverifiedRvf => "UnverifiedRvf",
        ContextProfileError::IdentityMismatch => "IdentityMismatch",
        ContextProfileError::ProfileSegment => "ProfileSegment",
        ContextProfileError::UntrustedProfile => "UntrustedProfile",
        ContextProfileError::ViewSegment => "ViewSegment",
        ContextProfileError::ViewDigestMismatch => "ViewDigestMismatch",
        ContextProfileError::InvalidRvf => "InvalidRvf",
        ContextProfileError::RvfTooLarge => "RvfTooLarge",
    }
}

/// Converts a profile failure into a thrown `ContextProfileError`.
#[must_use]
pub fn profile_error(error: ContextProfileError) -> JsValue {
    js_error(
        "ContextProfileError",
        profile_error_code(error),
        &error.to_string(),
    )
}
