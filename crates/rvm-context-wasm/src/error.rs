//! JavaScript error construction carrying the originating Rust variant name.

use rvm_context::error::ContextError;
use rvm_context::profile::ContextProfileError;
use rvm_context::receipt::ContextReceiptError;
use rvm_context::uri::UriError;
use rvm_witness::ChainIntegrityError;
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

/// Returns the stable code for a governed context failure.
#[must_use]
pub fn context_error_code(error: ContextError) -> &'static str {
    match error {
        ContextError::AccessDenied => "AccessDenied",
        ContextError::GrantTableFull => "GrantTableFull",
        ContextError::GrantAlreadyBound => "GrantAlreadyBound",
        ContextError::ScopeEscalation => "ScopeEscalation",
        ContextError::Capability(_) => "Capability",
        ContextError::PinnedUriRequired => "PinnedUriRequired",
        ContextError::VersionlessUriRequired => "VersionlessUriRequired",
        ContextError::ImmutableRevision => "ImmutableRevision",
        ContextError::RevisionNotFound => "RevisionNotFound",
        ContextError::RevisionConflict => "RevisionConflict",
        ContextError::AliasNotFound => "AliasNotFound",
        ContextError::AliasConflict => "AliasConflict",
        ContextError::AliasGenerationExhausted => "AliasGenerationExhausted",
        ContextError::ObjectTableFull => "ObjectTableFull",
        ContextError::AliasTableFull => "AliasTableFull",
        ContextError::ObjectTooLarge => "ObjectTooLarge",
        ContextError::InvalidQuery => "InvalidQuery",
        ContextError::InvalidResultLimit => "InvalidResultLimit",
        ContextError::Tombstoned => "Tombstoned",
        ContextError::OperationMismatch => "OperationMismatch",
        ContextError::RevisionHashMismatch => "RevisionHashMismatch",
        ContextError::RvfVerificationFailed => "RvfVerificationFailed",
        ContextError::ReceiptSealFailed => "ReceiptSealFailed",
        ContextError::InvalidTarget => "InvalidTarget",
        ContextError::ResolverScopeViolation => "ResolverScopeViolation",
        ContextError::BackendUnavailable => "BackendUnavailable",
    }
}

/// Converts a governed context failure into a thrown `ContextError`.
///
/// Authorization failures deliberately collapse to `AccessDenied` in the core
/// crate so that an unauthorized caller cannot probe for existence. That
/// property is preserved here: this function adds no detail of its own.
#[must_use]
pub fn context_error(error: ContextError) -> JsValue {
    js_error(
        "ContextError",
        context_error_code(error),
        &error.to_string(),
    )
}

/// Returns the stable code for a witness chain integrity failure.
#[must_use]
pub fn chain_error_code(error: ChainIntegrityError) -> &'static str {
    match error {
        ChainIntegrityError::ChainBreak { .. } => "ChainBreak",
        ChainIntegrityError::RecordCorrupted { .. } => "RecordCorrupted",
        ChainIntegrityError::EmptyLog => "EmptyLog",
    }
}

/// Converts a witness chain failure into a thrown `WitnessChainError`.
#[must_use]
pub fn chain_error(error: ChainIntegrityError) -> JsValue {
    js_error(
        "WitnessChainError",
        chain_error_code(error),
        &error.to_string(),
    )
}

/// Returns the stable code for a receipt failure.
#[must_use]
pub fn receipt_error_code(error: &ContextReceiptError) -> &'static str {
    match error {
        ContextReceiptError::EmptyEpoch => "EmptyEpoch",
        ContextReceiptError::TooManyRecords => "TooManyRecords",
        ContextReceiptError::SequenceRange => "SequenceRange",
        ContextReceiptError::TimestampBounds => "TimestampBounds",
        ContextReceiptError::Chain(_) => "Chain",
        ContextReceiptError::Snapshot(_) => "Snapshot",
        ContextReceiptError::SignerMismatch => "SignerMismatch",
        ContextReceiptError::Signature(_) => "Signature",
        ContextReceiptError::Encoding(_) => "Encoding",
        ContextReceiptError::WitnessRootMismatch => "WitnessRootMismatch",
        ContextReceiptError::ReceiptContinuity => "ReceiptContinuity",
    }
}

/// Converts a receipt failure into a thrown `ContextReceiptError`.
///
/// Takes the error by value so it can be used directly as a `map_err`
/// argument, matching the other converters in this module.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn receipt_error(error: ContextReceiptError) -> JsValue {
    let code = receipt_error_code(&error);
    js_error("ContextReceiptError", code, &error.to_string())
}

/// Builds a thrown error for a binding-level argument failure.
#[must_use]
pub fn argument_error(code: &str, message: &str) -> JsValue {
    js_error("ContextArgumentError", code, message)
}
