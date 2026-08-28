//! Error types for RVF container parsing and verification.
//!
//! # Errors versus verification failures
//!
//! These two are deliberately different things. An [`RvfError`] means the
//! bytes are not a well-formed RVF container, or that the container asks for
//! something RVM cannot represent — there is nothing to report on. A
//! *verification failure* (a bad hash, an unsigned executable, an oversize
//! segment) is a result, and ADR-284 §1.9 requires a witness record for it,
//! so it is carried in [`crate::VerificationReport`] rather than raised.
//! Callers who want the failure as an error call
//! [`crate::VerificationReport::into_result`].

use crate::capability::CapabilityClass;
use core::fmt;
use rvm_types::RvmError;

/// Errors from reading an RVF container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvfError {
    /// A segment header's magic number does not match [`crate::SEGMENT_MAGIC`].
    BadMagic,
    /// The stream ends inside a header, payload, or footer.
    Truncated,
    /// The segment format version is not one this crate can read.
    UnsupportedVersion(u8),
    /// A payload length runs past the end of the container, or overflows.
    PayloadOutOfBounds,
    /// A segment declares a payload larger than the format permits.
    PayloadTooLarge,
    /// A segment declares more than the format's maximum 63 alignment bytes.
    InvalidAlignmentPadding,
    /// Bytes declared as alignment padding are not all zero.
    NonZeroAlignmentPadding,
    /// A signature footer is structurally invalid or internally inconsistent.
    MalformedFooter,
    /// A segment sets `SIGNED` but its footer declares no signature.
    SignedFlagWithoutFooter,
    /// The container holds no segments at all.
    NoSegments,
    /// Trailing bytes after the last segment are not zero padding.
    TrailingBytes,
    /// The container declares more segments than the format permits.
    TooManySegments,
    /// The walk failed to advance, which would otherwise loop forever.
    NoForwardProgress,
    /// A trailing Level-0 root page has the right magic but a bad CRC32C.
    RootManifestChecksumMismatch,
    /// A trailing Level-0 root page uses an unsupported format version.
    UnsupportedRootManifestVersion(u16),
    /// A trailing Level-0 root page has inconsistent fields.
    MalformedRootManifest,
    /// The container requires a capability class RVM cannot represent.
    ///
    /// ADR-286 §3 requires refusal rather than degradation: an agent that
    /// quietly runs without a capability it declared is indistinguishable
    /// from an agent that is working.
    UnsupportedCapability(CapabilityClass),
    /// The container names a capability class unknown to this RVM version.
    UnknownCapability,
    /// A capability mapping could not be installed into the capability table.
    CapabilityTableFull,
}

impl fmt::Display for RvfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "segment header magic does not match RVF v1"),
            Self::Truncated => write!(f, "container ends inside a segment"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported segment format version {v}"),
            Self::PayloadOutOfBounds => {
                write!(
                    f,
                    "segment payload length runs past the end of the container"
                )
            }
            Self::PayloadTooLarge => write!(f, "segment payload exceeds the format maximum"),
            Self::InvalidAlignmentPadding => {
                write!(f, "segment alignment padding exceeds 63 bytes")
            }
            Self::NonZeroAlignmentPadding => {
                write!(f, "segment alignment padding contains non-zero bytes")
            }
            Self::MalformedFooter => write!(f, "signature footer is malformed"),
            Self::SignedFlagWithoutFooter => {
                write!(f, "segment sets SIGNED but carries no signature")
            }
            Self::NoSegments => write!(f, "container holds no segments"),
            Self::TrailingBytes => write!(f, "trailing bytes are not a segment header"),
            Self::TooManySegments => write!(f, "container declares too many segments"),
            Self::NoForwardProgress => write!(f, "segment does not advance the read cursor"),
            Self::RootManifestChecksumMismatch => {
                write!(f, "Level-0 root manifest CRC32C does not match")
            }
            Self::UnsupportedRootManifestVersion(version) => {
                write!(f, "unsupported Level-0 root manifest version {version}")
            }
            Self::MalformedRootManifest => {
                write!(f, "Level-0 root manifest fields are inconsistent")
            }
            Self::UnsupportedCapability(c) => {
                write!(f, "RVM cannot represent capability class {c}")
            }
            Self::UnknownCapability => f.write_str("RVF declares an unknown capability class"),
            Self::CapabilityTableFull => write!(f, "capability table has no free slot"),
        }
    }
}

impl From<RvfError> for RvmError {
    fn from(e: RvfError) -> Self {
        match e {
            RvfError::UnsupportedCapability(_)
            | RvfError::UnknownCapability
            | RvfError::UnsupportedVersion(_)
            | RvfError::UnsupportedRootManifestVersion(_) => RvmError::Unsupported,
            RvfError::CapabilityTableFull | RvfError::TooManySegments => {
                RvmError::ResourceLimitExceeded
            }
            // Every remaining variant means the bytes are not a well-formed
            // container, which is a structural verification failure.
            _ => RvmError::ProofInvalid,
        }
    }
}

/// Shorthand result type for RVF operations.
pub type RvfResult<T> = core::result::Result<T, RvfError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_renders_without_panicking() {
        use core::fmt::Write;
        let all = [
            RvfError::BadMagic,
            RvfError::Truncated,
            RvfError::UnsupportedVersion(9),
            RvfError::PayloadOutOfBounds,
            RvfError::PayloadTooLarge,
            RvfError::InvalidAlignmentPadding,
            RvfError::NonZeroAlignmentPadding,
            RvfError::MalformedFooter,
            RvfError::SignedFlagWithoutFooter,
            RvfError::NoSegments,
            RvfError::TrailingBytes,
            RvfError::TooManySegments,
            RvfError::NoForwardProgress,
            RvfError::RootManifestChecksumMismatch,
            RvfError::UnsupportedRootManifestVersion(9),
            RvfError::MalformedRootManifest,
            RvfError::UnsupportedCapability(CapabilityClass::Clipboard),
            RvfError::UnknownCapability,
            RvfError::CapabilityTableFull,
        ];
        for e in all {
            let mut s = alloc::string::String::new();
            write!(&mut s, "{e}").unwrap();
            assert!(!s.is_empty(), "{e:?} rendered empty");
        }
    }

    #[test]
    fn unsupported_capability_maps_to_unsupported_not_invalid_parameter() {
        let mapped: RvmError = RvfError::UnsupportedCapability(CapabilityClass::Randomness).into();
        assert_eq!(mapped, RvmError::Unsupported);
        let mapped: RvmError = RvfError::BadMagic.into();
        assert_eq!(mapped, RvmError::ProofInvalid);
    }
}
