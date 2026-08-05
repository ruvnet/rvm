//! Typed reasons a verification check produced its outcome.

use core::fmt;

/// Why a check produced its outcome.
///
/// A typed code rather than a message: `no_std` targets should not have to
/// allocate a string per record to learn why an artifact was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailCode {
    /// The container hashes to the expected identity.
    IdentityMatches,
    /// The container hashes to something other than the expected identity.
    IdentityMismatch,
    /// A root manifest segment was found.
    RootManifestFound,
    /// The container has no `MANIFEST` segment.
    RootManifestMissing,
    /// The payload matches the header's content hash.
    ContentHashMatches,
    /// The payload does not match the header's content hash.
    ContentHashMismatch,
    /// The executable segment carries a signature footer.
    ExecutableIsSigned,
    /// The executable segment is unsigned and unsigned executables are refused.
    ExecutableIsUnsigned,
    /// The executable segment is unsigned, permitted as a development build.
    UnsignedExecutablePermitted,
    /// The signature verifies against a trusted key.
    SignatureVerifies,
    /// The signature verifies against none of the trusted keys.
    SignatureRejected,
    /// No trusted key was supplied, so the signature could not be checked.
    NoTrustedKey,
    /// The signature algorithm is not Ed25519, which is all this crate checks.
    UnsupportedSignatureAlgorithm,
    /// The signature footer could not be decoded.
    FooterMalformed,
    /// The container fits inside every policy limit.
    WithinSizePolicy,
    /// The container exceeds a policy limit.
    ExceedsSizePolicy,
    /// Every declared class mapped into `rvm-cap`.
    CapabilitiesMapped,
    /// A declared class is one RVM cannot represent.
    CapabilityUnsupported,
}

impl fmt::Display for DetailCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IdentityMatches => "container hashes to the expected identity",
            Self::IdentityMismatch => "container hashes to something else",
            Self::RootManifestFound => "root manifest segment found",
            Self::RootManifestMissing => "container has no MANIFEST segment",
            Self::ContentHashMatches => "payload matches the header content hash",
            Self::ContentHashMismatch => "payload does not match the header content hash",
            Self::ExecutableIsSigned => "executable segment carries a signature footer",
            Self::ExecutableIsUnsigned => "executable segment is unsigned and refused",
            Self::UnsignedExecutablePermitted => "unsigned executable permitted for development",
            Self::SignatureVerifies => "signature verifies against a trusted key",
            Self::SignatureRejected => "signature verifies against no trusted key",
            Self::NoTrustedKey => "no trusted key supplied; signature not checked",
            Self::UnsupportedSignatureAlgorithm => "signature algorithm is not Ed25519",
            Self::FooterMalformed => "signature footer could not be decoded",
            Self::WithinSizePolicy => "container fits inside every policy limit",
            Self::ExceedsSizePolicy => "container exceeds a policy limit",
            Self::CapabilitiesMapped => "declared capability classes mapped into rvm-cap",
            Self::CapabilityUnsupported => "declared capability class is unrepresentable",
        };
        f.write_str(s)
    }
}
