//! TEE (Trusted Execution Environment) trait definitions for
//! hardware-backed attestation (ADR-142 Phase 2 stubs).
//!
//! These are trait definitions only. Concrete platform implementations
//! (SGX, SEV-SNP, TDX, ARM CCA) are deferred to Phase 3.

use crate::signer::SignatureError;

/// Supported TEE platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeePlatform {
    /// Intel Software Guard Extensions.
    Sgx,
    /// AMD Secure Encrypted Virtualization -- Secure Nested Paging.
    SevSnp,
    /// Intel Trust Domain Extensions.
    Tdx,
    /// Arm Confidential Compute Architecture.
    ArmCca,
}

/// Provider of TEE attestation quotes.
///
/// Implementations generate platform-specific attestation quotes
/// that bind a 64-byte report data payload to the enclave's
/// measurement and identity.
pub trait TeeQuoteProvider: Send + Sync {
    /// Generate a TEE attestation quote for the given report data.
    ///
    /// The returned quote is a fixed 256-byte buffer. Platforms that
    /// produce larger quotes must truncate or hash down to fit.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::UnsupportedPlatform`] if the current
    /// hardware does not support this TEE platform.
    fn generate_quote(&self, report_data: &[u8; 64]) -> Result<[u8; 256], SignatureError>;

    /// Return the TEE platform this provider targets.
    fn platform(&self) -> TeePlatform;
}

/// Verifier of TEE attestation quotes.
///
/// Implementations verify that a quote was produced by genuine TEE
/// hardware, that the enclave measurement matches expectations, and
/// that the report data matches.
pub trait TeeQuoteVerifier: Send + Sync {
    /// Verify a TEE attestation quote.
    ///
    /// # Arguments
    ///
    /// * `quote` -- The raw quote bytes (variable length).
    /// * `expected_measurement` -- The expected enclave measurement (MRENCLAVE, etc.).
    /// * `expected_report_data` -- The expected 64-byte report data.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::BadMeasurement`] if the measurement does not match.
    /// Returns [`SignatureError::BadSignature`] if the quote signature is invalid.
    /// Returns [`SignatureError::ExpiredCollateral`] if the TCB collateral has expired.
    fn verify_quote(
        &self,
        quote: &[u8],
        expected_measurement: &[u8; 32],
        expected_report_data: &[u8; 64],
    ) -> Result<(), SignatureError>;

    /// Check whether the cached collateral is still valid.
    ///
    /// Returns `true` if the TCB info, QE identity, and CRL data have
    /// not expired.
    fn collateral_valid(&self) -> bool;
}
