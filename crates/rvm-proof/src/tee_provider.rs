//! Software-emulated TEE quote provider (ADR-142 Phase 3).
//!
//! Produces HMAC-SHA256 based quotes that simulate TEE attestation
//! without requiring actual hardware. Suitable for testing, development,
//! and software-only deployments.

use crate::signer::SignatureError;
use crate::tee::{TeePlatform, TeeQuoteProvider};

#[cfg(feature = "crypto-sha256")]
use hmac::{Hmac, Mac};
#[cfg(feature = "crypto-sha256")]
use sha2::Sha256;

#[cfg(feature = "crypto-sha256")]
type HmacSha256 = Hmac<Sha256>;

/// Magic bytes at the start of every software TEE quote.
pub(crate) const QUOTE_MAGIC: &[u8; 4] = b"RVMq";

/// Offset table for the quote wire format.
///
/// | Offset | Length | Field            |
/// |--------|--------|------------------|
/// | 0      | 4      | Magic (`RVMq`)   |
/// | 4      | 1      | Platform byte    |
/// | 5      | 32     | Measurement      |
/// | 37     | 64     | Report data      |
/// | 101    | 32     | HMAC-SHA256 tag  |
///
/// Total: 133 bytes (fits in 256-byte return buffer).
pub(crate) const OFFSET_MAGIC: usize = 0;
pub(crate) const OFFSET_PLATFORM: usize = 4;
pub(crate) const OFFSET_MEASUREMENT: usize = 5;
pub(crate) const OFFSET_REPORT_DATA: usize = 37;
pub(crate) const OFFSET_HMAC: usize = 101;

/// Total length of a software TEE quote.
pub(crate) const QUOTE_LEN: usize = 133;

/// Software TEE quote provider for testing and development.
///
/// Produces HMAC-SHA256 based quotes that simulate TEE attestation.
/// The quote structure is deterministic given the same inputs, making
/// it suitable for reproducible testing.
#[cfg(feature = "crypto-sha256")]
pub struct SoftwareTeeProvider {
    platform: TeePlatform,
    measurement: [u8; 32],
    signer_key: [u8; 32],
}

#[cfg(feature = "crypto-sha256")]
impl SoftwareTeeProvider {
    /// Create a new software TEE provider.
    ///
    /// # Arguments
    ///
    /// * `platform` -- The TEE platform to simulate.
    /// * `measurement` -- Simulated enclave measurement (MRENCLAVE, MRTD, etc.).
    /// * `signer_key` -- 32-byte key used for HMAC quote signing.
    #[must_use]
    pub const fn new(
        platform: TeePlatform,
        measurement: [u8; 32],
        signer_key: [u8; 32],
    ) -> Self {
        Self {
            platform,
            measurement,
            signer_key,
        }
    }

    /// Return the measurement configured for this provider.
    #[must_use]
    pub const fn measurement(&self) -> &[u8; 32] {
        &self.measurement
    }

    /// Encode the platform as a single discriminant byte.
    #[must_use]
    const fn platform_byte(platform: TeePlatform) -> u8 {
        match platform {
            TeePlatform::Sgx => 0x01,
            TeePlatform::SevSnp => 0x02,
            TeePlatform::Tdx => 0x03,
            TeePlatform::ArmCca => 0x04,
        }
    }

    /// Compute HMAC-SHA256 over the quote body (magic || platform || measurement || report_data).
    fn compute_quote_hmac(&self, body: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.signer_key)
            .expect("HMAC key length is 32 bytes");
        mac.update(body);
        let result = mac.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result.into_bytes());
        out
    }
}

#[cfg(feature = "crypto-sha256")]
impl TeeQuoteProvider for SoftwareTeeProvider {
    fn generate_quote(&self, report_data: &[u8; 64]) -> Result<[u8; 256], SignatureError> {
        let mut quote = [0u8; 256];

        // Magic
        quote[OFFSET_MAGIC..OFFSET_MAGIC + 4].copy_from_slice(QUOTE_MAGIC);

        // Platform discriminant
        quote[OFFSET_PLATFORM] = Self::platform_byte(self.platform);

        // Measurement
        quote[OFFSET_MEASUREMENT..OFFSET_MEASUREMENT + 32]
            .copy_from_slice(&self.measurement);

        // Report data
        quote[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + 64]
            .copy_from_slice(report_data);

        // HMAC over (magic || platform || measurement || report_data)
        let hmac_tag = self.compute_quote_hmac(&quote[..OFFSET_HMAC]);
        quote[OFFSET_HMAC..OFFSET_HMAC + 32].copy_from_slice(&hmac_tag);

        Ok(quote)
    }

    fn platform(&self) -> TeePlatform {
        self.platform
    }
}

/// Parse the platform byte back to a [`TeePlatform`] variant.
///
/// Returns `None` for unrecognised discriminants.
pub(crate) fn platform_from_byte(byte: u8) -> Option<TeePlatform> {
    match byte {
        0x01 => Some(TeePlatform::Sgx),
        0x02 => Some(TeePlatform::SevSnp),
        0x03 => Some(TeePlatform::Tdx),
        0x04 => Some(TeePlatform::ArmCca),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "crypto-sha256")]
    mod provider_tests {
        use super::*;

        fn test_provider() -> SoftwareTeeProvider {
            SoftwareTeeProvider::new(
                TeePlatform::Sgx,
                [0xAA; 32],
                [0xBB; 32],
            )
        }

        #[test]
        fn quote_has_correct_magic() {
            let provider = test_provider();
            let report_data = [0x11; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            assert_eq!(&quote[0..4], b"RVMq");
        }

        #[test]
        fn quote_has_correct_platform_byte() {
            let provider = test_provider();
            let quote = provider.generate_quote(&[0; 64]).unwrap();
            assert_eq!(quote[4], 0x01); // Sgx

            let tdx = SoftwareTeeProvider::new(TeePlatform::Tdx, [0; 32], [0; 32]);
            let quote = tdx.generate_quote(&[0; 64]).unwrap();
            assert_eq!(quote[4], 0x03); // Tdx
        }

        #[test]
        fn quote_contains_measurement() {
            let measurement = [0xCC; 32];
            let provider = SoftwareTeeProvider::new(
                TeePlatform::SevSnp,
                measurement,
                [0xDD; 32],
            );
            let quote = provider.generate_quote(&[0; 64]).unwrap();
            assert_eq!(&quote[5..37], &measurement);
        }

        #[test]
        fn quote_contains_report_data() {
            let provider = test_provider();
            let report_data = [0xEE; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            assert_eq!(&quote[37..101], &report_data);
        }

        #[test]
        fn quote_hmac_is_not_zero() {
            let provider = test_provider();
            let quote = provider.generate_quote(&[0xFF; 64]).unwrap();
            assert_ne!(&quote[101..133], &[0u8; 32]);
        }

        #[test]
        fn quote_is_deterministic() {
            let provider = test_provider();
            let rd = [0x42; 64];
            let q1 = provider.generate_quote(&rd).unwrap();
            let q2 = provider.generate_quote(&rd).unwrap();
            assert_eq!(q1, q2);
        }

        #[test]
        fn quote_trailing_bytes_are_zero() {
            let provider = test_provider();
            let quote = provider.generate_quote(&[0; 64]).unwrap();
            // Bytes after the quote structure (133..256) should be zero.
            assert_eq!(&quote[QUOTE_LEN..], &[0u8; 256 - QUOTE_LEN]);
        }

        #[test]
        fn platform_returns_configured_value() {
            let provider = test_provider();
            assert_eq!(provider.platform(), TeePlatform::Sgx);

            let arm = SoftwareTeeProvider::new(
                TeePlatform::ArmCca,
                [0; 32],
                [0; 32],
            );
            assert_eq!(arm.platform(), TeePlatform::ArmCca);
        }

        #[test]
        fn different_report_data_produces_different_quotes() {
            let provider = test_provider();
            let q1 = provider.generate_quote(&[0x00; 64]).unwrap();
            let q2 = provider.generate_quote(&[0xFF; 64]).unwrap();
            assert_ne!(q1, q2);
        }

        #[test]
        fn different_keys_produce_different_hmacs() {
            let p1 = SoftwareTeeProvider::new(
                TeePlatform::Sgx,
                [0xAA; 32],
                [0x11; 32],
            );
            let p2 = SoftwareTeeProvider::new(
                TeePlatform::Sgx,
                [0xAA; 32],
                [0x22; 32],
            );
            let rd = [0; 64];
            let q1 = p1.generate_quote(&rd).unwrap();
            let q2 = p2.generate_quote(&rd).unwrap();
            // Body (magic+platform+measurement+report_data) is the same,
            // but HMACs must differ.
            assert_eq!(&q1[..101], &q2[..101]);
            assert_ne!(&q1[101..133], &q2[101..133]);
        }
    }

    #[test]
    fn platform_from_byte_round_trips() {
        assert_eq!(platform_from_byte(0x01), Some(TeePlatform::Sgx));
        assert_eq!(platform_from_byte(0x02), Some(TeePlatform::SevSnp));
        assert_eq!(platform_from_byte(0x03), Some(TeePlatform::Tdx));
        assert_eq!(platform_from_byte(0x04), Some(TeePlatform::ArmCca));
        assert_eq!(platform_from_byte(0x00), None);
        assert_eq!(platform_from_byte(0xFF), None);
    }
}
