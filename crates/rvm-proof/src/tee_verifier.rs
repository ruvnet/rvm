//! Software-emulated TEE quote verifier (ADR-142 Phase 3).
//!
//! Validates quotes produced by [`SoftwareTeeProvider`] using
//! constant-time HMAC comparison and collateral expiry tracking.

use crate::constant_time::ct_eq_32;
use crate::signer::SignatureError;
use crate::tee::TeeQuoteVerifier;
use crate::tee_provider::{
    platform_from_byte, QUOTE_LEN, QUOTE_MAGIC,
    OFFSET_HMAC, OFFSET_MEASUREMENT, OFFSET_PLATFORM, OFFSET_REPORT_DATA,
};

#[cfg(feature = "crypto-sha256")]
use hmac::{Hmac, Mac};
#[cfg(feature = "crypto-sha256")]
use sha2::Sha256;

#[cfg(feature = "crypto-sha256")]
type HmacSha256 = Hmac<Sha256>;

/// Software TEE quote verifier.
///
/// Validates quotes from [`SoftwareTeeProvider`](crate::tee_provider::SoftwareTeeProvider)
/// using constant-time comparison. Supports collateral expiry tracking
/// via a monotonic epoch counter.
#[cfg(feature = "crypto-sha256")]
pub struct SoftwareTeeVerifier {
    signer_key: [u8; 32],
    collateral_expiry_epoch: u64,
    current_epoch: u64,
}

#[cfg(feature = "crypto-sha256")]
impl SoftwareTeeVerifier {
    /// Create a new software TEE verifier.
    ///
    /// # Arguments
    ///
    /// * `signer_key` -- The 32-byte HMAC key matching the provider's key.
    /// * `collateral_expiry_epoch` -- Epoch at which collateral expires (0 = no expiry).
    /// * `current_epoch` -- The current epoch value.
    #[must_use]
    pub const fn new(
        signer_key: [u8; 32],
        collateral_expiry_epoch: u64,
        current_epoch: u64,
    ) -> Self {
        Self {
            signer_key,
            collateral_expiry_epoch,
            current_epoch,
        }
    }

    /// Update the current epoch (for testing or monotonic time advancement).
    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Refresh collateral by setting a new expiry epoch.
    pub fn refresh_collateral(&mut self, new_expiry_epoch: u64) {
        self.collateral_expiry_epoch = new_expiry_epoch;
    }

    /// Compute HMAC-SHA256 over the given body bytes.
    fn compute_hmac(&self, body: &[u8]) -> [u8; 32] {
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
impl TeeQuoteVerifier for SoftwareTeeVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        expected_measurement: &[u8; 32],
        expected_report_data: &[u8; 64],
    ) -> Result<(), SignatureError> {
        // Check minimum length.
        if quote.len() < QUOTE_LEN {
            return Err(SignatureError::MalformedInput);
        }

        // Verify magic.
        if &quote[..4] != QUOTE_MAGIC.as_slice() {
            return Err(SignatureError::MalformedInput);
        }

        // Verify platform byte is recognised.
        if platform_from_byte(quote[OFFSET_PLATFORM]).is_none() {
            return Err(SignatureError::UnsupportedPlatform);
        }

        // Check collateral expiry before doing expensive HMAC work.
        if !self.collateral_valid() {
            return Err(SignatureError::ExpiredCollateral);
        }

        // Verify measurement matches.
        let quote_measurement: &[u8; 32] = quote[OFFSET_MEASUREMENT..OFFSET_MEASUREMENT + 32]
            .try_into()
            .map_err(|_| SignatureError::MalformedInput)?;
        if !ct_eq_32(quote_measurement, expected_measurement) {
            return Err(SignatureError::BadMeasurement);
        }

        // Verify report data matches.
        let quote_report_data = &quote[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + 64];
        // Use constant-time comparison for the 64-byte report data.
        let mut diff: u8 = 0;
        let mut i = 0;
        while i < 64 {
            diff |= quote_report_data[i] ^ expected_report_data[i];
            i += 1;
        }
        if diff != 0 {
            return Err(SignatureError::BadSignature);
        }

        // Recompute HMAC over the body and constant-time compare.
        let expected_hmac = self.compute_hmac(&quote[..OFFSET_HMAC]);
        let quote_hmac: &[u8; 32] = quote[OFFSET_HMAC..OFFSET_HMAC + 32]
            .try_into()
            .map_err(|_| SignatureError::MalformedInput)?;
        if !ct_eq_32(&expected_hmac, quote_hmac) {
            return Err(SignatureError::BadSignature);
        }

        Ok(())
    }

    fn collateral_valid(&self) -> bool {
        if self.collateral_expiry_epoch == 0 {
            return true;
        }
        self.current_epoch < self.collateral_expiry_epoch
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(feature = "crypto-sha256")]
    mod verifier_tests {
        use crate::tee::{TeePlatform, TeeQuoteProvider, TeeQuoteVerifier};
        use crate::tee_provider::SoftwareTeeProvider;
        use crate::tee_verifier::SoftwareTeeVerifier;
        use crate::signer::SignatureError;

        fn test_pair() -> (SoftwareTeeProvider, SoftwareTeeVerifier) {
            let key = [0xBB; 32];
            let measurement = [0xAA; 32];
            let provider = SoftwareTeeProvider::new(TeePlatform::Sgx, measurement, key);
            let verifier = SoftwareTeeVerifier::new(key, 0, 0);
            (provider, verifier)
        }

        #[test]
        fn accepts_valid_quote() {
            let (provider, verifier) = test_pair();
            let report_data = [0x11; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            let measurement = [0xAA; 32];
            assert!(verifier.verify_quote(&quote, &measurement, &report_data).is_ok());
        }

        #[test]
        fn rejects_tampered_hmac() {
            let (provider, verifier) = test_pair();
            let report_data = [0x22; 64];
            let mut quote = provider.generate_quote(&report_data).unwrap();
            // Flip a bit in the HMAC.
            quote[101] ^= 0xFF;
            let measurement = [0xAA; 32];
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &report_data),
                Err(SignatureError::BadSignature),
            );
        }

        #[test]
        fn rejects_tampered_measurement_in_quote() {
            let (provider, verifier) = test_pair();
            let report_data = [0x33; 64];
            let mut quote = provider.generate_quote(&report_data).unwrap();
            // Tamper with the measurement inside the quote.
            quote[5] ^= 0xFF;
            let measurement = [0xAA; 32];
            // The HMAC will also fail, but measurement check happens first.
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &report_data),
                Err(SignatureError::BadMeasurement),
            );
        }

        #[test]
        fn rejects_wrong_expected_measurement() {
            let (provider, verifier) = test_pair();
            let report_data = [0x44; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            let wrong_measurement = [0xFF; 32];
            assert_eq!(
                verifier.verify_quote(&quote, &wrong_measurement, &report_data),
                Err(SignatureError::BadMeasurement),
            );
        }

        #[test]
        fn rejects_wrong_report_data() {
            let (provider, verifier) = test_pair();
            let report_data = [0x55; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            let wrong_report_data = [0x00; 64];
            let measurement = [0xAA; 32];
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &wrong_report_data),
                Err(SignatureError::BadSignature),
            );
        }

        #[test]
        fn rejects_truncated_quote() {
            let (_, verifier) = test_pair();
            let short_quote = [0u8; 50];
            let measurement = [0xAA; 32];
            let report_data = [0; 64];
            assert_eq!(
                verifier.verify_quote(&short_quote, &measurement, &report_data),
                Err(SignatureError::MalformedInput),
            );
        }

        #[test]
        fn rejects_bad_magic() {
            let (provider, verifier) = test_pair();
            let report_data = [0; 64];
            let mut quote = provider.generate_quote(&report_data).unwrap();
            quote[0] = b'X'; // Corrupt magic.
            let measurement = [0xAA; 32];
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &report_data),
                Err(SignatureError::MalformedInput),
            );
        }

        #[test]
        fn rejects_unknown_platform() {
            let (provider, verifier) = test_pair();
            let report_data = [0; 64];
            let mut quote = provider.generate_quote(&report_data).unwrap();
            quote[4] = 0xFF; // Unknown platform byte.
            let measurement = [0xAA; 32];
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &report_data),
                Err(SignatureError::UnsupportedPlatform),
            );
        }

        #[test]
        fn collateral_valid_no_expiry() {
            let verifier = SoftwareTeeVerifier::new([0; 32], 0, 100);
            assert!(verifier.collateral_valid());
        }

        #[test]
        fn collateral_valid_before_expiry() {
            let verifier = SoftwareTeeVerifier::new([0; 32], 100, 50);
            assert!(verifier.collateral_valid());
        }

        #[test]
        fn collateral_invalid_at_expiry() {
            let verifier = SoftwareTeeVerifier::new([0; 32], 100, 100);
            assert!(!verifier.collateral_valid());
        }

        #[test]
        fn collateral_invalid_after_expiry() {
            let verifier = SoftwareTeeVerifier::new([0; 32], 100, 200);
            assert!(!verifier.collateral_valid());
        }

        #[test]
        fn rejects_expired_collateral() {
            let key = [0xBB; 32];
            let measurement = [0xAA; 32];
            let provider = SoftwareTeeProvider::new(TeePlatform::Sgx, measurement, key);
            let verifier = SoftwareTeeVerifier::new(key, 10, 20); // Expired.
            let report_data = [0; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &report_data),
                Err(SignatureError::ExpiredCollateral),
            );
        }

        #[test]
        fn set_epoch_updates_current_epoch() {
            let mut verifier = SoftwareTeeVerifier::new([0; 32], 100, 50);
            assert!(verifier.collateral_valid());
            verifier.set_epoch(150);
            assert!(!verifier.collateral_valid());
        }

        #[test]
        fn refresh_collateral_extends_validity() {
            let mut verifier = SoftwareTeeVerifier::new([0; 32], 100, 150);
            assert!(!verifier.collateral_valid());
            verifier.refresh_collateral(200);
            assert!(verifier.collateral_valid());
        }

        #[test]
        fn wrong_key_rejects_quote() {
            let key = [0xBB; 32];
            let wrong_key = [0xCC; 32];
            let measurement = [0xAA; 32];
            let provider = SoftwareTeeProvider::new(TeePlatform::Sgx, measurement, key);
            let verifier = SoftwareTeeVerifier::new(wrong_key, 0, 0);
            let report_data = [0; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            assert_eq!(
                verifier.verify_quote(&quote, &measurement, &report_data),
                Err(SignatureError::BadSignature),
            );
        }
    }
}
