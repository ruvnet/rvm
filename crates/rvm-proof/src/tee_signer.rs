//! TEE-backed witness signer (ADR-142 Phase 3).
//!
//! Composes a [`TeeQuoteProvider`] and [`TeeQuoteVerifier`] with an
//! inner [`HmacSha256WitnessSigner`] to produce witness signatures
//! that are bound to a TEE measurement via self-attestation.

use crate::signer::{SignatureError, WitnessSigner};
use crate::tee::{TeeQuoteProvider, TeeQuoteVerifier};

#[cfg(feature = "crypto-sha256")]
use crate::signer::HmacSha256WitnessSigner;

#[cfg(feature = "crypto-sha256")]
use sha2::{Digest, Sha256};

/// TEE-backed witness signer that combines quote generation,
/// verification, and signing into a single pipeline.
///
/// The signing flow is:
///
/// 1. Generate a TEE quote with the digest as report data (padded to 64 bytes).
/// 2. Verify the quote against the expected measurement (self-attestation).
/// 3. Sign the digest with the inner HMAC signer.
///
/// This ensures that every signature is bound to a specific TEE measurement
/// and platform, providing attestation-backed integrity.
#[cfg(feature = "crypto-sha256")]
pub struct TeeWitnessSigner<P: TeeQuoteProvider, V: TeeQuoteVerifier> {
    provider: P,
    verifier: V,
    hmac_signer: HmacSha256WitnessSigner,
    measurement: [u8; 32],
}

#[cfg(feature = "crypto-sha256")]
impl<P: TeeQuoteProvider, V: TeeQuoteVerifier> TeeWitnessSigner<P, V> {
    /// Create a new TEE witness signer.
    ///
    /// # Arguments
    ///
    /// * `provider` -- TEE quote provider for generating attestation quotes.
    /// * `verifier` -- TEE quote verifier for self-attestation.
    /// * `hmac_signer` -- Inner HMAC-SHA256 signer for producing signatures.
    /// * `measurement` -- Expected enclave measurement for self-attestation.
    #[must_use]
    pub const fn new(
        provider: P,
        verifier: V,
        hmac_signer: HmacSha256WitnessSigner,
        measurement: [u8; 32],
    ) -> Self {
        Self {
            provider,
            verifier,
            hmac_signer,
            measurement,
        }
    }

    /// Pad a 32-byte digest into a 64-byte report data buffer.
    ///
    /// The digest occupies the first 32 bytes; the remaining 32 bytes
    /// are zeroed. This is the canonical encoding for binding a digest
    /// to a TEE quote.
    fn digest_to_report_data(digest: &[u8; 32]) -> [u8; 64] {
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(digest);
        report_data
    }

    /// Perform self-attestation: generate and verify a quote for the
    /// given digest.
    fn self_attest(&self, digest: &[u8; 32]) -> Result<(), SignatureError> {
        let report_data = Self::digest_to_report_data(digest);
        let quote = self.provider.generate_quote(&report_data)?;
        self.verifier
            .verify_quote(&quote, &self.measurement, &report_data)
    }

    /// Return a reference to the inner HMAC signer.
    #[must_use]
    pub const fn inner_signer(&self) -> &HmacSha256WitnessSigner {
        &self.hmac_signer
    }

    /// Return the measurement this signer is bound to.
    #[must_use]
    pub const fn measurement(&self) -> &[u8; 32] {
        &self.measurement
    }

    /// Encode the platform as a single discriminant byte.
    fn platform_byte(&self) -> u8 {
        use crate::tee::TeePlatform;
        match self.provider.platform() {
            TeePlatform::Sgx => 0x01,
            TeePlatform::SevSnp => 0x02,
            TeePlatform::Tdx => 0x03,
            TeePlatform::ArmCca => 0x04,
        }
    }
}

#[cfg(feature = "crypto-sha256")]
impl<P: TeeQuoteProvider, V: TeeQuoteVerifier> WitnessSigner for TeeWitnessSigner<P, V> {
    fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        // Step 1+2: Self-attest (generate quote, then verify it).
        // If self-attestation fails in a `no_std` environment where we
        // cannot propagate Result from `sign`, we return a zero signature
        // which will fail verification. This keeps the trait contract.
        if self.self_attest(digest).is_err() {
            return [0u8; 64];
        }
        // Step 3: Sign with the inner HMAC signer.
        self.hmac_signer.sign(digest)
    }

    fn verify(&self, digest: &[u8; 32], signature: &[u8; 64]) -> Result<(), SignatureError> {
        // Verify the cryptographic signature first.
        self.hmac_signer.verify(digest, signature)?;
        // Then verify measurement binding via self-attestation.
        self.self_attest(digest)
    }

    fn signer_id(&self) -> [u8; 32] {
        // signer_id = SHA-256(0x03 || platform_byte || measurement)
        let mut hasher = Sha256::new();
        hasher.update([0x03]);
        hasher.update([self.platform_byte()]);
        hasher.update(self.measurement);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(feature = "crypto-sha256")]
    mod tee_signer_tests {
        use crate::signer::{HmacSha256WitnessSigner, SignatureError, WitnessSigner};
        use crate::tee::{TeePlatform, TeeQuoteProvider, TeeQuoteVerifier};
        use crate::tee_provider::SoftwareTeeProvider;
        use crate::tee_verifier::SoftwareTeeVerifier;
        use crate::tee_signer::TeeWitnessSigner;

        fn make_signer() -> TeeWitnessSigner<SoftwareTeeProvider, SoftwareTeeVerifier> {
            let tee_key = [0xBB; 32];
            let measurement = [0xAA; 32];
            let hmac_key = [0xCC; 32];
            let provider = SoftwareTeeProvider::new(TeePlatform::Sgx, measurement, tee_key);
            let verifier = SoftwareTeeVerifier::new(tee_key, 0, 0);
            let hmac_signer = HmacSha256WitnessSigner::new(hmac_key);
            TeeWitnessSigner::new(provider, verifier, hmac_signer, measurement)
        }

        #[test]
        fn sign_verify_round_trip() {
            let signer = make_signer();
            let digest = [0x11; 32];
            let sig = signer.sign(&digest);
            assert!(signer.verify(&digest, &sig).is_ok());
        }

        #[test]
        fn verify_rejects_tampered_signature() {
            let signer = make_signer();
            let digest = [0x22; 32];
            let mut sig = signer.sign(&digest);
            sig[0] ^= 0xFF;
            assert_eq!(
                signer.verify(&digest, &sig),
                Err(SignatureError::BadSignature),
            );
        }

        #[test]
        fn verify_rejects_wrong_digest() {
            let signer = make_signer();
            let digest_a = [0x33; 32];
            let digest_b = [0x44; 32];
            let sig = signer.sign(&digest_a);
            assert_eq!(
                signer.verify(&digest_b, &sig),
                Err(SignatureError::BadSignature),
            );
        }

        #[test]
        fn signer_id_is_deterministic() {
            let signer = make_signer();
            let id1 = signer.signer_id();
            let id2 = signer.signer_id();
            assert_eq!(id1, id2);
        }

        #[test]
        fn signer_id_is_not_zero() {
            let signer = make_signer();
            assert_ne!(signer.signer_id(), [0u8; 32]);
        }

        #[test]
        fn signer_id_differs_per_platform() {
            let tee_key = [0xBB; 32];
            let measurement = [0xAA; 32];
            let hmac_key = [0xCC; 32];

            let sgx_provider = SoftwareTeeProvider::new(TeePlatform::Sgx, measurement, tee_key);
            let sgx_verifier = SoftwareTeeVerifier::new(tee_key, 0, 0);
            let sgx_signer = TeeWitnessSigner::new(
                sgx_provider,
                sgx_verifier,
                HmacSha256WitnessSigner::new(hmac_key),
                measurement,
            );

            let tdx_provider = SoftwareTeeProvider::new(TeePlatform::Tdx, measurement, tee_key);
            let tdx_verifier = SoftwareTeeVerifier::new(tee_key, 0, 0);
            let tdx_signer = TeeWitnessSigner::new(
                tdx_provider,
                tdx_verifier,
                HmacSha256WitnessSigner::new(hmac_key),
                measurement,
            );

            assert_ne!(sgx_signer.signer_id(), tdx_signer.signer_id());
        }

        #[test]
        fn signer_id_differs_per_measurement() {
            let tee_key = [0xBB; 32];
            let hmac_key = [0xCC; 32];

            let m1 = [0x11; 32];
            let p1 = SoftwareTeeProvider::new(TeePlatform::Sgx, m1, tee_key);
            let v1 = SoftwareTeeVerifier::new(tee_key, 0, 0);
            let s1 = TeeWitnessSigner::new(
                p1,
                v1,
                HmacSha256WitnessSigner::new(hmac_key),
                m1,
            );

            let m2 = [0x22; 32];
            let p2 = SoftwareTeeProvider::new(TeePlatform::Sgx, m2, tee_key);
            let v2 = SoftwareTeeVerifier::new(tee_key, 0, 0);
            let s2 = TeeWitnessSigner::new(
                p2,
                v2,
                HmacSha256WitnessSigner::new(hmac_key),
                m2,
            );

            assert_ne!(s1.signer_id(), s2.signer_id());
        }

        #[test]
        fn sign_returns_zero_on_attestation_failure() {
            // Create a signer with mismatched measurement to trigger
            // self-attestation failure.
            let tee_key = [0xBB; 32];
            let provider_measurement = [0xAA; 32];
            let signer_measurement = [0xFF; 32]; // Mismatch!
            let hmac_key = [0xCC; 32];
            let provider = SoftwareTeeProvider::new(
                TeePlatform::Sgx,
                provider_measurement,
                tee_key,
            );
            let verifier = SoftwareTeeVerifier::new(tee_key, 0, 0);
            let hmac_signer = HmacSha256WitnessSigner::new(hmac_key);
            let signer = TeeWitnessSigner::new(
                provider,
                verifier,
                hmac_signer,
                signer_measurement,
            );

            let digest = [0x55; 32];
            let sig = signer.sign(&digest);
            assert_eq!(sig, [0u8; 64]);
        }

        #[test]
        fn expired_collateral_blocks_signing() {
            let tee_key = [0xBB; 32];
            let measurement = [0xAA; 32];
            let hmac_key = [0xCC; 32];
            let provider = SoftwareTeeProvider::new(TeePlatform::Sgx, measurement, tee_key);
            let verifier = SoftwareTeeVerifier::new(tee_key, 10, 20); // Expired.
            let hmac_signer = HmacSha256WitnessSigner::new(hmac_key);
            let signer = TeeWitnessSigner::new(
                provider,
                verifier,
                hmac_signer,
                measurement,
            );

            let digest = [0x66; 32];
            let sig = signer.sign(&digest);
            // Self-attestation fails due to expired collateral, so zero signature.
            assert_eq!(sig, [0u8; 64]);
        }

        #[test]
        fn full_pipeline_provider_verifier_signer() {
            // End-to-end: provider generates quote, verifier validates it,
            // signer signs and verifies a digest.
            let tee_key = [0xDD; 32];
            let measurement = [0xEE; 32];
            let hmac_key = [0xFF; 32];

            let provider = SoftwareTeeProvider::new(TeePlatform::SevSnp, measurement, tee_key);
            let verifier = SoftwareTeeVerifier::new(tee_key, 1000, 500);

            // First, manually test the quote pipeline.
            let report_data = [0x77; 64];
            let quote = provider.generate_quote(&report_data).unwrap();
            assert!(verifier
                .verify_quote(&quote, &measurement, &report_data)
                .is_ok());

            // Now test the combined signer.
            let signer = TeeWitnessSigner::new(
                SoftwareTeeProvider::new(TeePlatform::SevSnp, measurement, tee_key),
                SoftwareTeeVerifier::new(tee_key, 1000, 500),
                HmacSha256WitnessSigner::new(hmac_key),
                measurement,
            );

            let digest = [0x88; 32];
            let sig = signer.sign(&digest);
            assert_ne!(sig, [0u8; 64]); // Not a failure signature.
            assert!(signer.verify(&digest, &sig).is_ok());
        }

        #[test]
        fn signature_is_deterministic() {
            let signer = make_signer();
            let digest = [0x99; 32];
            let sig1 = signer.sign(&digest);
            let sig2 = signer.sign(&digest);
            assert_eq!(sig1, sig2);
        }

        #[test]
        fn all_four_platforms_produce_distinct_ids() {
            let tee_key = [0xBB; 32];
            let measurement = [0xAA; 32];
            let hmac_key = [0xCC; 32];

            let platforms = [
                TeePlatform::Sgx,
                TeePlatform::SevSnp,
                TeePlatform::Tdx,
                TeePlatform::ArmCca,
            ];

            let ids: [_; 4] = core::array::from_fn(|i| {
                let provider = SoftwareTeeProvider::new(platforms[i], measurement, tee_key);
                let verifier = SoftwareTeeVerifier::new(tee_key, 0, 0);
                let signer = TeeWitnessSigner::new(
                    provider,
                    verifier,
                    HmacSha256WitnessSigner::new(hmac_key),
                    measurement,
                );
                signer.signer_id()
            });

            // All pairs must be distinct.
            for i in 0..4 {
                for j in (i + 1)..4 {
                    assert_ne!(ids[i], ids[j], "platforms {i} and {j} collide");
                }
            }
        }
    }
}
