//! Optional witness signing trait (ADR-134 Section 9).
//!
//! Provides pluggable signing for witness records. Production
//! deployments should enable the `strict-signing` feature to use
//! [`StrictSigner`] (FNV-1a based) or supply a TEE-backed signer.

use rvm_types::WitnessRecord;

/// Optional cryptographic signing for witness records.
pub trait WitnessSigner {
    /// Sign a witness record. Returns a truncated 8-byte signature.
    fn sign(&self, record: &WitnessRecord) -> [u8; 8];

    /// Verify a signature on a witness record.
    fn verify(&self, record: &WitnessRecord) -> bool;
}

/// No-op signer for deployments without TEE.
///
/// **Security warning:** `NullSigner` accepts all records as valid
/// without performing any integrity check. It exists only for
/// testing and environments where TEE signing is unavailable.
#[deprecated(note = "Use a real WitnessSigner implementation in production")]
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSigner;

#[allow(deprecated)]
impl WitnessSigner for NullSigner {
    fn sign(&self, _record: &WitnessRecord) -> [u8; 8] {
        [0u8; 8]
    }

    fn verify(&self, _record: &WitnessRecord) -> bool {
        true
    }
}

/// FNV-1a-based witness signer for non-TEE deployments.
///
/// Computes an FNV-1a hash over the first 52 bytes of the witness
/// record (all fields except `aux` and `pad`) and stores the
/// truncated 8-byte result in the `aux` field as a signature.
///
/// This is not cryptographically strong but provides non-trivial
/// tamper evidence for environments without hardware attestation.
///
/// When the `strict-signing` feature is enabled, this is the
/// recommended default signer.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrictSigner;

impl StrictSigner {
    /// Compute the FNV-1a signature bytes for a witness record.
    ///
    /// We hash the first 52 bytes of the record (all content fields
    /// before `aux` and `pad`).
    fn compute_signature(record: &WitnessRecord) -> [u8; 8] {
        let record_bytes = record_to_bytes(record);
        // Hash the first 52 bytes (everything before aux + pad).
        let hash = fnv1a_64(&record_bytes[..52]);
        hash.to_le_bytes()
    }
}

impl WitnessSigner for StrictSigner {
    fn sign(&self, record: &WitnessRecord) -> [u8; 8] {
        Self::compute_signature(record)
    }

    fn verify(&self, record: &WitnessRecord) -> bool {
        let expected = Self::compute_signature(record);
        record.aux == expected
    }
}

/// Convert a `WitnessRecord`'s content fields to a byte array for hashing.
///
/// We manually serialise the fields in layout order to avoid depending
/// on `repr(C)` padding semantics across platforms.
fn record_to_bytes(r: &WitnessRecord) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[0..8].copy_from_slice(&r.sequence.to_le_bytes());
    buf[8..16].copy_from_slice(&r.timestamp_ns.to_le_bytes());
    buf[16] = r.action_kind;
    buf[17] = r.proof_tier;
    buf[18] = r.flags;
    buf[19] = 0; // reserved
    buf[20..24].copy_from_slice(&r.actor_partition_id.to_le_bytes());
    buf[24..32].copy_from_slice(&r.target_object_id.to_le_bytes());
    buf[32..36].copy_from_slice(&r.capability_hash.to_le_bytes());
    buf[36..44].copy_from_slice(&r.payload);
    buf[44..48].copy_from_slice(&r.prev_hash.to_le_bytes());
    buf[48..52].copy_from_slice(&r.record_hash.to_le_bytes());
    buf[52..60].copy_from_slice(&r.aux);
    // buf[60..64] is pad, stays zero.
    buf
}

/// FNV-1a 64-bit hash.
fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Return the default signer based on feature flags.
///
/// When `strict-signing` is enabled, returns a `StrictSigner`.
/// Otherwise, returns a `NullSigner`.
#[cfg(feature = "strict-signing")]
#[must_use]
pub fn default_signer() -> StrictSigner {
    StrictSigner
}

/// Return the default signer based on feature flags.
///
/// When `strict-signing` is not enabled, returns a `NullSigner`.
#[cfg(not(feature = "strict-signing"))]
#[must_use]
#[allow(deprecated)]
pub fn default_signer() -> NullSigner {
    NullSigner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_null_signer_sign() {
        let signer = NullSigner;
        let record = WitnessRecord::zeroed();
        assert_eq!(signer.sign(&record), [0u8; 8]);
    }

    #[test]
    #[allow(deprecated)]
    fn test_null_signer_verify() {
        let signer = NullSigner;
        let record = WitnessRecord::zeroed();
        assert!(signer.verify(&record));
    }

    #[test]
    fn test_strict_signer_sign_nonzero() {
        let signer = StrictSigner;
        let mut record = WitnessRecord::zeroed();
        record.sequence = 42;
        record.action_kind = 0x01;
        record.actor_partition_id = 7;

        let sig = signer.sign(&record);
        // The signature should not be all zeros for non-zero input.
        assert_ne!(sig, [0u8; 8]);
    }

    #[test]
    fn test_strict_signer_verify_round_trip() {
        let signer = StrictSigner;
        let mut record = WitnessRecord::zeroed();
        record.sequence = 100;
        record.timestamp_ns = 1_000_000;
        record.action_kind = 0x10;
        record.proof_tier = 2;
        record.actor_partition_id = 3;
        record.target_object_id = 99;
        record.capability_hash = 0xDEAD;
        record.prev_hash = 0x1234;
        record.record_hash = 0x5678;

        // Sign: place signature in aux.
        let sig = signer.sign(&record);
        record.aux = sig;

        // Verify should pass.
        assert!(signer.verify(&record));
    }

    #[test]
    fn test_strict_signer_tampered_record_fails() {
        let signer = StrictSigner;
        let mut record = WitnessRecord::zeroed();
        record.sequence = 100;
        record.actor_partition_id = 3;

        // Sign and place in aux.
        let sig = signer.sign(&record);
        record.aux = sig;

        // Tamper with the record.
        record.sequence = 101;

        // Verify should fail.
        assert!(!signer.verify(&record));
    }

    #[test]
    fn test_strict_signer_deterministic() {
        let signer = StrictSigner;
        let mut record = WitnessRecord::zeroed();
        record.sequence = 42;

        let sig1 = signer.sign(&record);
        let sig2 = signer.sign(&record);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_strict_signer_different_records_different_sigs() {
        let signer = StrictSigner;

        let mut r1 = WitnessRecord::zeroed();
        r1.sequence = 1;

        let mut r2 = WitnessRecord::zeroed();
        r2.sequence = 2;

        assert_ne!(signer.sign(&r1), signer.sign(&r2));
    }

    #[test]
    fn test_default_signer_exists() {
        // Just verify the function is callable.
        let _signer = default_signer();
    }
}
