//! Optional witness signing trait (ADR-134 Section 9).

use rvm_types::WitnessRecord;

/// Optional cryptographic signing for witness records.
pub trait WitnessSigner {
    /// Sign a witness record. Returns a truncated 8-byte signature.
    fn sign(&self, record: &WitnessRecord) -> [u8; 8];

    /// Verify a signature on a witness record.
    fn verify(&self, record: &WitnessRecord) -> bool;
}

/// No-op signer for deployments without TEE.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSigner;

impl WitnessSigner for NullSigner {
    fn sign(&self, _record: &WitnessRecord) -> [u8; 8] {
        [0u8; 8]
    }

    fn verify(&self, _record: &WitnessRecord) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_signer_sign() {
        let signer = NullSigner;
        let record = WitnessRecord::zeroed();
        assert_eq!(signer.sign(&record), [0u8; 8]);
    }

    #[test]
    fn test_null_signer_verify() {
        let signer = NullSigner;
        let record = WitnessRecord::zeroed();
        assert!(signer.verify(&record));
    }
}
