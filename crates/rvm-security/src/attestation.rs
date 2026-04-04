//! Attestation chain -- collects boot measurements and runtime witness
//! hashes into a verifiable attestation report (ADR-134, ADR-142).
//!
//! The attestation chain provides a tamper-evident record of the
//! platform's boot and runtime state. It can be presented to a remote
//! verifier to prove the system booted correctly and has been operating
//! within policy.
//!
//! When the `crypto-sha256` feature is enabled (default), SHA-256 is
//! used for chain extension, producing a native 32-byte chain root.
//! When disabled, the legacy FNV-1a overlapping-window scheme is used.

#[cfg(not(feature = "crypto-sha256"))]
use rvm_types::fnv1a_64;

/// Maximum number of entries in the attestation chain.
pub const MAX_ATTESTATION_ENTRIES: usize = 64;

/// A single entry in the attestation chain.
#[derive(Debug, Clone, Copy)]
pub struct AttestationEntry {
    /// Sequence number of this entry.
    pub sequence: u32,
    /// The measurement hash (boot phase hash or witness digest).
    pub hash: [u8; 32],
    /// A tag identifying the source: 0 = boot, 1 = runtime witness.
    pub source_tag: u8,
}

impl AttestationEntry {
    /// Create a zeroed attestation entry.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            sequence: 0,
            hash: [0u8; 32],
            source_tag: 0,
        }
    }
}

/// The attestation chain: accumulates boot + runtime measurements.
#[derive(Debug)]
pub struct AttestationChain {
    /// Chain entries.
    entries: [AttestationEntry; MAX_ATTESTATION_ENTRIES],
    /// Number of entries recorded.
    count: usize,
    /// Running chain hash (accumulated over all entries).
    chain_hash: [u8; 32],
}

impl AttestationChain {
    /// Create a new, empty attestation chain.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn new() -> Self {
        Self {
            entries: [AttestationEntry::zeroed(); MAX_ATTESTATION_ENTRIES],
            count: 0,
            chain_hash: [0u8; 32],
        }
    }

    /// Add a boot measurement to the chain.
    ///
    /// Returns `false` if the chain is full.
    pub fn add_boot_measurement(&mut self, hash: [u8; 32]) -> bool {
        self.add_entry(hash, 0)
    }

    /// Add a runtime witness hash to the chain.
    ///
    /// Returns `false` if the chain is full.
    pub fn add_runtime_witness(&mut self, hash: [u8; 32]) -> bool {
        self.add_entry(hash, 1)
    }

    /// Internal: add an entry with the given source tag.
    #[allow(clippy::cast_possible_truncation)]
    fn add_entry(&mut self, hash: [u8; 32], source_tag: u8) -> bool {
        if self.count >= MAX_ATTESTATION_ENTRIES {
            return false;
        }

        let seq = self.count as u32;
        self.entries[self.count] = AttestationEntry {
            sequence: seq,
            hash,
            source_tag,
        };
        self.count += 1;

        // Extend the chain hash
        self.extend_chain_hash(&hash);
        true
    }

    /// Extend the running chain hash with a new measurement using SHA-256.
    ///
    /// `new_chain_hash = SHA-256(current_chain_hash || measurement_hash)`
    ///
    /// The output is a native 32-byte digest -- a perfect fit for the
    /// `chain_root: [u8; 32]` field.
    #[cfg(feature = "crypto-sha256")]
    fn extend_chain_hash(&mut self, hash: &[u8; 32]) {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(self.chain_hash);
        hasher.update(hash);
        let digest = hasher.finalize();

        self.chain_hash.copy_from_slice(&digest);
    }

    /// Extend the running chain hash with a new measurement using FNV-1a
    /// overlapping windows (legacy fallback).
    #[cfg(not(feature = "crypto-sha256"))]
    fn extend_chain_hash(&mut self, hash: &[u8; 32]) {
        let mut input = [0u8; 64]; // current chain hash + new hash
        input[..32].copy_from_slice(&self.chain_hash);
        input[32..64].copy_from_slice(hash);

        let h0 = fnv1a_64(&input);
        let h1 = fnv1a_64(&input[8..]);
        let h2 = fnv1a_64(&input[16..]);
        let h3 = fnv1a_64(&input[24..]);

        self.chain_hash[..8].copy_from_slice(&h0.to_le_bytes());
        self.chain_hash[8..16].copy_from_slice(&h1.to_le_bytes());
        self.chain_hash[16..24].copy_from_slice(&h2.to_le_bytes());
        self.chain_hash[24..32].copy_from_slice(&h3.to_le_bytes());
    }

    /// Return the number of entries in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Check whether the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Generate an attestation report from the current chain state.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn generate_attestation_report(&self) -> AttestationReport {
        AttestationReport {
            entry_count: self.count as u32,
            chain_root: self.chain_hash,
            boot_measurement_count: self.boot_measurement_count(),
            runtime_witness_count: self.runtime_witness_count(),
        }
    }

    /// Count boot measurement entries.
    fn boot_measurement_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.count {
            if self.entries[i].source_tag == 0 {
                count += 1;
            }
        }
        count
    }

    /// Count runtime witness entries.
    fn runtime_witness_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.count {
            if self.entries[i].source_tag == 1 {
                count += 1;
            }
        }
        count
    }
}

impl Default for AttestationChain {
    fn default() -> Self {
        Self::new()
    }
}

/// An attestation report summarizing the platform's measurement state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationReport {
    /// Total number of entries in the attestation chain.
    pub entry_count: u32,
    /// Root hash of the attestation chain.
    pub chain_root: [u8; 32],
    /// Number of boot measurement entries.
    pub boot_measurement_count: u32,
    /// Number of runtime witness entries.
    pub runtime_witness_count: u32,
}

/// Verify an attestation report against an expected chain root.
///
/// Returns `true` if the report's chain root matches the expected root.
/// Uses constant-time comparison to prevent timing side-channel attacks
/// when verifying attestation roots derived from secrets.
#[must_use]
pub fn verify_attestation(report: &AttestationReport, expected_root: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    report.chain_root.ct_eq(expected_root).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain() {
        let chain = AttestationChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        let report = chain.generate_attestation_report();
        assert_eq!(report.entry_count, 0);
        assert_eq!(report.boot_measurement_count, 0);
        assert_eq!(report.runtime_witness_count, 0);
    }

    #[test]
    fn test_add_boot_measurement() {
        let mut chain = AttestationChain::new();
        assert!(chain.add_boot_measurement([0xAA; 32]));
        assert_eq!(chain.len(), 1);

        let report = chain.generate_attestation_report();
        assert_eq!(report.entry_count, 1);
        assert_eq!(report.boot_measurement_count, 1);
        assert_eq!(report.runtime_witness_count, 0);
    }

    #[test]
    fn test_add_runtime_witness() {
        let mut chain = AttestationChain::new();
        assert!(chain.add_runtime_witness([0xBB; 32]));
        assert_eq!(chain.len(), 1);

        let report = chain.generate_attestation_report();
        assert_eq!(report.runtime_witness_count, 1);
    }

    #[test]
    fn test_mixed_entries() {
        let mut chain = AttestationChain::new();
        chain.add_boot_measurement([1; 32]);
        chain.add_boot_measurement([2; 32]);
        chain.add_runtime_witness([3; 32]);
        chain.add_boot_measurement([4; 32]);
        chain.add_runtime_witness([5; 32]);

        let report = chain.generate_attestation_report();
        assert_eq!(report.entry_count, 5);
        assert_eq!(report.boot_measurement_count, 3);
        assert_eq!(report.runtime_witness_count, 2);
    }

    #[test]
    fn test_chain_determinism() {
        let mut c1 = AttestationChain::new();
        let mut c2 = AttestationChain::new();

        c1.add_boot_measurement([0xAA; 32]);
        c1.add_runtime_witness([0xBB; 32]);

        c2.add_boot_measurement([0xAA; 32]);
        c2.add_runtime_witness([0xBB; 32]);

        let r1 = c1.generate_attestation_report();
        let r2 = c2.generate_attestation_report();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_chain_sensitivity() {
        let mut c1 = AttestationChain::new();
        let mut c2 = AttestationChain::new();

        c1.add_boot_measurement([0xAA; 32]);
        c2.add_boot_measurement([0xBB; 32]);

        let r1 = c1.generate_attestation_report();
        let r2 = c2.generate_attestation_report();
        assert_ne!(r1.chain_root, r2.chain_root);
    }

    #[test]
    fn test_verify_attestation_matches() {
        let mut chain = AttestationChain::new();
        chain.add_boot_measurement([0xAA; 32]);
        let report = chain.generate_attestation_report();
        assert!(verify_attestation(&report, &report.chain_root));
    }

    #[test]
    fn test_verify_attestation_mismatch() {
        let mut chain = AttestationChain::new();
        chain.add_boot_measurement([0xAA; 32]);
        let report = chain.generate_attestation_report();
        let wrong_root = [0xFF; 32];
        assert!(!verify_attestation(&report, &wrong_root));
    }

    #[test]
    fn test_chain_full() {
        let mut chain = AttestationChain::new();
        for i in 0..MAX_ATTESTATION_ENTRIES {
            assert!(chain.add_boot_measurement([i as u8; 32]));
        }
        assert_eq!(chain.len(), MAX_ATTESTATION_ENTRIES);
        // Chain is now full
        assert!(!chain.add_boot_measurement([0xFF; 32]));
    }

    #[test]
    fn test_order_matters() {
        let mut c1 = AttestationChain::new();
        let mut c2 = AttestationChain::new();

        c1.add_boot_measurement([1; 32]);
        c1.add_boot_measurement([2; 32]);

        c2.add_boot_measurement([2; 32]);
        c2.add_boot_measurement([1; 32]);

        let r1 = c1.generate_attestation_report();
        let r2 = c2.generate_attestation_report();
        assert_ne!(r1.chain_root, r2.chain_root);
    }

    #[cfg(feature = "crypto-sha256")]
    #[test]
    fn test_chain_root_not_zero_after_measurement() {
        let mut chain = AttestationChain::new();
        chain.add_boot_measurement([0xAA; 32]);
        let report = chain.generate_attestation_report();
        assert_ne!(report.chain_root, [0u8; 32]);
    }
}
