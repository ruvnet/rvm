//! FNV-1a hashing for witness chain integrity (ADR-134).
//!
//! FNV-1a is chosen for speed (< 50 ns for 64 bytes), not cryptographic
//! strength. For tamper resistance against a capable adversary, use the
//! optional TEE-backed `WitnessSigner`.

/// Re-export the canonical FNV-1a from rvm-types.
pub use rvm_types::fnv1a_64;

/// Compute the chain hash: FNV-1a of (`prev_hash` ++ sequence bytes).
///
/// This is stored in the next record's `prev_hash` field (truncated to u32).
#[must_use]
pub fn compute_chain_hash(prev_hash: u64, sequence: u64) -> u64 {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&prev_hash.to_le_bytes());
    buf[8..16].copy_from_slice(&sequence.to_le_bytes());
    fnv1a_64(&buf)
}

/// Compute the self-integrity hash of record data.
///
/// Takes a byte slice (typically the first 44 bytes of the record)
/// and computes FNV-1a over it.
#[must_use]
pub fn compute_record_hash(data: &[u8]) -> u64 {
    fnv1a_64(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_empty() {
        let hash = fnv1a_64(&[]);
        assert_eq!(hash, 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn test_fnv1a_deterministic() {
        let data = b"hello witness";
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fnv1a_different_inputs() {
        let h1 = fnv1a_64(b"aaa");
        let h2 = fnv1a_64(b"bbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_chain_hash_deterministic() {
        let h1 = compute_chain_hash(0, 1);
        let h2 = compute_chain_hash(0, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_chain_hash_differs_by_sequence() {
        let h1 = compute_chain_hash(0, 1);
        let h2 = compute_chain_hash(0, 2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_chain_hash_differs_by_prev() {
        let h1 = compute_chain_hash(100, 1);
        let h2 = compute_chain_hash(200, 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_record_hash_non_empty() {
        let data = [1u8, 2, 3, 4, 5];
        let h = compute_record_hash(&data);
        assert_ne!(h, 0);
    }
}
