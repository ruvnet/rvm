//! Content-hash algorithms for RVF segments.
//!
//! The segment header stores a 128-bit content hash whose algorithm is named
//! by the header's `checksum_algo` field. Every branch below has to match the
//! RuVector writer byte for byte, or verification would reject artifacts that
//! are in fact intact.
//!
//! | `checksum_algo` | Algorithm |
//! |---|---|
//! | 0 | CRC32C, deprecated — transparently upgraded to XXH3-128 |
//! | 1 | XXH3-128 (the writer's default) |
//! | 2 | SHAKE-256, first 128 bits |
//! | 3 | HMAC-SHAKE-256, reserved — falls back to XXH3-128 |
//! | other | XXH3-128 |
//!
//! Hashing is the *only* thing this crate does with an executable segment's
//! payload bytes (ADR-284 §1.7).

use crate::format::SegmentHeader;
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use subtle::ConstantTimeEq;

/// XXH3-128 of `data`, little-endian, as the header stores it.
#[must_use]
pub fn xxh3_128(data: &[u8]) -> [u8; 16] {
    xxhash_rust::xxh3::xxh3_128(data).to_le_bytes()
}

/// SHAKE-256 of `data`, truncated to the first 128 bits.
#[must_use]
pub fn shake256_128(data: &[u8]) -> [u8; 16] {
    let mut hasher = sha3::Shake256::default();
    hasher.update(data);
    let mut out = [0u8; 16];
    hasher.finalize_xof().read(&mut out);
    out
}

/// The content hash of `data` under algorithm `algo`.
///
/// Unknown and reserved algorithm values fall back to XXH3-128, matching the
/// writer. That is safe here because a mismatched fallback produces a hash
/// that does not verify, which is a refusal rather than an acceptance.
#[must_use]
pub fn content_hash(algo: u8, data: &[u8]) -> [u8; 16] {
    if algo == 2 {
        shake256_128(data)
    } else {
        xxh3_128(data)
    }
}

/// Whether `payload` hashes to the value in `header`.
///
/// The comparison is constant-time so that a partial match does not leak
/// through timing.
#[must_use]
pub fn verify_content_hash(header: &SegmentHeader, payload: &[u8]) -> bool {
    let expected = content_hash(header.checksum_algo, payload);
    expected.ct_eq(&header.content_hash).into()
}

/// SHA-256 of `data`.
///
/// This is what makes an RVF's canonical identity: `rvfIdentity` in the
/// ADR-291 runtime contract is the SHA-256 of the whole container.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // Disambiguated: sha3's `Update` is also in scope for the SHAKE path.
    Digest::update(&mut hasher, data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::SEGMENT_HEADER_SIZE;
    use crate::testkit;

    #[test]
    fn xxh3_and_shake_are_deterministic_and_distinct() {
        let data = b"test payload for differentiation";
        assert_eq!(xxh3_128(data), xxh3_128(data));
        assert_eq!(shake256_128(data), shake256_128(data));
        assert_ne!(xxh3_128(data), shake256_128(data));
    }

    #[test]
    fn algo_dispatch_matches_the_published_table() {
        let data = b"algo dispatch";
        for algo in [0u8, 1, 3, 9, 255] {
            assert_eq!(content_hash(algo, data), xxh3_128(data), "algo {algo}");
        }
        assert_eq!(content_hash(2, data), shake256_128(data));
    }

    #[test]
    fn a_written_segment_verifies_against_its_own_header() {
        let data = testkit::unsigned_segment(crate::format::SEG_TYPE_META, b"hello", 1);
        let header = SegmentHeader::parse(&data).unwrap();
        let payload = &data[SEGMENT_HEADER_SIZE..SEGMENT_HEADER_SIZE + 5];
        assert!(verify_content_hash(&header, payload));
    }

    #[test]
    fn a_flipped_payload_byte_fails_verification() {
        let data = testkit::unsigned_segment(crate::format::SEG_TYPE_META, b"hello", 1);
        let header = SegmentHeader::parse(&data).unwrap();
        assert!(!verify_content_hash(&header, b"hellp"));
    }

    #[test]
    fn sha256_matches_the_known_empty_digest() {
        // NIST: SHA-256("") = e3b0c442...
        let digest = sha256(b"");
        assert_eq!(digest[0], 0xe3);
        assert_eq!(digest[1], 0xb0);
        assert_eq!(digest[31], 0x55);
    }

    #[test]
    fn sha256_changes_when_any_byte_changes() {
        assert_ne!(sha256(b"agent"), sha256(b"agenu"));
    }
}
