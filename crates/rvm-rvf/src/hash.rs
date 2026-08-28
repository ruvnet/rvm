//! Content-hash algorithms for RVF segments.
//!
//! The segment header stores a 128-bit content hash whose algorithm is named
//! by the header's `checksum_algo` field. Every branch below has to match the
//! RuVector writer byte for byte, or verification would reject artifacts that
//! are in fact intact.
//!
//! | `checksum_algo` | Algorithm |
//! |---|---|
//! | 0 | Runtime-v1 legacy IEEE CRC32 rotation |
//! | 1 | XXH3-128 (the writer's default) |
//! | 2 | SHAKE-256, first 128 bits |
//! | 3 | HMAC-SHAKE-256, reserved — refused |
//! | other | unknown — refused |
//!
//! RuVector v1 has two shipped writer paths. `rvf-runtime` labels its legacy
//! CRC-rotation hash as algorithm zero; `rvf-wire` defaults to algorithm one.
//! Treating zero or an unknown value as XXH3 accepts neither contract safely,
//! so verification implements the deployed runtime bytes and fails closed on
//! every unimplemented discriminator.
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

/// Legacy RVF-runtime hash for `checksum_algo = 0`.
///
/// It is IEEE CRC32 (polynomial `0xEDB88320`, not CRC32C), repeated in four
/// little-endian lanes after rotations of 0, 8, 16, and 24 bits. This weak
/// checksum is retained strictly for byte compatibility with deployed v1
/// runtime containers; executable authority still requires a signature.
#[must_use]
pub fn legacy_crc32_rotation_128(data: &[u8]) -> [u8; 16] {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc = !crc;

    let mut hash = [0u8; 16];
    for lane in 0..4 {
        let rotated = crc.rotate_left(lane as u32 * 8);
        hash[lane * 4..(lane + 1) * 4].copy_from_slice(&rotated.to_le_bytes());
    }
    hash
}

/// Whether `algo` is implemented by this verifier.
#[must_use]
pub const fn is_supported_content_hash(algo: u8) -> bool {
    matches!(algo, 0..=2)
}

/// The content hash of `data` under algorithm `algo`.
///
/// Reserved and unknown values return a zero sentinel. Callers deciding
/// whether bytes are trustworthy must use [`verify_content_hash`], which
/// explicitly refuses those values before comparing any digest.
#[must_use]
pub fn content_hash(algo: u8, data: &[u8]) -> [u8; 16] {
    match algo {
        0 => legacy_crc32_rotation_128(data),
        1 => xxh3_128(data),
        2 => shake256_128(data),
        _ => [0u8; 16],
    }
}

/// Whether `payload` hashes to the value in `header`.
///
/// The comparison is constant-time so that a partial match does not leak
/// through timing.
#[must_use]
pub fn verify_content_hash(header: &SegmentHeader, payload: &[u8]) -> bool {
    if !is_supported_content_hash(header.checksum_algo) {
        return false;
    }
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
        assert_eq!(content_hash(0, data), legacy_crc32_rotation_128(data));
        assert_eq!(content_hash(1, data), xxh3_128(data));
        assert_eq!(content_hash(2, data), shake256_128(data));
        for algo in [3u8, 9, 255] {
            assert_eq!(content_hash(algo, data), [0u8; 16], "algo {algo}");
            assert!(!is_supported_content_hash(algo));
        }
    }

    #[test]
    fn legacy_hash_matches_the_deployed_runtime_vector() {
        let hash = legacy_crc32_rotation_128(b"123456789");
        assert_eq!(&hash[..4], &0xcbf4_3926u32.to_le_bytes());
        assert_eq!(
            hash,
            [
                0x26, 0x39, 0xf4, 0xcb, 0xcb, 0x26, 0x39, 0xf4, 0xf4, 0xcb, 0x26, 0x39, 0x39, 0xf4,
                0xcb, 0x26
            ]
        );
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
    fn unknown_and_reserved_algorithms_are_refused_even_with_a_zero_hash() {
        let mut data = testkit::unsigned_segment(crate::format::SEG_TYPE_META, b"hello", 1);
        for algo in [3u8, 4, 255] {
            data[0x20] = algo;
            data[0x28..0x38].fill(0);
            let header = SegmentHeader::parse(&data).unwrap();
            assert!(!verify_content_hash(&header, b"hello"), "algo {algo}");
        }
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
