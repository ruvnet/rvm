//! Synthetic RVF construction, for tests only.
//!
//! This crate never writes RVF files in production — it consumes them — so
//! nothing here is on the loading path. It exists so a test can build a
//! container byte by byte and then tamper with it, which is the only way to
//! show that verification actually refuses a tampered artifact rather than
//! merely accepting an intact one.
//!
//! The layout written here is the one [`crate::container`] reads:
//!
//! ```text
//! [ 64-byte header ][ payload ][ signature footer, if SIGNED ][ zero pad to 64 ]
//! ```

use crate::format::{
    compute_footer_length, FLAG_SIGNED, SEGMENT_ALIGNMENT, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC,
    SEGMENT_VERSION, SIG_ALGO_ED25519,
};
use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey};

/// The checksum algorithm the RuVector writer defaults to (XXH3-128).
const CHECKSUM_ALGO: u8 = 1;

/// An Ed25519 keypair derived deterministically from a seed, so a test that
/// signs a fixture produces the same bytes on every run.
pub struct TestKeypair {
    /// The signing key.
    pub signing: SigningKey,
    /// The 32-byte public key, as `VerifyOptions::trusted_keys` takes it.
    pub public: [u8; 32],
}

impl TestKeypair {
    /// Derive a keypair from `seed`. The same seed always yields the same key.
    #[must_use]
    pub fn deterministic(seed: u8) -> Self {
        let secret = crate::hash::sha256(&[seed; 32]);
        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key().to_bytes();
        Self { signing, public }
    }
}

fn header_bytes(
    seg_type: u8,
    payload: &[u8],
    flags: u16,
    segment_id: u64,
    alignment_pad: u32,
) -> [u8; SEGMENT_HEADER_SIZE] {
    let content_hash = crate::hash::content_hash(CHECKSUM_ALGO, payload);

    let mut b = [0u8; SEGMENT_HEADER_SIZE];
    b[0x00..0x04].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
    b[0x04] = SEGMENT_VERSION;
    b[0x05] = seg_type;
    b[0x06..0x08].copy_from_slice(&flags.to_le_bytes());
    b[0x08..0x10].copy_from_slice(&segment_id.to_le_bytes());
    b[0x10..0x18].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    // timestamp_ns stays zero: fixtures must be byte-reproducible.
    b[0x20] = CHECKSUM_ALGO;
    b[0x28..0x38].copy_from_slice(&content_hash);
    b[0x3C..0x40].copy_from_slice(&alignment_pad.to_le_bytes());
    b
}

fn pad_to_alignment(buf: &mut Vec<u8>) {
    let padded = buf.len().div_ceil(SEGMENT_ALIGNMENT) * SEGMENT_ALIGNMENT;
    buf.resize(padded, 0);
}

/// Build an unsigned segment.
#[must_use]
pub fn unsigned_segment(seg_type: u8, payload: &[u8], segment_id: u64) -> Vec<u8> {
    let unpadded = SEGMENT_HEADER_SIZE + payload.len();
    let pad = unpadded.div_ceil(SEGMENT_ALIGNMENT) * SEGMENT_ALIGNMENT - unpadded;

    let mut out = Vec::new();
    out.extend_from_slice(&header_bytes(seg_type, payload, 0, segment_id, pad as u32));
    out.extend_from_slice(payload);
    pad_to_alignment(&mut out);
    out
}

/// Build a segment carrying a real Ed25519 signature footer over `payload`.
///
/// # Panics
///
/// Panics only if the internally constructed fixed-size RVF header fails its
/// own parser, which indicates a testkit implementation defect.
#[must_use]
pub fn signed_segment(
    seg_type: u8,
    payload: &[u8],
    segment_id: u64,
    keypair: &TestKeypair,
) -> Vec<u8> {
    let footer_len = compute_footer_length(64) as usize;
    let unpadded = SEGMENT_HEADER_SIZE + payload.len() + footer_len;
    let pad = unpadded.div_ceil(SEGMENT_ALIGNMENT) * SEGMENT_ALIGNMENT - unpadded;

    let head = header_bytes(seg_type, payload, FLAG_SIGNED, segment_id, pad as u32);
    let header = crate::format::SegmentHeader::parse(&head).expect("testkit built a valid header");
    let msg = crate::format::build_signed_message(&header, payload);
    let signature = keypair.signing.sign(&msg).to_bytes();

    let mut out = Vec::new();
    out.extend_from_slice(&head);
    out.extend_from_slice(payload);
    out.extend_from_slice(&SIG_ALGO_ED25519.to_le_bytes());
    out.extend_from_slice(&64u16.to_le_bytes());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&compute_footer_length(64).to_le_bytes());
    pad_to_alignment(&mut out);
    out
}

/// Build a segment that sets `SIGNED` but writes no footer, so the trailing
/// zero padding is all a reader finds where a signature should be.
#[must_use]
pub fn signed_flag_without_footer(seg_type: u8, payload: &[u8], segment_id: u64) -> Vec<u8> {
    let unpadded = SEGMENT_HEADER_SIZE + payload.len();
    let pad = unpadded.div_ceil(SEGMENT_ALIGNMENT) * SEGMENT_ALIGNMENT - unpadded;

    let mut out = Vec::new();
    out.extend_from_slice(&header_bytes(
        seg_type,
        payload,
        FLAG_SIGNED,
        segment_id,
        pad as u32,
    ));
    out.extend_from_slice(payload);
    pad_to_alignment(&mut out);
    // Guarantee the padding is long enough to decode as an (empty) footer.
    if out.len() - (SEGMENT_HEADER_SIZE + payload.len()) < 8 {
        out.resize(out.len() + SEGMENT_ALIGNMENT, 0);
    }
    out
}

/// A minimal but complete container: a `META` segment carrying the given
/// capability declaration, then a `MANIFEST` segment as the root.
#[must_use]
pub fn minimal_container(capabilities: &str) -> Vec<u8> {
    let mut meta = Vec::new();
    meta.extend_from_slice(crate::capability::CAPABILITY_DECLARATION_KEY.as_bytes());
    meta.push(b'=');
    meta.extend_from_slice(capabilities.as_bytes());

    let mut out = unsigned_segment(crate::format::SEG_TYPE_META, &meta, 1);
    out.extend(unsigned_segment(
        crate::format::SEG_TYPE_MANIFEST,
        b"root",
        2,
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{SegmentHeader, SEG_TYPE_META, SEG_TYPE_WASM};

    #[test]
    fn unsigned_segment_is_aligned_and_parses() {
        let data = unsigned_segment(SEG_TYPE_META, b"hello", 3);
        assert_eq!(data.len() % SEGMENT_ALIGNMENT, 0);
        let header = SegmentHeader::parse(&data).unwrap();
        assert_eq!(header.segment_id, 3);
        assert!(!header.is_signed());
    }

    #[test]
    fn signed_segment_is_aligned_and_carries_a_real_signature() {
        let kp = TestKeypair::deterministic(1);
        let data = signed_segment(SEG_TYPE_WASM, b"\0asm\x01\0\0\0", 4, &kp);
        assert_eq!(data.len() % SEGMENT_ALIGNMENT, 0);
        let header = SegmentHeader::parse(&data).unwrap();
        assert!(header.is_signed());
    }

    #[test]
    fn fixtures_are_byte_reproducible() {
        let kp = TestKeypair::deterministic(2);
        assert_eq!(
            signed_segment(SEG_TYPE_WASM, b"code", 1, &kp),
            signed_segment(SEG_TYPE_WASM, b"code", 1, &kp)
        );
        assert_eq!(minimal_container("network"), minimal_container("network"));
    }

    #[test]
    fn the_same_seed_yields_the_same_key() {
        assert_eq!(
            TestKeypair::deterministic(9).public,
            TestKeypair::deterministic(9).public
        );
        assert_ne!(
            TestKeypair::deterministic(9).public,
            TestKeypair::deterministic(10).public
        );
    }
}
