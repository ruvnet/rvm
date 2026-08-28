//! The RVF v1 wire format, restricted to what verification needs.
//!
//! Byte-compatible with `rvf-types` / `rvf-wire` / `rvf-crypto` in the
//! RuVector repository. Those crates are `std`-oriented and live in a
//! separate workspace, so the layout is restated here rather than depended
//! upon; every constant and offset below is asserted against the published
//! format in this module's tests.
//!
//! # Mnemonics versus wire bytes
//!
//! [`SEGMENT_MAGIC`] renders as the mnemonic `RVFS` only under *big-endian*
//! rendering. RVF v1 serializes every multi-byte integer little-endian, so
//! the bytes that actually appear on the wire are `53 46 56 52`. Compare
//! against [`SEGMENT_MAGIC_BYTES`], never an ASCII literal.

use crate::error::{RvfError, RvfResult};

/// Segment header magic. Mnemonic `RVFS` under big-endian rendering.
pub const SEGMENT_MAGIC: u32 = 0x5256_4653;

/// The exact four bytes a v1 segment header starts with: `53 46 56 52`.
pub const SEGMENT_MAGIC_BYTES: [u8; 4] = SEGMENT_MAGIC.to_le_bytes();

/// The only segment format version this crate accepts.
pub const SEGMENT_VERSION: u8 = 1;

/// Size of a segment header in bytes.
pub const SEGMENT_HEADER_SIZE: usize = 64;

/// Every segment starts at a 64-byte aligned boundary.
pub const SEGMENT_ALIGNMENT: usize = 64;

/// Maximum payload size the format permits for one segment (4 GiB).
///
/// This is a *format* ceiling, not a policy ceiling. Policy limits live in
/// [`crate::SizePolicy`] and are always tighter.
pub const MAX_SEGMENT_PAYLOAD: u64 = 4 * 1024 * 1024 * 1024;

/// Upper bound on segments in one container, so a malformed length field
/// cannot turn the walk into an unbounded loop.
pub const MAX_SEGMENTS: usize = 1 << 20;

/// Minimum signature-footer wire size: 2 + 2 + 4.
pub const SIGNATURE_FOOTER_MIN_SIZE: usize = 8;

/// Largest signature length any supported algorithm produces (SLH-DSA-128s).
pub const MAX_SIGNATURE_LENGTH: u16 = 7856;

/// Signature algorithm discriminator for Ed25519.
pub const SIG_ALGO_ED25519: u16 = 0;

/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LENGTH: u16 = 64;

/// Domain-separation context mixed into every segment signature.
pub const SIGN_CONTEXT: &[u8] = b"RVF-v1-segment";

/// Length of the canonical message an Ed25519 segment signature covers.
///
/// `header[0..40] || content_hash || context || segment_id || shake256_128(payload)`
pub const SIGNED_MESSAGE_LEN: usize = 40 + 16 + 14 + 8 + 16;

/// `SegmentType::Manifest`: the segment directory and root manifest.
pub const SEG_TYPE_MANIFEST: u8 = 0x05;
/// `SegmentType::Meta`: arbitrary key-value metadata, where capability
/// declarations live.
pub const SEG_TYPE_META: u8 = 0x07;
/// `SegmentType::Witness`: capability manifests, proofs, and audit trails.
pub const SEG_TYPE_WITNESS: u8 = 0x0A;
/// `SegmentType::Profile`: domain profile declarations.
pub const SEG_TYPE_PROFILE: u8 = 0x0B;
/// `SegmentType::Kernel`: an embedded kernel image.
pub const SEG_TYPE_KERNEL: u8 = 0x0E;
/// `SegmentType::Ebpf`: an embedded eBPF program.
pub const SEG_TYPE_EBPF: u8 = 0x0F;
/// `SegmentType::Wasm`: embedded WASM bytecode.
pub const SEG_TYPE_WASM: u8 = 0x10;

/// `SegmentFlags::ENCRYPTED`: the payload is encrypted.
pub const FLAG_ENCRYPTED: u16 = 0x0002;
/// `SegmentFlags::SIGNED`: a signature footer follows the payload.
pub const FLAG_SIGNED: u16 = 0x0004;
/// Mask of all flag bits the format defines; bits 12-15 are reserved.
pub const FLAG_KNOWN_MASK: u16 = 0x0FFF;

/// Segment types whose payload is code a runtime would execute.
///
/// ADR-284 §1.3 treats these as the segments that must be signed before a
/// runtime may load them.
pub const EXECUTABLE_SEGMENT_TYPES: [u8; 3] = [SEG_TYPE_KERNEL, SEG_TYPE_EBPF, SEG_TYPE_WASM];

/// True when `seg_type` names an executable segment.
#[inline]
#[must_use]
pub const fn is_executable(seg_type: u8) -> bool {
    seg_type == SEG_TYPE_KERNEL || seg_type == SEG_TYPE_EBPF || seg_type == SEG_TYPE_WASM
}

/// Which size budget a segment's bytes are charged against.
///
/// ADR-284 §1.8 requires maximum model, runtime, memory, and state sizes to
/// be enforced through signed policy. That requires a *total* classification
/// of segment types into those four budgets, which is what this enum is.
/// An unrecognized type is charged to [`SegmentClass::Memory`], the
/// fail-closed default, rather than escaping accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentClass {
    /// Executable code: kernel, eBPF, WASM.
    Runtime,
    /// Model payload: vectors, quantization codebooks, indexes, hot data.
    Model,
    /// Mutable state: journals, deltas, COW maps, refcounts, membership.
    State,
    /// Everything else: manifests, metadata, witnesses, profiles, crypto.
    Memory,
}

/// Classify a segment type into its size budget.
#[must_use]
pub const fn segment_class(seg_type: u8) -> SegmentClass {
    match seg_type {
        SEG_TYPE_KERNEL | SEG_TYPE_EBPF | SEG_TYPE_WASM => SegmentClass::Runtime,
        // Vec, Index, Quant, Hot, Sketch.
        0x01 | 0x02 | 0x06 | 0x08 | 0x09 => SegmentClass::Model,
        // Overlay, Journal, CowMap, Refcount, Membership, Delta.
        0x03 | 0x04 | 0x20..=0x23 => SegmentClass::State,
        _ => SegmentClass::Memory,
    }
}

/// The fixed 64-byte header that precedes every segment payload.
///
/// Field order and offsets match the wire format exactly; all multi-byte
/// fields are little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Magic number; must equal [`SEGMENT_MAGIC`].
    pub magic: u32,
    /// Segment format version.
    pub version: u8,
    /// Segment type discriminator.
    pub seg_type: u8,
    /// Bitfield flags.
    pub flags: u16,
    /// Monotonically increasing segment ordinal.
    pub segment_id: u64,
    /// Byte length of the payload, after the header and before any footer.
    pub payload_length: u64,
    /// Nanosecond UNIX timestamp of segment creation.
    pub timestamp_ns: u64,
    /// Hash algorithm: 0 runtime-v1 CRC rotation, 1 XXH3-128, 2 SHAKE-256.
    pub checksum_algo: u8,
    /// Compression: 0 none, 1 LZ4, 2 ZSTD, 3 custom.
    pub compression: u8,
    /// Reserved; must be zero.
    pub reserved_0: u16,
    /// Reserved; must be zero.
    pub reserved_1: u32,
    /// First 128 bits of the payload hash, per `checksum_algo`.
    pub content_hash: [u8; 16],
    /// Payload size before compression, or 0 when uncompressed.
    pub uncompressed_len: u32,
    /// Zero padding that follows the segment, to the next 64-byte boundary.
    pub alignment_pad: u32,
}

impl SegmentHeader {
    /// Parse a header from the first 64 bytes of `data`.
    ///
    /// # Errors
    ///
    /// [`RvfError::Truncated`] when `data` is shorter than a header,
    /// [`RvfError::BadMagic`] when the magic does not match, and
    /// [`RvfError::UnsupportedVersion`] for any version but 1.
    pub fn parse(data: &[u8]) -> RvfResult<Self> {
        if data.len() < SEGMENT_HEADER_SIZE {
            return Err(RvfError::Truncated);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SEGMENT_MAGIC {
            return Err(RvfError::BadMagic);
        }
        let version = data[4];
        if version != SEGMENT_VERSION {
            return Err(RvfError::UnsupportedVersion(version));
        }

        Ok(Self {
            magic,
            version,
            seg_type: data[5],
            flags: u16::from_le_bytes([data[6], data[7]]),
            segment_id: u64_at(data, 0x08),
            payload_length: u64_at(data, 0x10),
            timestamp_ns: u64_at(data, 0x18),
            checksum_algo: data[0x20],
            compression: data[0x21],
            reserved_0: u16::from_le_bytes([data[0x22], data[0x23]]),
            reserved_1: u32_at(data, 0x24),
            content_hash: {
                let mut h = [0u8; 16];
                h.copy_from_slice(&data[0x28..0x38]);
                h
            },
            uncompressed_len: u32_at(data, 0x38),
            alignment_pad: u32_at(data, 0x3C),
        })
    }

    /// Serialize this header back to its 64-byte wire representation.
    ///
    /// Signature verification covers the first 40 bytes of this encoding, so
    /// it has to reproduce the writer's byte order exactly.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SEGMENT_HEADER_SIZE] {
        let mut b = [0u8; SEGMENT_HEADER_SIZE];
        b[0x00..0x04].copy_from_slice(&self.magic.to_le_bytes());
        b[0x04] = self.version;
        b[0x05] = self.seg_type;
        b[0x06..0x08].copy_from_slice(&self.flags.to_le_bytes());
        b[0x08..0x10].copy_from_slice(&self.segment_id.to_le_bytes());
        b[0x10..0x18].copy_from_slice(&self.payload_length.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        b[0x20] = self.checksum_algo;
        b[0x21] = self.compression;
        b[0x22..0x24].copy_from_slice(&self.reserved_0.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&self.reserved_1.to_le_bytes());
        b[0x28..0x38].copy_from_slice(&self.content_hash);
        b[0x38..0x3C].copy_from_slice(&self.uncompressed_len.to_le_bytes());
        b[0x3C..0x40].copy_from_slice(&self.alignment_pad.to_le_bytes());
        b
    }

    /// Whether the header declares a signature footer.
    #[inline]
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        (self.flags & FLAG_KNOWN_MASK) & FLAG_SIGNED == FLAG_SIGNED
    }

    /// Whether the header declares an encrypted payload.
    #[inline]
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        (self.flags & FLAG_KNOWN_MASK) & FLAG_ENCRYPTED == FLAG_ENCRYPTED
    }

    /// Whether this segment's payload is code a runtime would execute.
    #[inline]
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        is_executable(self.seg_type)
    }

    /// Which size budget this segment's bytes are charged against.
    #[inline]
    #[must_use]
    pub const fn class(&self) -> SegmentClass {
        segment_class(self.seg_type)
    }
}

/// A decoded signature footer, borrowing its signature bytes.
///
/// Borrowing rather than copying matters here: the largest supported
/// algorithm produces a 7,856-byte signature, and an owned buffer that size
/// on the stack is not acceptable on the `no_std` targets this crate serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureFooter<'a> {
    /// Signature algorithm: 0 Ed25519, 1 ML-DSA-65, 2 SLH-DSA-128s.
    pub sig_algo: u16,
    /// Declared signature length in bytes.
    pub sig_length: u16,
    /// The signature bytes, exactly `sig_length` long.
    pub signature: &'a [u8],
    /// Total footer size, for backward scanning.
    pub footer_length: u32,
}

/// The footer length implied by a signature length.
///
/// Layout: 2 (`sig_algo`) + 2 (`sig_length`) + `sig_length` + 4
/// (`footer_length`).
#[inline]
#[must_use]
pub const fn compute_footer_length(sig_length: u16) -> u32 {
    2 + 2 + sig_length as u32 + 4
}

/// Decode a signature footer from the start of `data`.
///
/// # Errors
///
/// [`RvfError::Truncated`] when `data` cannot hold the declared signature,
/// and [`RvfError::MalformedFooter`] when the declared length exceeds what
/// any supported algorithm produces.
pub fn decode_signature_footer(data: &[u8]) -> RvfResult<SignatureFooter<'_>> {
    if data.len() < SIGNATURE_FOOTER_MIN_SIZE {
        return Err(RvfError::Truncated);
    }
    let sig_algo = u16::from_le_bytes([data[0], data[1]]);
    let sig_length = u16::from_le_bytes([data[2], data[3]]);
    if sig_length > MAX_SIGNATURE_LENGTH {
        return Err(RvfError::MalformedFooter);
    }
    let sig_len = sig_length as usize;
    let end = 4 + sig_len + 4;
    if data.len() < end {
        return Err(RvfError::Truncated);
    }
    let footer_length = u32_at(data, 4 + sig_len);

    Ok(SignatureFooter {
        sig_algo,
        sig_length,
        signature: &data[4..4 + sig_len],
        footer_length,
    })
}

/// Build the canonical message an Ed25519 segment signature covers.
///
/// `header[0..40] || content_hash || "RVF-v1-segment" || segment_id ||
/// shake256_128(payload)`. The length is fixed, so this allocates nothing.
#[must_use]
pub fn build_signed_message(header: &SegmentHeader, payload: &[u8]) -> [u8; SIGNED_MESSAGE_LEN] {
    let header_bytes = header.to_bytes();
    let payload_hash = crate::hash::shake256_128(payload);

    let mut msg = [0u8; SIGNED_MESSAGE_LEN];
    msg[0..40].copy_from_slice(&header_bytes[..40]);
    msg[40..56].copy_from_slice(&header.content_hash);
    msg[56..70].copy_from_slice(SIGN_CONTEXT);
    msg[70..78].copy_from_slice(&header.segment_id.to_le_bytes());
    msg[78..94].copy_from_slice(&payload_hash);
    msg
}

/// Round `n` up to the next 64-byte segment boundary.
#[inline]
#[must_use]
pub const fn align_up(n: usize) -> usize {
    n.div_ceil(SEGMENT_ALIGNMENT) * SEGMENT_ALIGNMENT
}

#[inline]
fn u64_at(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[off..off + 8]);
    u64::from_le_bytes(b)
}

#[inline]
fn u32_at(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[off..off + 4]);
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    #[test]
    fn magic_wire_bytes_are_not_the_mnemonic() {
        assert_eq!(SEGMENT_MAGIC_BYTES, [0x53, 0x46, 0x56, 0x52]);
        assert_eq!(&SEGMENT_MAGIC.to_be_bytes(), b"RVFS");
        assert_ne!(&SEGMENT_MAGIC_BYTES, b"RVFS");
    }

    #[test]
    fn header_round_trips_through_the_wire_encoding() {
        let data = testkit::unsigned_segment(SEG_TYPE_META, b"hello", 7);
        let header = SegmentHeader::parse(&data).unwrap();
        assert_eq!(header.segment_id, 7);
        assert_eq!(header.payload_length, 5);
        assert_eq!(header.checksum_algo, 1);
        assert_eq!(&header.to_bytes()[..], &data[..SEGMENT_HEADER_SIZE]);
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data[0] ^= 0xff;
        assert_eq!(SegmentHeader::parse(&data), Err(RvfError::BadMagic));
    }

    #[test]
    fn parse_rejects_an_unsupported_version() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data[4] = 2;
        assert_eq!(
            SegmentHeader::parse(&data),
            Err(RvfError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn parse_rejects_a_short_buffer() {
        assert_eq!(SegmentHeader::parse(&[0u8; 10]), Err(RvfError::Truncated));
    }

    #[test]
    fn executable_types_are_kernel_ebpf_and_wasm() {
        for t in EXECUTABLE_SEGMENT_TYPES {
            assert!(is_executable(t));
            assert_eq!(segment_class(t), SegmentClass::Runtime);
        }
        assert!(!is_executable(SEG_TYPE_META));
        assert!(!is_executable(0xEE));
    }

    #[test]
    fn context_uses_the_canonical_rvf_profile_and_witness_discriminants() {
        // These values are assigned by the RVF v1 registry in RuVector.  Keep
        // the RVM reader aligned rather than inventing context-only segment
        // types that another RVF implementation would not understand.
        assert_eq!(SEG_TYPE_WITNESS, 0x0A);
        assert_eq!(SEG_TYPE_PROFILE, 0x0B);
    }

    #[test]
    fn segment_classification_is_total() {
        // Every possible discriminator is charged to some budget; nothing
        // escapes size accounting.
        for t in 0u8..=0xFF {
            let class = segment_class(t);
            if is_executable(t) {
                assert_eq!(class, SegmentClass::Runtime);
            }
        }
        assert_eq!(segment_class(0x01), SegmentClass::Model);
        assert_eq!(segment_class(0x23), SegmentClass::State);
        assert_eq!(segment_class(SEG_TYPE_MANIFEST), SegmentClass::Memory);
        assert_eq!(segment_class(0xEE), SegmentClass::Memory);
    }

    #[test]
    fn footer_length_matches_the_published_formula() {
        assert_eq!(compute_footer_length(64), 72);
        assert_eq!(compute_footer_length(3309), 3317);
    }

    #[test]
    fn footer_decodes_from_a_signed_segment() {
        let kp = testkit::TestKeypair::deterministic(3);
        let data = testkit::signed_segment(SEG_TYPE_WASM, b"code", 1, &kp);
        let footer = decode_signature_footer(&data[SEGMENT_HEADER_SIZE + 4..]).unwrap();
        assert_eq!(footer.sig_algo, SIG_ALGO_ED25519);
        assert_eq!(footer.sig_length, ED25519_SIGNATURE_LENGTH);
        assert_eq!(footer.footer_length, 72);
        assert_eq!(footer.signature.len(), 64);
    }

    #[test]
    fn footer_decode_rejects_truncation_and_absurd_lengths() {
        assert_eq!(decode_signature_footer(&[0u8; 5]), Err(RvfError::Truncated));

        let mut buf = [0u8; 16];
        buf[2..4].copy_from_slice(&(MAX_SIGNATURE_LENGTH + 1).to_le_bytes());
        assert_eq!(
            decode_signature_footer(&buf),
            Err(RvfError::MalformedFooter)
        );

        let mut buf = [0u8; 16];
        buf[2..4].copy_from_slice(&64u16.to_le_bytes());
        assert_eq!(decode_signature_footer(&buf), Err(RvfError::Truncated));
    }

    #[test]
    fn signed_message_layout_is_fixed_length() {
        assert_eq!(SIGNED_MESSAGE_LEN, 94);
        let data = testkit::unsigned_segment(SEG_TYPE_WASM, b"code", 1);
        let header = SegmentHeader::parse(&data).unwrap();
        let msg = build_signed_message(&header, b"code");
        assert_eq!(&msg[56..70], SIGN_CONTEXT);
        assert_eq!(&msg[40..56], &header.content_hash);
    }

    #[test]
    fn align_up_rounds_to_64() {
        assert_eq!(align_up(0), 0);
        assert_eq!(align_up(1), 64);
        assert_eq!(align_up(64), 64);
        assert_eq!(align_up(65), 128);
    }

    #[test]
    fn flags_are_read_through_the_known_mask() {
        let data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        let header = SegmentHeader::parse(&data).unwrap();
        assert!(!header.is_signed());
        assert!(!header.is_encrypted());
    }
}
