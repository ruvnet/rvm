//! Inspection-only walk over an RVF segment stream.
//!
//! This module is the single place that turns raw bytes into a segment
//! inventory, and it is deliberately the only place that touches offsets. It
//! upholds ADR-284 §1.7: the walk reads 64-byte headers and records byte
//! ranges. It never maps, links, interprets, or executes a payload.
//! Executable payload bytes leave this module only as `&[u8]` handed to a
//! hash or a signature check.
//!
//! Layout of one segment on the wire:
//!
//! ```text
//! [ 64-byte header ][ payload_length bytes ][ signature footer? ][ zero pad ]
//! ```
//!
//! The footer is present exactly when the header's `SIGNED` flag is set, and
//! its own trailing `footer_length` field gives its size. Wire containers use
//! the header's `alignment_pad` bytes before the next segment; runtime
//! containers set that field to zero and pack the next header immediately.
//! Both shapes are RVF v1 (RuVector ADR-009).
//!
//! Forge-authored files additionally end in a fixed 4096-byte Level-0 root
//! page. It is not a segment. The page is trimmed only after its magic,
//! version, field consistency, and CRC32C have been validated.

use crate::error::{RvfError, RvfResult};
use crate::format::{
    compute_footer_length, decode_signature_footer, SegmentHeader, MAX_SEGMENTS,
    MAX_SEGMENT_PAYLOAD, SEGMENT_HEADER_SIZE,
};
use alloc::vec::Vec;
use core::ops::Range;

/// Numeric magic of the Level-0 root manifest (mnemonic `RVM0`).
pub const ROOT_MANIFEST_MAGIC: u32 = 0x5256_4D30;
/// Exact little-endian bytes at the start of a Level-0 root manifest.
pub const ROOT_MANIFEST_MAGIC_BYTES: [u8; 4] = ROOT_MANIFEST_MAGIC.to_le_bytes();
/// Fixed byte length of a Level-0 root manifest page.
pub const ROOT_MANIFEST_SIZE: usize = 4096;

const ROOT_VERSION_OFFSET: usize = 0x004;
const ROOT_L1_OFFSET: usize = 0x008;
const ROOT_L1_LENGTH: usize = 0x010;
const ROOT_SIGNATURE_ALGO: usize = 0x098;
const ROOT_SIGNATURE_LENGTH: usize = 0x09A;
const ROOT_SIGNATURE: usize = 0x09C;
const ROOT_SIGNATURE_CAPACITY: usize = 3684;
const ROOT_CHECKSUM: usize = 0xFFC;

/// Parsed, integrity-checked metadata from the trailing Level-0 root page.
///
/// The CRC32C is a corruption check, not authentication. Authority is only
/// established later by [`crate::verify`] when its signature and its pointer
/// to the signed `MANIFEST` segment are both verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootManifestPage {
    /// Byte range occupied by the page in the complete artifact.
    pub range: Range<usize>,
    /// Root-page format version.
    pub version: u16,
    /// Byte offset of the authoritative `MANIFEST` segment.
    pub l1_manifest_offset: u64,
    /// Complete encoded byte length of that `MANIFEST` segment.
    pub l1_manifest_length: u64,
    /// Root-page signature algorithm (`0` unsigned, `1` Ed25519).
    pub signature_algo: u16,
    /// Number of signature bytes present in the fixed signature buffer.
    pub signature_length: u16,
}

impl RootManifestPage {
    /// Borrow the complete 4096-byte page from the artifact it was parsed from.
    ///
    /// # Panics
    ///
    /// If `data` is not the artifact passed to [`root_manifest_page`].
    #[must_use]
    pub fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8; ROOT_MANIFEST_SIZE] {
        data[self.range.clone()]
            .try_into()
            .expect("a parsed Level-0 range is exactly 4096 bytes")
    }

    /// Borrow the declared signature bytes.
    ///
    /// # Panics
    ///
    /// If `data` is not the artifact passed to [`root_manifest_page`].
    #[must_use]
    pub fn signature<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let page = self.bytes(data);
        &page[ROOT_SIGNATURE..ROOT_SIGNATURE + self.signature_length as usize]
    }
}

/// One segment located in the byte stream. Holds ranges, never payload copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSegment {
    /// Zero-based position in the stream.
    pub index: usize,
    /// Byte offset of the segment header.
    pub offset: usize,
    /// The parsed 64-byte header.
    pub header: SegmentHeader,
    /// Byte range of the payload within the container.
    pub payload: Range<usize>,
    /// Byte range of the signature footer, when the `SIGNED` flag is set.
    pub footer: Option<Range<usize>>,
    /// Complete encoded range: header, payload, footer, and declared padding.
    pub encoded: Range<usize>,
}

/// Parse and integrity-check the optional Level-0 root page at EOF.
///
/// A page is recognized only at `data.len() - 4096`. A matching magic with a
/// bad checksum is rejected instead of silently treated as an absent page.
///
/// # Errors
///
/// [`RvfError::RootManifestChecksumMismatch`] for a corrupt page,
/// [`RvfError::UnsupportedRootManifestVersion`] for a version other than one,
/// and [`RvfError::MalformedRootManifest`] for inconsistent signature fields.
pub fn root_manifest_page(data: &[u8]) -> RvfResult<Option<RootManifestPage>> {
    if data.len() < ROOT_MANIFEST_SIZE + SEGMENT_HEADER_SIZE {
        return Ok(None);
    }
    let start = data.len() - ROOT_MANIFEST_SIZE;
    if data[start..start + 4] != ROOT_MANIFEST_MAGIC_BYTES {
        return Ok(None);
    }

    let page = &data[start..];
    let stored = u32::from_le_bytes([
        page[ROOT_CHECKSUM],
        page[ROOT_CHECKSUM + 1],
        page[ROOT_CHECKSUM + 2],
        page[ROOT_CHECKSUM + 3],
    ]);
    if stored != crc32c(&page[..ROOT_CHECKSUM]) {
        return Err(RvfError::RootManifestChecksumMismatch);
    }

    let version = u16_at(page, ROOT_VERSION_OFFSET);
    if version != 1 {
        return Err(RvfError::UnsupportedRootManifestVersion(version));
    }
    let signature_algo = u16_at(page, ROOT_SIGNATURE_ALGO);
    let signature_length = u16_at(page, ROOT_SIGNATURE_LENGTH);
    if signature_length as usize > ROOT_SIGNATURE_CAPACITY
        || (signature_algo == 0) != (signature_length == 0)
    {
        return Err(RvfError::MalformedRootManifest);
    }

    Ok(Some(RootManifestPage {
        range: start..data.len(),
        version,
        l1_manifest_offset: u64_at(page, ROOT_L1_OFFSET),
        l1_manifest_length: u64_at(page, ROOT_L1_LENGTH),
        signature_algo,
        signature_length,
    }))
}

/// CRC32C (Castagnoli) used by the fixed Level-0 page.
///
/// This small bitwise implementation keeps `rvm-rvf` `no_std` and avoids a
/// platform-specific dependency on a non-hot verification path.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

impl ParsedSegment {
    /// Whether the header declares a signature footer.
    #[inline]
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.header.is_signed()
    }

    /// Whether this segment's payload is code a runtime would execute.
    #[inline]
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.header.is_executable()
    }

    /// The payload bytes, borrowed from the container this segment came from.
    ///
    /// # Panics
    ///
    /// If `data` is not the container the segment was walked from. Every
    /// caller inside this crate passes the same slice it walked.
    #[inline]
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.payload.clone()]
    }
}

/// Walk `data` and return every segment in stream order.
///
/// The rejection set mirrors the RuVector reader exactly: bad magic,
/// truncated streams, payload lengths past the end, inconsistent footers, and
/// a `SIGNED` flag with no signature behind it.
///
/// # Errors
///
/// One of the [`RvfError`] variants describing which structural rule the
/// container broke.
pub fn walk(data: &[u8]) -> RvfResult<Vec<ParsedSegment>> {
    let page = root_manifest_page(data)?;
    if let Some(root) = page {
        // `rvf-wire` places the page inside the final MANIFEST payload, while
        // RVForge appends the same page after the aligned segment stream. Try
        // the embedded form first; if it is not a complete segment stream,
        // trim the independently checksummed standalone page and retry.
        if let Ok(segments) = walk_segments(data) {
            return Ok(segments);
        }
        return walk_segments(&data[..root.range.start]);
    }
    walk_segments(data)
}

fn walk_segments(body: &[u8]) -> RvfResult<Vec<ParsedSegment>> {
    if body.len() < SEGMENT_HEADER_SIZE {
        return Err(RvfError::Truncated);
    }

    let mut segments: Vec<ParsedSegment> = Vec::new();
    let mut offset = 0usize;

    while offset < body.len() {
        let remaining = body.len() - offset;

        // A short, all-zero tail is alignment padding, not a truncated segment.
        if remaining < SEGMENT_HEADER_SIZE {
            if body[offset..].iter().all(|&b| b == 0) {
                break;
            }
            return Err(RvfError::TrailingBytes);
        }

        if segments.len() >= MAX_SEGMENTS {
            return Err(RvfError::TooManySegments);
        }

        let header = SegmentHeader::parse(&body[offset..])?;

        if header.payload_length > MAX_SEGMENT_PAYLOAD {
            return Err(RvfError::PayloadTooLarge);
        }

        let payload_start = offset + SEGMENT_HEADER_SIZE;
        let payload_end = usize::try_from(header.payload_length)
            .ok()
            .and_then(|len| payload_start.checked_add(len))
            .ok_or(RvfError::PayloadOutOfBounds)?;
        if payload_end > body.len() {
            return Err(RvfError::PayloadOutOfBounds);
        }

        let mut end = payload_end;
        let mut footer = None;
        if header.is_signed() {
            let decoded = decode_signature_footer(&body[payload_end..])?;
            // A segment's zero padding decodes as a structurally valid but
            // empty footer. Accepting that would let any segment claim SIGNED
            // by setting one flag bit and changing nothing else, so require
            // the footer to actually carry a signature and to be internally
            // consistent about its own length.
            if decoded.sig_length == 0 {
                return Err(RvfError::SignedFlagWithoutFooter);
            }
            if decoded.footer_length != compute_footer_length(decoded.sig_length) {
                return Err(RvfError::MalformedFooter);
            }

            let footer_len = decoded.footer_length as usize;
            let footer_end = payload_end
                .checked_add(footer_len)
                .filter(|e| *e <= body.len())
                .ok_or(RvfError::MalformedFooter)?;
            footer = Some(payload_end..footer_end);
            end = footer_end;
        }

        let padding =
            usize::try_from(header.alignment_pad).map_err(|_| RvfError::InvalidAlignmentPadding)?;
        if padding >= crate::format::SEGMENT_ALIGNMENT {
            return Err(RvfError::InvalidAlignmentPadding);
        }
        let next = end
            .checked_add(padding)
            .filter(|next| *next <= body.len())
            .ok_or(RvfError::Truncated)?;
        if next <= offset {
            return Err(RvfError::NoForwardProgress);
        }
        if body[end..next].iter().any(|&byte| byte != 0) {
            return Err(RvfError::NonZeroAlignmentPadding);
        }

        segments.push(ParsedSegment {
            index: segments.len(),
            offset,
            header,
            payload: payload_start..payload_end,
            footer,
            encoded: offset..next,
        });

        offset = next;
    }

    if segments.is_empty() {
        return Err(RvfError::NoSegments);
    }
    Ok(segments)
}

/// The root manifest segment, when the container has one.
///
/// The *last* manifest in the stream is the root: later manifests supersede
/// earlier ones, matching the RuVector reader.
#[must_use]
pub fn root_manifest(segments: &[ParsedSegment]) -> Option<&ParsedSegment> {
    segments
        .iter()
        .rev()
        .find(|s| s.header.seg_type == crate::format::SEG_TYPE_MANIFEST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{SEGMENT_ALIGNMENT, SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
    use crate::testkit;
    use alloc::vec;

    fn packed_segment(seg_type: u8, payload: &[u8], segment_id: u64) -> Vec<u8> {
        let mut segment = testkit::unsigned_segment(seg_type, payload, segment_id);
        segment[0x3c..0x40].copy_from_slice(&0u32.to_le_bytes());
        segment.truncate(SEGMENT_HEADER_SIZE + payload.len());
        segment
    }

    fn root_page(l1_offset: u64, l1_length: u64) -> [u8; ROOT_MANIFEST_SIZE] {
        let mut page = [0u8; ROOT_MANIFEST_SIZE];
        page[..4].copy_from_slice(&ROOT_MANIFEST_MAGIC_BYTES);
        page[ROOT_VERSION_OFFSET..ROOT_VERSION_OFFSET + 2].copy_from_slice(&1u16.to_le_bytes());
        page[ROOT_L1_OFFSET..ROOT_L1_OFFSET + 8].copy_from_slice(&l1_offset.to_le_bytes());
        page[ROOT_L1_LENGTH..ROOT_L1_LENGTH + 8].copy_from_slice(&l1_length.to_le_bytes());
        let checksum = crc32c(&page[..ROOT_CHECKSUM]);
        page[ROOT_CHECKSUM..].copy_from_slice(&checksum.to_le_bytes());
        page
    }

    #[test]
    fn walks_a_two_segment_stream() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"first", 1);
        data.extend(testkit::unsigned_segment(
            SEG_TYPE_META,
            b"second payload",
            2,
        ));

        let segs = walk(&data).unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].header.segment_id, 1);
        assert_eq!(segs[0].payload(&data), b"first");
        assert_eq!(segs[1].header.segment_id, 2);
        assert_eq!(segs[1].payload(&data), b"second payload");
        assert_eq!(segs[1].offset, SEGMENT_ALIGNMENT * 2);
    }

    #[test]
    fn walks_runtime_segments_packed_without_alignment() {
        let first = packed_segment(SEG_TYPE_META, b"first", 1);
        let second_offset = first.len();
        let mut data = first;
        data.extend(packed_segment(SEG_TYPE_MANIFEST, b"runtime root", 2));

        let segs = walk(&data).unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].offset, 0);
        assert_eq!(segs[1].offset, second_offset);
        assert_ne!(second_offset % SEGMENT_ALIGNMENT, 0);
        assert_eq!(segs[1].payload(&data), b"runtime root");
    }

    #[test]
    fn rejects_a_stream_shorter_than_a_header() {
        assert_eq!(walk(&[0u8; 10]), Err(RvfError::Truncated));
    }

    #[test]
    fn rejects_a_bad_magic() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data[0] ^= 0xff;
        assert_eq!(walk(&data), Err(RvfError::BadMagic));
    }

    #[test]
    fn rejects_a_payload_length_past_the_end() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        // payload_length lives at header offset 0x10.
        data[0x10..0x18].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(walk(&data), Err(RvfError::PayloadOutOfBounds));
    }

    #[test]
    fn rejects_a_payload_length_over_the_format_maximum() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data[0x10..0x18].copy_from_slice(&(MAX_SEGMENT_PAYLOAD + 1).to_le_bytes());
        assert_eq!(walk(&data), Err(RvfError::PayloadTooLarge));
    }

    #[test]
    fn rejects_signed_flag_without_a_footer() {
        let data = testkit::signed_flag_without_footer(SEG_TYPE_WASM, b"code", 1);
        assert_eq!(walk(&data), Err(RvfError::SignedFlagWithoutFooter));
    }

    #[test]
    fn rejects_a_footer_whose_declared_length_is_inconsistent() {
        let kp = testkit::TestKeypair::deterministic(3);
        let mut data = testkit::signed_segment(SEG_TYPE_WASM, b"code", 1, &kp);
        // The footer's trailing footer_length is the last 4 bytes before pad.
        let footer_start = SEGMENT_HEADER_SIZE + 4;
        let len_at = footer_start + 4 + 64;
        data[len_at..len_at + 4].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(walk(&data), Err(RvfError::MalformedFooter));
    }

    #[test]
    fn accepts_a_well_formed_signed_segment() {
        let kp = testkit::TestKeypair::deterministic(3);
        let data = testkit::signed_segment(SEG_TYPE_WASM, b"code", 1, &kp);
        let segs = walk(&data).unwrap();
        assert_eq!(segs.len(), 1);
        assert!(segs[0].is_signed());
        assert!(segs[0].is_executable());
        assert_eq!(segs[0].footer.clone().unwrap().len(), 72);
    }

    #[test]
    fn rejects_non_zero_trailing_bytes() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data.extend_from_slice(b"junk");
        assert_eq!(walk(&data), Err(RvfError::TrailingBytes));
    }

    #[test]
    fn accepts_zero_padding_after_the_last_segment() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data.extend_from_slice(&[0u8; 8]);
        assert_eq!(walk(&data).unwrap().len(), 1);
    }

    #[test]
    fn rejects_non_zero_declared_padding() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        let last = data.len() - 1;
        data[last] = 1;
        assert_eq!(walk(&data), Err(RvfError::NonZeroAlignmentPadding));
    }

    #[test]
    fn trims_an_integrity_checked_root_page() {
        let body = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1);
        let mut data = body.clone();
        data.extend_from_slice(&root_page(0, body.len() as u64));

        let page = root_manifest_page(&data).unwrap().unwrap();
        assert_eq!(page.range, body.len()..data.len());
        assert_eq!(page.l1_manifest_offset, 0);
        assert_eq!(page.l1_manifest_length, body.len() as u64);
        assert_eq!(walk(&data).unwrap().len(), 1);
    }

    #[test]
    fn walks_a_wire_root_page_embedded_in_the_manifest_payload() {
        let mut payload = vec![0x11; SEGMENT_ALIGNMENT];
        payload.extend_from_slice(&root_page(
            SEGMENT_HEADER_SIZE as u64,
            SEGMENT_ALIGNMENT as u64,
        ));
        let data = testkit::unsigned_segment(SEG_TYPE_MANIFEST, &payload, 1);

        let page = root_manifest_page(&data).unwrap().unwrap();
        let segments = walk(&data).unwrap();
        assert_eq!(segments.len(), 1);
        assert!(segments[0].payload.contains(&page.range.start));
        assert_eq!(segments[0].payload.end, page.range.end);
    }

    #[test]
    fn rejects_a_root_page_with_a_bad_crc32c() {
        let body = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1);
        let mut data = body.clone();
        data.extend_from_slice(&root_page(0, body.len() as u64));
        data[body.len() + 8] ^= 1;

        assert_eq!(
            root_manifest_page(&data),
            Err(RvfError::RootManifestChecksumMismatch)
        );
        assert_eq!(walk(&data), Err(RvfError::RootManifestChecksumMismatch));
    }

    #[test]
    fn crc32c_matches_the_canonical_empty_root_vector() {
        let page = root_page(0, 0);
        assert_eq!(&page[ROOT_CHECKSUM..], &[0xff, 0xdd, 0x18, 0x14]);
    }

    #[test]
    fn root_manifest_is_the_last_manifest_in_the_stream() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"first", 1);
        data.extend(testkit::unsigned_segment(SEG_TYPE_META, b"m", 2));
        data.extend(testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 3));

        let segs = walk(&data).unwrap();
        assert_eq!(root_manifest(&segs).unwrap().header.segment_id, 3);
    }

    #[test]
    fn root_manifest_is_absent_when_no_manifest_segment_exists() {
        let data = testkit::unsigned_segment(SEG_TYPE_META, b"m", 1);
        let segs = walk(&data).unwrap();
        assert!(root_manifest(&segs).is_none());
    }
}
