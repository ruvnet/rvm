//! Synthetic RVF containers, for tests only.
//!
//! `rvm-rvf` keeps its own fixture builder private, so this is a second,
//! deliberately minimal one: enough segment framing to produce a container
//! that `rvm_rvf::verify` accepts, and nothing more. It writes only unsigned
//! segments — signature behaviour is `rvm-rvf`'s to test, and repeating it
//! here would be testing that crate through this one.
//!
//! Everything here panics on a malformed fixture rather than returning an
//! error: a broken fixture is a broken test, and surfacing it at the point of
//! construction beats letting it masquerade as a verification failure.

#![allow(clippy::missing_panics_doc)]

use alloc::vec::Vec;
use rvm_rvf::{content_hash, SegmentHeader, VerifyOptions, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC};

/// The checksum algorithm the RuVector writer defaults to (XXH3-128).
const CHECKSUM_ALGO: u8 = 1;
const SEG_TYPE_MANIFEST: u8 = 0x05;
const SEG_TYPE_META: u8 = 0x07;
const SEG_TYPE_WASM: u8 = 0x10;

/// A minimal valid WASM module: magic and version, no sections.
pub const MINIMAL_WASM: [u8; 8] = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

fn segment(seg_type: u8, payload: &[u8], segment_id: u64) -> Vec<u8> {
    let unpadded = SEGMENT_HEADER_SIZE + payload.len();
    let pad = unpadded.div_ceil(SEGMENT_HEADER_SIZE) * SEGMENT_HEADER_SIZE - unpadded;

    let mut header = [0u8; SEGMENT_HEADER_SIZE];
    header[0x00..0x04].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
    header[0x04] = 1;
    header[0x05] = seg_type;
    header[0x08..0x10].copy_from_slice(&segment_id.to_le_bytes());
    header[0x10..0x18].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    header[0x20] = CHECKSUM_ALGO;
    header[0x28..0x38].copy_from_slice(&content_hash(CHECKSUM_ALGO, payload));
    header[0x3C..0x40].copy_from_slice(&u32::try_from(pad).unwrap_or(0).to_le_bytes());

    let mut out = Vec::with_capacity(unpadded + pad);
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    out.resize(unpadded + pad, 0);
    // A header this builder wrote must be one the reader accepts; catching
    // that here keeps a framing mistake from surfacing as a mysterious
    // verification failure three modules away.
    debug_assert!(SegmentHeader::parse(&out).is_ok());
    out
}

fn meta_payload(classes: &str) -> Vec<u8> {
    let mut p = Vec::from(*b"rvf.capabilities=");
    p.extend_from_slice(classes.as_bytes());
    p
}

/// A container declaring `classes` and carrying no executable segment.
#[must_use]
pub fn container_declaring(classes: &str) -> Vec<u8> {
    let mut data = segment(SEG_TYPE_META, &meta_payload(classes), 1);
    data.extend(segment(SEG_TYPE_MANIFEST, b"root", 2));
    data
}

/// A container declaring `classes` with an unsigned WASM runtime segment.
///
/// The WASM segment is the second segment, so its payload starts at byte 192
/// as long as `classes` keeps the metadata payload under 48 bytes.
#[must_use]
pub fn container_with_wasm(classes: &str) -> Vec<u8> {
    container_with_module(classes, &MINIMAL_WASM)
}

/// A container declaring `classes` with the supplied unsigned WASM payload.
#[must_use]
pub fn container_with_module(classes: &str, module: &[u8]) -> Vec<u8> {
    let meta = meta_payload(classes);
    assert!(
        SEGMENT_HEADER_SIZE + meta.len() <= 128,
        "fixture assumes the META segment occupies two 64-byte blocks"
    );
    let mut data = segment(SEG_TYPE_META, &meta, 1);
    data.extend(segment(SEG_TYPE_WASM, module, 2));
    data.extend(segment(SEG_TYPE_MANIFEST, b"root", 3));
    data
}

/// Verification options that permit an unsigned executable.
///
/// Signing belongs to the Forge trust boundary (ADR-290); these fixtures are
/// about what the *host* does with an artifact that already verified, so they
/// take the documented development posture rather than carrying a keypair.
#[must_use]
pub fn lenient_options() -> VerifyOptions {
    VerifyOptions {
        allow_unsigned_executable: true,
        ..VerifyOptions::default()
    }
}

/// A [`crate::VerifiedPackage`] for a container declaring `classes`.
#[must_use]
pub fn package(classes: &str) -> crate::VerifiedPackage {
    let data = container_with_wasm(classes);
    let report = rvm_rvf::verify(&data, &lenient_options()).expect("fixture is a valid container");
    assert!(
        report.ok,
        "fixture failed verification: {:?}",
        report.failures()
    );
    crate::VerifiedPackage::from_report(&report).expect("fixture verified")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_rvf::{verify, walk, CapabilityClass};

    #[test]
    fn the_fixture_builder_produces_a_container_the_reader_accepts() {
        let data = container_with_wasm("memory,clock");
        let segments = walk(&data).unwrap();
        assert_eq!(segments.len(), 3);
        assert!(segments[1].is_executable());

        let report = verify(&data, &lenient_options()).unwrap();
        assert!(report.ok, "{:?}", report.failures());
        assert!(report.capabilities.is_granted(CapabilityClass::Clock));
    }

    #[test]
    fn the_wasm_payload_sits_where_the_tamper_tests_expect_it() {
        let data = container_with_wasm("memory");
        assert_eq!(&data[192..200], &MINIMAL_WASM);
    }
}
