//! Cross-repository wire compatibility.
//!
//! [`crate::format`] restates the RVF v1 layout rather than depending on
//! RuVector's `rvf-types` / `rvf-wire` / `rvf-crypto`, which are `std`-oriented
//! and live in a separate workspace. A restatement is only worth anything if it
//! is checked against the thing it restates, so the fixture below was produced
//! by *those crates* — `rvf_wire::write_segment` for the headers and content
//! hashes, `rvf_crypto::sign_segment` for the Ed25519 footer — and is verified
//! here by this crate's own reader.
//!
//! The fixture is three segments, 448 bytes:
//!
//! ```text
//! META      id 1, "rvf.capabilities=network,model,clock"   0..128
//! WASM      id 2, signed, "\0asm\x01\0\0\0"              128..320
//! MANIFEST  id 3, "root"                                 320..448
//! ```
//!
//! Regenerating it requires a program linked against the RuVector wire crates;
//! the recipe is in this module's doc comment above and the signing key is
//! `SigningKey::from_bytes(&sha256(&[11u8; 32]))`.

use crate::capability::CapabilityClass;
use crate::detail::DetailCode;
use crate::format::{
    build_signed_message, compute_footer_length, SegmentHeader, FLAG_SIGNED, SEGMENT_ALIGNMENT,
    SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION, SEG_TYPE_MANIFEST, SEG_TYPE_META,
    SEG_TYPE_WASM, SIG_ALGO_ED25519,
};
use crate::verify::{verify, CheckKind, Outcome, VerifyOptions};
use alloc::vec;
use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey};

/// A three-segment container written by `rvf-wire` and signed by `rvf-crypto`.
const FIXTURE_HEX: &str = concat!(
    "53465652010700000100000000000000240000000000000000000000000000000100000000000000",
    "505ac6eb33f8a5d1d81fecdac5217ec1000000001c0000007276662e6361706162696c6974696573",
    "3d6e6574776f726b2c6d6f64656c2c636c6f636b0000000000000000000000000000000000000000",
    "00000000000000005346565201100400020000000000000008000000000000000000000000000000",
    "01000000000000005889e0505be391fdbc0beb8ac177778400000000300000000061736d01000000",
    "0000400074169aa23d25d565b35e0cc03976312fa6a1fdb64d322a305c2094a81257ce86db95833a",
    "ae8addf0c56b1802f92e6728c2b0d9b812e5e0d586265a775f3d500c480000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "53465652010500000300000000000000040000000000000000000000000000000100000000000000",
    "c0efad1d59f253af6ba9f6840f32615b000000003c000000726f6f74000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000",
);

/// The public key `rvf-crypto` signed the WASM segment with.
const FIXTURE_PUBKEY_HEX: &str = "a10e23fcb5773fbf890582ee6253942263246aa90c4699984982b3978166343a";

/// The first complete MANIFEST segment of RuVector's checked-in
/// `examples/rvf/output/basic_store.rvf`, emitted by `rvf-runtime`.
///
/// This is intentionally 162 bytes rather than alignment-padded: it pins the
/// deployed packed layout and algorithm-zero CRC-rotation hash. SHA-256 of
/// these bytes is `cd211fdf...d41762b9`.
const RUNTIME_MANIFEST_FIXTURE_HEX: &str = concat!(
    "5346565201050000010000000000000062000000000000000000000000000000",
    "00000000000000007f783f4c4c7f783f3f4c7f78783f4c7f0000000000000000",
    "0000000080010000000000000000000000000000000000000000494449468eef",
    "b3739b419670bdb5ed6213734b6a000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000",
);

const RUNTIME_MANIFEST_SHA256_HEX: &str =
    "cd211fdfe3679718956e9d85a090003eb0e08dc8acbd6d1dd53c0b72d41762b9";

/// SHA-256 of the 4480-byte artifact produced by the canonical
/// `rvf_forge_core::author::ContainerBuilder` with one signed WASM segment,
/// file id `42` repeated, signing secret `17` repeated, and default SHAKE-256.
const FORGE_AUTHORED_SHA256_HEX: &str =
    "5307c48566750c3fbfcdc2113dd3cd24ec7129b7ecdacb93bfeb0dda6fd1f4f1";
const FORGE_AUTHORED_PUBLIC_KEY_HEX: &str =
    "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string has an odd length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

fn fixture() -> Vec<u8> {
    unhex(FIXTURE_HEX)
}

fn fixture_pubkey() -> [u8; 32] {
    <[u8; 32]>::try_from(unhex(FIXTURE_PUBKEY_HEX).as_slice()).expect("32-byte key")
}

fn forge_segment(seg_type: u8, payload: &[u8], segment_id: u64, key: &SigningKey) -> Vec<u8> {
    let footer_len = compute_footer_length(64) as usize;
    let unpadded = SEGMENT_HEADER_SIZE + payload.len() + footer_len;
    let padding = unpadded.div_ceil(SEGMENT_ALIGNMENT) * SEGMENT_ALIGNMENT - unpadded;

    let mut header_bytes = [0u8; SEGMENT_HEADER_SIZE];
    header_bytes[..4].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
    header_bytes[4] = SEGMENT_VERSION;
    header_bytes[5] = seg_type;
    header_bytes[6..8].copy_from_slice(&FLAG_SIGNED.to_le_bytes());
    header_bytes[8..16].copy_from_slice(&segment_id.to_le_bytes());
    header_bytes[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    header_bytes[0x20] = 2;
    header_bytes[0x28..0x38].copy_from_slice(&crate::hash::shake256_128(payload));
    header_bytes[0x3c..0x40].copy_from_slice(&(padding as u32).to_le_bytes());

    let header = SegmentHeader::parse(&header_bytes).expect("canonical header");
    let signature = key.sign(&build_signed_message(&header, payload)).to_bytes();
    let mut out = Vec::with_capacity(unpadded + padding);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(payload);
    out.extend_from_slice(&SIG_ALGO_ED25519.to_le_bytes());
    out.extend_from_slice(&64u16.to_le_bytes());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&compute_footer_length(64).to_le_bytes());
    out.resize(unpadded + padding, 0);
    out
}

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

fn forge_root_page(
    manifest_offset: u64,
    manifest_length: u64,
    key: &SigningKey,
) -> [u8; crate::ROOT_MANIFEST_SIZE] {
    const SIGNATURE: usize = 0x09c;
    const CHECKSUM: usize = 0x0ffc;
    let mut page = [0u8; crate::ROOT_MANIFEST_SIZE];
    page[..4].copy_from_slice(&crate::ROOT_MANIFEST_MAGIC_BYTES);
    page[4..6].copy_from_slice(&1u16.to_le_bytes());
    page[8..16].copy_from_slice(&manifest_offset.to_le_bytes());
    page[16..24].copy_from_slice(&manifest_length.to_le_bytes());
    page[0x22] = 1;
    page[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
    page[0x098..0x09a].copy_from_slice(&1u16.to_le_bytes());
    page[0x09a..0x09c].copy_from_slice(&64u16.to_le_bytes());
    page[0x0f00..0x0f10].fill(0x42);

    let mut signable = page;
    signable[SIGNATURE..SIGNATURE + 64].fill(0);
    signable[CHECKSUM..].fill(0);
    let signature = key.sign(&signable).to_bytes();
    page[SIGNATURE..SIGNATURE + 64].copy_from_slice(&signature);
    let checksum = crc32c(&page[..CHECKSUM]);
    page[CHECKSUM..].copy_from_slice(&checksum.to_le_bytes());
    page
}

fn forge_authored_fixture() -> (Vec<u8>, [u8; 32]) {
    let key = SigningKey::from_bytes(&[0x17; 32]);
    let public = key.verifying_key().to_bytes();
    let mut body = forge_segment(SEG_TYPE_WASM, b"\0asm\x01\0\0\0", 1, &key);
    let manifest_offset = body.len();
    let manifest = forge_segment(SEG_TYPE_MANIFEST, b"root", 2, &key);
    let manifest_length = manifest.len();
    body.extend_from_slice(&manifest);
    body.extend_from_slice(&forge_root_page(
        manifest_offset as u64,
        manifest_length as u64,
        &key,
    ));
    (body, public)
}

#[test]
fn the_ruvector_writers_segment_layout_walks() {
    let data = fixture();
    assert_eq!(data.len(), 448);

    let segs = crate::container::walk(&data).unwrap();
    assert_eq!(segs.len(), 3);

    assert_eq!(segs[0].header.seg_type, SEG_TYPE_META);
    assert_eq!(segs[0].header.segment_id, 1);
    assert_eq!(segs[0].offset, 0);
    assert_eq!(
        segs[0].payload(&data),
        b"rvf.capabilities=network,model,clock"
    );

    assert_eq!(segs[1].header.seg_type, SEG_TYPE_WASM);
    assert_eq!(segs[1].offset, 128);
    assert!(segs[1].is_signed());
    assert!(segs[1].is_executable());
    assert_eq!(segs[1].payload(&data), b"\0asm\x01\0\0\0");
    assert_eq!(segs[1].footer.clone().unwrap().len(), 72);

    assert_eq!(segs[2].header.seg_type, SEG_TYPE_MANIFEST);
    assert_eq!(segs[2].offset, 320);
}

#[test]
fn the_ruvector_writers_content_hashes_verify() {
    let data = fixture();
    let segs = crate::container::walk(&data).unwrap();
    // `rvf_wire::write_segment` defaults to XXH3-128, algorithm 1.
    for seg in &segs {
        assert_eq!(seg.header.checksum_algo, 1);
        assert!(
            crate::hash::verify_content_hash(&seg.header, seg.payload(&data)),
            "segment {} content hash did not verify",
            seg.header.segment_id
        );
    }
}

#[test]
fn the_rvf_crypto_signature_verifies_against_its_key() {
    let data = fixture();
    let opts = VerifyOptions::with_trusted_keys(vec![fixture_pubkey()]);
    let report = verify(&data, &opts).unwrap();

    assert!(report.ok, "{:?}", report.failures());
    let sig = report
        .records
        .iter()
        .find(|r| r.check == CheckKind::Signature)
        .expect("no signature record");
    assert_eq!(sig.outcome, Outcome::Pass);
    assert_eq!(sig.detail, DetailCode::SignatureVerifies);
}

#[test]
fn the_signature_is_rejected_under_a_stranger_key() {
    let data = fixture();
    let stranger = crate::testkit::TestKeypair::deterministic(200);
    let opts = VerifyOptions::with_trusted_keys(vec![stranger.public]);
    let report = verify(&data, &opts).unwrap();

    assert!(!report.ok);
    assert_eq!(
        report
            .first_failure(CheckKind::Signature)
            .expect("no signature failure")
            .detail,
        DetailCode::SignatureRejected
    );
}

#[test]
fn tampering_with_the_fixture_breaks_both_hash_and_signature() {
    let mut data = fixture();
    // The WASM payload begins one 64-byte header past the segment start.
    data[128 + 64] ^= 0xff;

    let opts = VerifyOptions::with_trusted_keys(vec![fixture_pubkey()]);
    let report = verify(&data, &opts).unwrap();

    assert!(!report.ok);
    assert!(report.first_failure(CheckKind::ContentHash).is_some());
    assert!(report.first_failure(CheckKind::Signature).is_some());
}

#[test]
fn declared_capabilities_read_the_same_from_the_ruvector_writers_metadata() {
    let data = fixture();
    let opts = VerifyOptions::with_trusted_keys(vec![fixture_pubkey()]);
    let report = verify(&data, &opts).unwrap();

    assert!(report.capabilities.is_granted(CapabilityClass::Network));
    assert!(report.capabilities.is_granted(CapabilityClass::Model));
    assert!(report.capabilities.is_granted(CapabilityClass::Clock));
    assert_eq!(report.capabilities.granted().len(), 3);
    assert_eq!(report.capabilities.denied().len(), 12);
}

#[test]
fn this_crates_testkit_derives_the_same_key_as_rvf_forge_cores() {
    // Both derive from SHA-256 of a 32-byte seed fill, so a fixture signed by
    // one is verifiable by the other. If this drifts, every signed fixture in
    // the suite stops meaning what it claims to mean.
    assert_eq!(
        crate::testkit::TestKeypair::deterministic(11).public,
        fixture_pubkey()
    );
}

#[test]
fn this_crates_testkit_reproduces_the_ruvector_writers_bytes() {
    // The strongest form of the compatibility claim: given the same inputs,
    // this crate's fixture builder emits the same bytes the RuVector writer
    // did, header fields and signature footer included.
    let kp = crate::testkit::TestKeypair::deterministic(11);
    let mut built =
        crate::testkit::unsigned_segment(SEG_TYPE_META, b"rvf.capabilities=network,model,clock", 1);
    built.extend(crate::testkit::signed_segment(
        SEG_TYPE_WASM,
        b"\0asm\x01\0\0\0",
        2,
        &kp,
    ));
    built.extend(crate::testkit::unsigned_segment(
        SEG_TYPE_MANIFEST,
        b"root",
        3,
    ));

    assert_eq!(built, fixture());
}

#[test]
fn canonical_runtime_manifest_uses_packed_layout_and_legacy_algo_zero() {
    let data = unhex(RUNTIME_MANIFEST_FIXTURE_HEX);
    assert_eq!(data.len(), 162);
    assert_eq!(
        crate::sha256(&data).as_slice(),
        unhex(RUNTIME_MANIFEST_SHA256_HEX).as_slice()
    );

    let segments = crate::walk(&data).unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].header.seg_type, SEG_TYPE_MANIFEST);
    assert_eq!(segments[0].header.checksum_algo, 0);
    assert_eq!(segments[0].header.alignment_pad, 0);
    assert_eq!(segments[0].encoded, 0..162);
    assert!(crate::verify_content_hash(
        &segments[0].header,
        segments[0].payload(&data)
    ));

    let report = verify(&data, &VerifyOptions::default()).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
}

#[test]
fn current_rvforge_container_matches_its_canonical_golden_identity() {
    let (data, public) = forge_authored_fixture();
    assert_eq!(data.len(), 4480);
    assert_eq!(public.as_slice(), unhex(FORGE_AUTHORED_PUBLIC_KEY_HEX));
    assert_eq!(
        crate::sha256(&data).as_slice(),
        unhex(FORGE_AUTHORED_SHA256_HEX).as_slice()
    );

    let segments = crate::walk(&data).unwrap();
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].offset, 0);
    assert_eq!(segments[1].offset, 192);
    assert_eq!(segments[1].header.seg_type, SEG_TYPE_MANIFEST);
    let page = crate::root_manifest_page(&data).unwrap().unwrap();
    assert_eq!(page.range, 384..4480);
    assert_eq!(page.l1_manifest_offset, 192);
    assert_eq!(page.l1_manifest_length, 192);

    let report = verify(&data, &VerifyOptions::with_trusted_keys(vec![public])).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    assert_eq!(report.trusted_root_signer(), Some(public));
    for check in [
        CheckKind::RootPageIntegrity,
        CheckKind::RootPageBinding,
        CheckKind::RootPageSignature,
        CheckKind::RootSignerBinding,
    ] {
        assert_eq!(
            report
                .records()
                .iter()
                .find(|record| record.check == check)
                .expect("root-page verification record")
                .outcome,
            Outcome::Pass
        );
    }
}

#[test]
fn canonical_wire_manifest_can_embed_the_level_zero_page() {
    let mut page = [0u8; crate::ROOT_MANIFEST_SIZE];
    page[..4].copy_from_slice(&crate::ROOT_MANIFEST_MAGIC_BYTES);
    page[4..6].copy_from_slice(&1u16.to_le_bytes());
    page[8..16].copy_from_slice(&(SEGMENT_HEADER_SIZE as u64).to_le_bytes());
    page[16..24].copy_from_slice(&(SEGMENT_ALIGNMENT as u64).to_le_bytes());
    let checksum = crc32c(&page[..0x0ffc]);
    page[0x0ffc..].copy_from_slice(&checksum.to_le_bytes());

    let mut payload = vec![0x11; SEGMENT_ALIGNMENT];
    payload.extend_from_slice(&page);
    let data = crate::testkit::unsigned_segment(SEG_TYPE_MANIFEST, &payload, 1);
    let report = verify(&data, &VerifyOptions::default()).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    assert_eq!(
        report
            .records()
            .iter()
            .find(|record| record.check == CheckKind::RootPageBinding)
            .unwrap()
            .outcome,
        Outcome::Pass
    );
}

#[test]
fn rvforge_root_page_cannot_retarget_or_change_signer() {
    let (mut data, public) = forge_authored_fixture();
    let page_start = data.len() - crate::ROOT_MANIFEST_SIZE;

    // Repoint to the WASM segment, then repair only the corruption checksum.
    // The semantic binding and the root-page signature must both fail.
    data[page_start + 8..page_start + 16].copy_from_slice(&0u64.to_le_bytes());
    data[page_start + 16..page_start + 24].copy_from_slice(&192u64.to_le_bytes());
    let checksum = crc32c(&data[page_start..page_start + 0x0ffc]);
    data[page_start + 0x0ffc..].copy_from_slice(&checksum.to_le_bytes());

    let report = verify(&data, &VerifyOptions::with_trusted_keys(vec![public])).unwrap();
    assert!(!report.is_ok());
    assert!(report.first_failure(CheckKind::RootPageBinding).is_some());
    assert!(report.first_failure(CheckKind::RootPageSignature).is_some());
    assert_eq!(report.trusted_root_signer(), None);
}

#[test]
fn independently_valid_root_signatures_must_come_from_the_same_key() {
    let segment_key = SigningKey::from_bytes(&[0x17; 32]);
    let page_key = SigningKey::from_bytes(&[0x18; 32]);
    let mut data = forge_segment(SEG_TYPE_WASM, b"\0asm\x01\0\0\0", 1, &segment_key);
    let manifest_offset = data.len();
    let manifest = forge_segment(SEG_TYPE_MANIFEST, b"root", 2, &segment_key);
    let manifest_length = manifest.len();
    data.extend_from_slice(&manifest);
    data.extend_from_slice(&forge_root_page(
        manifest_offset as u64,
        manifest_length as u64,
        &page_key,
    ));

    let options = VerifyOptions::with_trusted_keys(vec![
        segment_key.verifying_key().to_bytes(),
        page_key.verifying_key().to_bytes(),
    ]);
    let report = verify(&data, &options).unwrap();
    assert_eq!(
        report
            .records()
            .iter()
            .find(|record| record.check == CheckKind::RootPageSignature)
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    assert!(report.first_failure(CheckKind::RootSignerBinding).is_some());
    assert_eq!(report.trusted_root_signer(), None);
}
