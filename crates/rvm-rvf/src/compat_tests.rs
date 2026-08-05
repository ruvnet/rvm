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
use crate::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
use crate::verify::{verify, CheckKind, Outcome, VerifyOptions};
use alloc::vec;
use alloc::vec::Vec;

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
