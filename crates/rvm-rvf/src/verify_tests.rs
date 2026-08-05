//! Tests for [`crate::verify`], split out so neither file grows past the
//! workspace's 500-line ceiling.

use super::*;
use crate::capability::CapabilityClass;
use crate::detail::DetailCode;
use crate::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
use crate::policy::SizePolicy;
use crate::testkit::{signed_segment, unsigned_segment, TestKeypair};
use alloc::vec;

fn manifest_only() -> Vec<u8> {
    unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1)
}

fn record_for(report: &VerificationReport, check: CheckKind) -> &VerificationRecord {
    report
        .records
        .iter()
        .find(|r| r.check == check)
        .unwrap_or_else(|| panic!("no {check:?} record"))
}

#[test]
fn a_clean_container_verifies() {
    let report = verify(&manifest_only(), &VerifyOptions::default()).unwrap();
    assert!(report.ok, "{:?}", report.failures());
    assert_eq!(report.segment_count, 1);
    // One 64-byte header plus a 4-byte payload, padded to the 64-byte
    // segment boundary.
    assert_eq!(report.byte_length, 128);
}

#[test]
fn every_segment_produces_a_content_hash_record() {
    let mut data = manifest_only();
    data.extend(unsigned_segment(SEG_TYPE_META, b"metadata", 2));
    let report = verify(&data, &VerifyOptions::default()).unwrap();

    let hash_records: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.check == CheckKind::ContentHash)
        .collect();
    assert_eq!(hash_records.len(), 2);
    assert!(hash_records.iter().all(|r| r.outcome == Outcome::Pass));
}

#[test]
fn a_tampered_payload_fails_its_content_hash() {
    let mut data = manifest_only();
    data.extend(unsigned_segment(SEG_TYPE_META, b"metadata", 2));
    // Segment 1 pads to 0..128, so segment 2's header is at 128 and its
    // payload begins at 192. Flip a payload byte, leaving both headers intact
    // so the walk still succeeds and only the content-hash check fails.
    data[192] ^= 0xff;

    let report = verify(&data, &VerifyOptions::default()).unwrap();
    assert!(!report.ok);
    let failures = report.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].check, CheckKind::ContentHash);
    assert_eq!(failures[0].segment_id, Some(2));
    assert_eq!(failures[0].detail, DetailCode::ContentHashMismatch);
}

#[test]
fn an_unsigned_executable_is_refused_by_default() {
    let mut data = manifest_only();
    data.extend(unsigned_segment(SEG_TYPE_WASM, b"\0asm", 5));
    let report = verify(&data, &VerifyOptions::default()).unwrap();

    assert!(!report.ok);
    let rec = report.first_failure(CheckKind::ExecutableSigned).unwrap();
    assert_eq!(rec.detail, DetailCode::ExecutableIsUnsigned);
    assert_eq!(rec.segment_type, SEG_TYPE_WASM);
}

#[test]
fn an_unsigned_executable_is_permitted_for_development_builds() {
    let mut data = manifest_only();
    data.extend(unsigned_segment(SEG_TYPE_WASM, b"\0asm", 5));
    let opts = VerifyOptions {
        allow_unsigned_executable: true,
        ..VerifyOptions::default()
    };
    let report = verify(&data, &opts).unwrap();

    assert!(report.ok, "{:?}", report.failures());
    assert_eq!(
        record_for(&report, CheckKind::ExecutableSigned).outcome,
        Outcome::Skip
    );
}

#[test]
fn a_signed_executable_verifies_against_its_key() {
    let kp = TestKeypair::deterministic(7);
    let mut data = manifest_only();
    data.extend(signed_segment(SEG_TYPE_WASM, b"\0asm", 5, &kp));

    let opts = VerifyOptions::with_trusted_keys(vec![kp.public]);
    let report = verify(&data, &opts).unwrap();

    assert!(report.ok, "{:?}", report.failures());
    let sig = record_for(&report, CheckKind::Signature);
    assert_eq!(sig.outcome, Outcome::Pass);
    assert_eq!(sig.detail, DetailCode::SignatureVerifies);
}

#[test]
fn a_signature_fails_against_an_untrusted_key() {
    let signer = TestKeypair::deterministic(7);
    let stranger = TestKeypair::deterministic(8);
    let mut data = manifest_only();
    data.extend(signed_segment(SEG_TYPE_WASM, b"\0asm", 5, &signer));

    let opts = VerifyOptions::with_trusted_keys(vec![stranger.public]);
    let report = verify(&data, &opts).unwrap();

    assert!(!report.ok);
    assert_eq!(
        report.first_failure(CheckKind::Signature).unwrap().detail,
        DetailCode::SignatureRejected
    );
}

#[test]
fn a_tampered_signed_payload_fails_both_hash_and_signature() {
    let kp = TestKeypair::deterministic(7);
    let mut data = manifest_only();
    data.extend(signed_segment(SEG_TYPE_WASM, b"\0asm code", 5, &kp));
    // Segment 1 pads to 128; segment 2's payload begins one header later.
    data[192] ^= 0xff;

    let opts = VerifyOptions::with_trusted_keys(vec![kp.public]);
    let report = verify(&data, &opts).unwrap();

    assert!(!report.ok);
    assert!(report.first_failure(CheckKind::ContentHash).is_some());
    assert!(report.first_failure(CheckKind::Signature).is_some());
}

#[test]
fn a_signature_is_skipped_not_passed_when_no_key_is_trusted() {
    let kp = TestKeypair::deterministic(7);
    let mut data = manifest_only();
    data.extend(signed_segment(SEG_TYPE_WASM, b"\0asm", 5, &kp));

    let report = verify(&data, &VerifyOptions::default()).unwrap();
    assert_eq!(
        record_for(&report, CheckKind::Signature).detail,
        DetailCode::NoTrustedKey
    );
    // A skip is not a failure, and the executable is signed, so this passes.
    assert!(report.ok, "{:?}", report.failures());
}

#[test]
fn a_missing_root_manifest_fails() {
    let data = unsigned_segment(SEG_TYPE_META, b"metadata", 1);
    let report = verify(&data, &VerifyOptions::default()).unwrap();
    assert!(!report.ok);
    assert_eq!(
        report
            .first_failure(CheckKind::RootManifestPresent)
            .unwrap()
            .detail,
        DetailCode::RootManifestMissing
    );
}

#[test]
fn identity_is_the_sha256_of_the_whole_container() {
    let data = manifest_only();
    let report = verify(&data, &VerifyOptions::default()).unwrap();
    assert_eq!(report.rvf_identity, crate::hash::sha256(&data));

    let opts = VerifyOptions::default().expect_identity(report.rvf_identity);
    assert!(verify(&data, &opts).unwrap().ok);
}

#[test]
fn an_identity_mismatch_fails() {
    let opts = VerifyOptions::default().expect_identity([0u8; 32]);
    let report = verify(&manifest_only(), &opts).unwrap();
    assert!(!report.ok);
    assert_eq!(
        report.first_failure(CheckKind::Identity).unwrap().detail,
        DetailCode::IdentityMismatch
    );
}

#[test]
fn an_oversize_container_fails_the_size_policy_check() {
    let payload = vec![0u8; 4096];
    let mut data = manifest_only();
    data.extend(unsigned_segment(SEG_TYPE_WASM, &payload, 2));

    let opts = VerifyOptions {
        allow_unsigned_executable: true,
        size_policy: SizePolicy::default().with_max_runtime_bytes(1024),
        ..VerifyOptions::default()
    };
    let report = verify(&data, &opts).unwrap();

    assert!(!report.ok);
    assert_eq!(
        report.first_failure(CheckKind::SizePolicy).unwrap().detail,
        DetailCode::ExceedsSizePolicy
    );
    assert_eq!(report.size_violations.len(), 1);
}

#[test]
fn the_same_container_passes_under_a_policy_that_permits_its_size() {
    let payload = vec![0u8; 4096];
    let mut data = manifest_only();
    data.extend(unsigned_segment(SEG_TYPE_WASM, &payload, 2));

    let opts = VerifyOptions {
        allow_unsigned_executable: true,
        size_policy: SizePolicy::permissive(),
        ..VerifyOptions::default()
    };
    let report = verify(&data, &opts).unwrap();
    assert!(report.ok, "{:?}", report.failures());
    assert!(report.size_violations.is_empty());
}

#[test]
fn declared_capabilities_reach_the_report_and_the_rest_stay_denied() {
    let data = crate::testkit::minimal_container("network,clock");
    let report = verify(&data, &VerifyOptions::default()).unwrap();

    assert!(report.ok, "{:?}", report.failures());
    assert!(report.capabilities.is_granted(CapabilityClass::Network));
    assert!(report.capabilities.is_granted(CapabilityClass::Clock));
    assert!(!report.capabilities.is_granted(CapabilityClass::Filesystem));
    assert_eq!(report.capabilities.denied().len(), 13);
}

#[test]
fn an_unsupported_capability_class_is_witnessed_and_then_refused() {
    let data = crate::testkit::minimal_container("network,clipboard");
    let report = verify(&data, &VerifyOptions::default()).unwrap();

    // The refusal is a *result*: it appears as a record so it can be
    // witnessed, rather than being raised and losing the evidence.
    assert!(!report.ok);
    let rec = report.first_failure(CheckKind::CapabilityMapping).unwrap();
    assert_eq!(rec.detail, DetailCode::CapabilityUnsupported);
    // A refused artifact grants nothing.
    assert!(report.capabilities.granted().is_empty());

    match report.into_result() {
        Err(RvfError::UnsupportedCapability(_)) => {}
        other => panic!("expected UnsupportedCapability, got {other:?}"),
    }
}

#[test]
fn a_malformed_container_is_an_error_not_a_report() {
    let junk = vec![b'x'; 128];
    assert_eq!(
        verify(&junk, &VerifyOptions::default()),
        Err(RvfError::BadMagic)
    );
    assert_eq!(
        verify(&[0u8; 8], &VerifyOptions::default()),
        Err(RvfError::Truncated)
    );
}

#[test]
fn reports_are_deterministic() {
    let data = crate::testkit::minimal_container("network");
    let a = verify(&data, &VerifyOptions::default()).unwrap();
    let b = verify(&data, &VerifyOptions::default()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn a_passing_report_converts_to_itself() {
    let report = verify(&manifest_only(), &VerifyOptions::default()).unwrap();
    assert!(report.clone().into_result().is_ok());
    assert!(report.failures().is_empty());
}

#[test]
fn every_check_produces_exactly_one_record_per_subject() {
    let kp = TestKeypair::deterministic(4);
    let mut data = manifest_only();
    data.extend(signed_segment(SEG_TYPE_WASM, b"\0asm", 2, &kp));

    let opts = VerifyOptions::with_trusted_keys(vec![kp.public]).expect_identity([0u8; 32]);
    let report = verify(&data, &opts).unwrap();

    let count = |k: CheckKind| report.records.iter().filter(|r| r.check == k).count();
    assert_eq!(count(CheckKind::Identity), 1);
    assert_eq!(count(CheckKind::RootManifestPresent), 1);
    assert_eq!(count(CheckKind::SizePolicy), 1);
    assert_eq!(count(CheckKind::CapabilityMapping), 1);
    assert_eq!(count(CheckKind::ContentHash), 2);
    assert_eq!(count(CheckKind::ExecutableSigned), 1);
    assert_eq!(count(CheckKind::Signature), 1);
}

#[test]
fn detail_codes_all_render() {
    use core::fmt::Write;
    let codes = [
        DetailCode::IdentityMatches,
        DetailCode::IdentityMismatch,
        DetailCode::RootManifestFound,
        DetailCode::RootManifestMissing,
        DetailCode::ContentHashMatches,
        DetailCode::ContentHashMismatch,
        DetailCode::ExecutableIsSigned,
        DetailCode::ExecutableIsUnsigned,
        DetailCode::UnsignedExecutablePermitted,
        DetailCode::SignatureVerifies,
        DetailCode::SignatureRejected,
        DetailCode::NoTrustedKey,
        DetailCode::UnsupportedSignatureAlgorithm,
        DetailCode::FooterMalformed,
        DetailCode::WithinSizePolicy,
        DetailCode::ExceedsSizePolicy,
        DetailCode::CapabilitiesMapped,
        DetailCode::CapabilityUnsupported,
    ];
    for code in codes {
        let mut s = alloc::string::String::new();
        write!(&mut s, "{code}").unwrap();
        assert!(!s.is_empty());
    }
}
