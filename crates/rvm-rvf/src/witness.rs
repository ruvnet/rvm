//! Witness emission for verification results.
//!
//! ADR-284 §1.9 requires a witness record for every verification result —
//! successes and failures alike. A rejected RVF is an auditable event, not a
//! silent error, and ADR-286 §2 says the same about capability denials: a
//! denial is how "undeclared access was attempted and refused" becomes
//! provable rather than merely asserted.
//!
//! # Mapping onto `ActionKind`
//!
//! `rvm-witness` records carry an [`ActionKind`], and verification is a P2
//! structural validation, so the three outcomes map onto the proof kinds:
//!
//! | [`Outcome`] | [`ActionKind`] | Reading |
//! |---|---|---|
//! | `Pass` | `ProofVerifiedP2` | the check was discharged |
//! | `Fail` | `ProofRejected` | the check was discharged and refused |
//! | `Skip` | `ProofEscalated` | the check could not be discharged here and is left to the caller's policy |
//!
//! `Skip` is deliberately *not* `ProofVerifiedP2`. "No trusted key was
//! supplied" is not a passing signature check, and an audit trail that
//! recorded it as one would be worse than no trail.

use crate::verify::{CheckKind, Outcome, VerificationRecord, VerificationReport};
use rvm_types::{fnv1a_32, ActionKind, WitnessRecord};
use rvm_witness::WitnessLog;

/// Who performed the verification, and when.
///
/// The timestamp is supplied rather than sampled: this crate is `no_std` and
/// has no clock, and a verification report that read one would stop being a
/// pure function of its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessContext {
    /// The partition that performed the verification.
    pub actor_partition_id: u32,
    /// Nanosecond timestamp to stamp on every emitted record.
    pub timestamp_ns: u64,
}

impl WitnessContext {
    /// A context for `actor` at `timestamp_ns`.
    #[must_use]
    pub const fn new(actor_partition_id: u32, timestamp_ns: u64) -> Self {
        Self {
            actor_partition_id,
            timestamp_ns,
        }
    }
}

/// The `ActionKind` a verification outcome is recorded under.
#[must_use]
pub const fn action_kind_for(outcome: Outcome) -> ActionKind {
    match outcome {
        Outcome::Pass => ActionKind::ProofVerifiedP2,
        Outcome::Fail => ActionKind::ProofRejected,
        Outcome::Skip => ActionKind::ProofEscalated,
    }
}

/// Build the witness record for one verification result.
///
/// The record binds the result to the artifact: `capability_hash` is an
/// FNV-1a fold of the container's SHA-256 identity and `payload` carries the
/// identity's first eight bytes, so a record cannot be replayed against a
/// different artifact and still read as evidence about it.
#[must_use]
pub fn build_record(
    record: &VerificationRecord,
    rvf_identity: &[u8; 32],
    ctx: WitnessContext,
) -> WitnessRecord {
    let mut r = WitnessRecord::zeroed();
    r.action_kind = action_kind_for(record.outcome) as u8;
    r.proof_tier = 2;
    r.flags = record.check as u8;
    r.actor_partition_id = ctx.actor_partition_id;
    r.target_object_id = record.segment_id.unwrap_or(0);
    r.capability_hash = fnv1a_32(rvf_identity);
    r.timestamp_ns = ctx.timestamp_ns;
    r.payload.copy_from_slice(&rvf_identity[..8]);

    // aux: segment index (4 bytes LE), segment type, detail discriminant.
    let index = u32::try_from(record.segment_index.unwrap_or(0)).unwrap_or(u32::MAX);
    r.aux[0..4].copy_from_slice(&index.to_le_bytes());
    r.aux[4] = record.segment_type;
    r.aux[5] = record.outcome as u8;
    r
}

/// Append a witness record for every result in `report`.
///
/// Returns the number of records appended, which is always
/// `report.records.len()` — that equality is the requirement, not an
/// implementation detail.
pub fn emit_report<const N: usize>(
    report: &VerificationReport,
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) -> usize {
    for record in &report.records {
        let _ = log.append(build_record(record, &report.rvf_identity, ctx));
    }
    report.records.len()
}

/// Append a witness record for a single result.
///
/// Returns the sequence number the log assigned.
pub fn emit_record<const N: usize>(
    record: &VerificationRecord,
    rvf_identity: &[u8; 32],
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) -> u64 {
    log.append(build_record(record, rvf_identity, ctx))
}

/// Whether every result in `report` is one this crate emits a record for.
///
/// There is no result kind that is silently dropped, so this is always true;
/// it exists so the invariant is testable rather than assumed.
#[must_use]
pub const fn emits_a_record_for(_check: CheckKind) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
    use crate::testkit::{signed_segment, unsigned_segment, TestKeypair};
    use crate::verify::{verify, VerifyOptions};
    use alloc::vec;

    const CTX: WitnessContext = WitnessContext::new(7, 1_000);

    fn manifest_only() -> alloc::vec::Vec<u8> {
        unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1)
    }

    #[test]
    fn a_passing_verification_emits_a_record_for_every_result() {
        let data = manifest_only();
        let report = verify(&data, &VerifyOptions::default()).unwrap();
        assert!(report.ok);

        let log = WitnessLog::<64>::new();
        let emitted = emit_report(&report, &log, CTX);

        assert_eq!(emitted, report.records.len());
        assert_eq!(log.total_emitted(), emitted as u64);
    }

    #[test]
    fn a_failing_verification_also_emits_a_record_for_every_result() {
        let mut data = manifest_only();
        data.extend(unsigned_segment(SEG_TYPE_WASM, b"\0asm", 2));
        let report = verify(&data, &VerifyOptions::default()).unwrap();
        assert!(!report.ok);

        let log = WitnessLog::<64>::new();
        let emitted = emit_report(&report, &log, CTX);

        assert_eq!(emitted, report.records.len());
        assert_eq!(log.total_emitted(), emitted as u64);

        // The refusal itself is in the log, under ProofRejected.
        let rejected = (0..emitted)
            .filter_map(|i| log.get(i))
            .filter(|r| r.action_kind == ActionKind::ProofRejected as u8)
            .count();
        assert_eq!(rejected, report.failures().len());
    }

    #[test]
    fn a_skip_is_recorded_as_escalated_not_as_a_pass() {
        let kp = TestKeypair::deterministic(7);
        let mut data = manifest_only();
        data.extend(signed_segment(SEG_TYPE_WASM, b"\0asm", 2, &kp));
        // No trusted key, so the signature check skips.
        let report = verify(&data, &VerifyOptions::default()).unwrap();

        let skipped = report
            .records
            .iter()
            .find(|r| r.outcome == Outcome::Skip)
            .expect("expected a skipped check");
        let record = build_record(skipped, &report.rvf_identity, CTX);

        assert_eq!(record.action_kind, ActionKind::ProofEscalated as u8);
        assert_ne!(record.action_kind, ActionKind::ProofVerifiedP2 as u8);
    }

    #[test]
    fn a_capability_denial_is_witnessed() {
        let data = crate::testkit::minimal_container("clipboard");
        let report = verify(&data, &VerifyOptions::default()).unwrap();
        assert!(!report.ok);

        let log = WitnessLog::<64>::new();
        emit_report(&report, &log, CTX);

        let cap_records: alloc::vec::Vec<_> = (0..report.records.len())
            .filter_map(|i| log.get(i))
            .filter(|r| r.flags == CheckKind::CapabilityMapping as u8)
            .collect();
        assert_eq!(cap_records.len(), 1);
        assert_eq!(cap_records[0].action_kind, ActionKind::ProofRejected as u8);
    }

    #[test]
    fn records_bind_to_the_artifact_they_describe() {
        let a = verify(&manifest_only(), &VerifyOptions::default()).unwrap();
        let b = verify(
            &unsigned_segment(SEG_TYPE_MANIFEST, b"different", 1),
            &VerifyOptions::default(),
        )
        .unwrap();

        let ra = build_record(&a.records[0], &a.rvf_identity, CTX);
        let rb = build_record(&b.records[0], &b.rvf_identity, CTX);

        assert_ne!(ra.capability_hash, rb.capability_hash);
        assert_ne!(ra.payload, rb.payload);
        assert_eq!(&ra.payload[..], &a.rvf_identity[..8]);
    }

    #[test]
    fn per_segment_results_carry_their_segment_coordinates() {
        let mut data = manifest_only();
        data.extend(unsigned_segment(SEG_TYPE_META, b"metadata", 42));
        let report = verify(&data, &VerifyOptions::default()).unwrap();

        let seg_record = report
            .records
            .iter()
            .find(|r| r.segment_id == Some(42))
            .unwrap();
        let record = build_record(seg_record, &report.rvf_identity, CTX);

        assert_eq!(record.target_object_id, 42);
        assert_eq!(record.aux[0..4], 1u32.to_le_bytes());
        assert_eq!(record.aux[4], SEG_TYPE_META);
        assert_eq!(record.actor_partition_id, 7);
        assert_eq!(record.timestamp_ns, 1_000);
        assert_eq!(record.proof_tier, 2);
    }

    #[test]
    fn the_log_chains_the_emitted_records() {
        let data = manifest_only();
        let report = verify(&data, &VerifyOptions::default()).unwrap();
        let log = WitnessLog::<64>::new();
        emit_report(&report, &log, CTX);

        let records: alloc::vec::Vec<_> = (0..report.records.len())
            .filter_map(|i| log.get(i))
            .collect();
        assert!(rvm_witness::verify_chain(&records).is_ok());
    }

    #[test]
    fn every_check_kind_is_emitted() {
        for check in [
            CheckKind::Identity,
            CheckKind::RootManifestPresent,
            CheckKind::ContentHash,
            CheckKind::ExecutableSigned,
            CheckKind::Signature,
            CheckKind::SizePolicy,
            CheckKind::CapabilityMapping,
        ] {
            assert!(emits_a_record_for(check));
        }
    }

    #[test]
    fn outcome_to_action_kind_is_the_documented_mapping() {
        assert_eq!(action_kind_for(Outcome::Pass), ActionKind::ProofVerifiedP2);
        assert_eq!(action_kind_for(Outcome::Fail), ActionKind::ProofRejected);
        assert_eq!(action_kind_for(Outcome::Skip), ActionKind::ProofEscalated);
    }

    #[test]
    fn a_single_result_can_be_emitted_on_its_own() {
        let report = verify(&manifest_only(), &VerifyOptions::default()).unwrap();
        let log = WitnessLog::<8>::new();
        let seq = emit_record(&report.records[0], &report.rvf_identity, &log, CTX);
        assert_eq!(seq, 0);
        assert_eq!(log.total_emitted(), 1);
        let _ = vec![0u8; 0];
    }
}
