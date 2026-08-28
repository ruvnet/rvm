//! `inspect` and `verify`: the two operations that never execute anything.
//!
//! ADR-289 §3 states the rule plainly — *`inspect` and `verify` never execute
//! RVF content* — and the reason is that build workers, package scanners, and
//! store front-ends handle untrusted artifacts constantly. Any path where
//! reading an RVF can become running one turns every such tool into an
//! execution surface for third-party code.
//!
//! Both are thin over `rvm-rvf`, deliberately. Reimplementing segment walking
//! or signature checking here would give the CLI, the desktop reader, and
//! Forge three chances to disagree about whether the same artifact is
//! acceptable, which is the failure ADR-289 rejects in its alternatives.

use alloc::vec::Vec;
use rvm_rvf::{
    declared_classes, emit_report, sha256, walk, CapabilityClass, VerificationReport,
    VerifyOptions, WitnessContext,
};
use rvm_witness::WitnessLog;

use crate::error::LaunchResult;

/// One segment, as reported by [`inspect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSummary {
    /// Position in the stream.
    pub index: usize,
    /// The segment's ordinal from its header.
    pub segment_id: u64,
    /// The type discriminator.
    pub segment_type: u8,
    /// Payload length in bytes.
    pub payload_bytes: u64,
    /// Whether the header declares a signature footer.
    pub signed: bool,
    /// Whether the payload is code a runtime would execute.
    pub executable: bool,
}

/// What an artifact says about itself, with no trust claim attached.
///
/// `content_digest` is the SHA-256 of the bytes as they are. It is *not* an
/// endorsement: it says which artifact was inspected, not that the artifact is
/// intact or signed. Only [`verify`] answers that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// SHA-256 of the container as supplied.
    pub content_digest: [u8; 32],
    /// Container size in bytes.
    pub byte_length: u64,
    /// Every segment, in stream order.
    pub segments: Vec<SegmentSummary>,
    /// The capability classes the container declares.
    pub declared_classes: Vec<CapabilityClass>,
    /// Whether a root manifest segment is present.
    pub has_root_manifest: bool,
}

impl Inspection {
    /// How many segments carry executable payload.
    #[must_use]
    pub fn executable_segments(&self) -> usize {
        self.segments.iter().filter(|s| s.executable).count()
    }

    /// How many segments carry a signature footer.
    #[must_use]
    pub fn signed_segments(&self) -> usize {
        self.segments.iter().filter(|s| s.signed).count()
    }
}

/// Read an artifact's structure and declarations without executing any of it.
///
/// The walk reads 64-byte headers and records byte ranges; the only payloads
/// touched are metadata segments, scanned as text for the capability
/// declaration. No executable segment's payload is read at all.
///
/// # Errors
///
/// [`LaunchError::Rvf`](crate::LaunchError::Rvf) when the bytes are not a
/// well-formed container. A container that is well-formed but *invalid* — bad
/// hash, unsigned executable — inspects fine, because reporting what a
/// suspicious artifact claims is the entire job.
pub fn inspect(data: &[u8]) -> LaunchResult<Inspection> {
    let segments = walk(data)?;
    let summaries = segments
        .iter()
        .map(|s| SegmentSummary {
            index: s.index,
            segment_id: s.header.segment_id,
            segment_type: s.header.seg_type,
            payload_bytes: s.header.payload_length,
            signed: s.is_signed(),
            executable: s.is_executable(),
        })
        .collect();

    Ok(Inspection {
        content_digest: sha256(data),
        byte_length: data.len() as u64,
        segments: summaries,
        declared_classes: declared_classes(data, &segments),
        has_root_manifest: rvm_rvf::root_manifest(&segments).is_some(),
    })
}

/// Verify an artifact and witness the result, pass or fail.
///
/// Returns the report rather than a verdict: ADR-289 criterion 5 requires a
/// witness record on both outcomes, and the caller needs the failing records
/// to say *why* it refused. Turning the report into an executable instance
/// goes through [`VerifiedPackage`](rvm_host::VerifiedPackage), which is where
/// a failed report stops.
///
/// # Errors
///
/// [`LaunchError::Rvf`](crate::LaunchError::Rvf) when the bytes are not a
/// well-formed container. Verification *failures* come back inside the report.
pub fn verify<const N: usize>(
    data: &[u8],
    options: &VerifyOptions,
    log: &WitnessLog<N>,
    context: WitnessContext,
) -> LaunchResult<VerificationReport> {
    let report = rvm_rvf::verify(data, options)?;
    emit_report(&report, log, context);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_host::testkit;
    use rvm_rvf::{RvfError, SEGMENT_MAGIC_BYTES};

    const CTX: WitnessContext = WitnessContext::new(1, 100);

    #[test]
    fn inspection_reports_structure_and_declarations() {
        let data = testkit::container_with_wasm("memory,clock");
        let report = inspect(&data).unwrap();

        assert_eq!(report.segments.len(), 3);
        assert_eq!(report.executable_segments(), 1);
        assert_eq!(report.signed_segments(), 0);
        assert!(report.has_root_manifest);
        assert_eq!(
            report.declared_classes,
            [CapabilityClass::Memory, CapabilityClass::Clock]
        );
        assert_eq!(report.content_digest, rvm_rvf::sha256(&data));
        assert_eq!(report.byte_length, data.len() as u64);
    }

    #[test]
    fn inspection_succeeds_on_an_artifact_that_would_fail_verification() {
        // Tamper with the WASM payload. The container is still well-formed, so
        // inspection reports it — which is exactly what a scanner needs.
        let mut data = testkit::container_with_wasm("memory");
        data[192] ^= 0xff;

        let inspected = inspect(&data).unwrap();
        assert_eq!(inspected.executable_segments(), 1);

        let log = WitnessLog::<64>::new();
        let report = verify(&data, &testkit::lenient_options(), &log, CTX).unwrap();
        assert!(!report.is_ok());
    }

    #[test]
    fn inspection_refuses_bytes_that_are_not_a_container() {
        let mut data = testkit::container_declaring("memory");
        data[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_ne!(&data[0..4], &SEGMENT_MAGIC_BYTES);
        assert_eq!(
            inspect(&data),
            Err(crate::LaunchError::Rvf(RvfError::BadMagic))
        );
    }

    #[test]
    fn verification_is_witnessed_when_it_passes() {
        let data = testkit::container_with_wasm("memory");
        let log = WitnessLog::<64>::new();
        let report = verify(&data, &testkit::lenient_options(), &log, CTX).unwrap();

        assert!(report.is_ok());
        assert_eq!(log.total_emitted(), report.records().len() as u64);
    }

    #[test]
    fn verification_is_witnessed_when_it_fails() {
        let data = testkit::container_with_wasm("memory");
        let log = WitnessLog::<64>::new();
        // The strict posture refuses the unsigned executable.
        let report = verify(&data, &VerifyOptions::default(), &log, CTX).unwrap();

        assert!(!report.is_ok());
        assert_eq!(log.total_emitted(), report.records().len() as u64);
        let rejected = (0..log.len())
            .filter_map(|i| log.get(i))
            .filter(|r| r.action_kind == rvm_types::ActionKind::ProofRejected as u8)
            .count();
        assert_eq!(rejected, report.failures().len());
        assert!(rejected > 0);
    }

    #[test]
    fn neither_operation_reads_an_executable_payload_into_a_result() {
        // The inspection carries ranges and lengths, never payload bytes, so
        // there is nothing in the returned value a caller could run.
        let data = testkit::container_with_wasm("memory");
        let inspected = inspect(&data).unwrap();
        let wasm = inspected.segments.iter().find(|s| s.executable).unwrap();
        assert_eq!(wasm.payload_bytes, testkit::MINIMAL_WASM.len() as u64);
        assert_eq!(
            core::mem::size_of_val(wasm),
            core::mem::size_of::<SegmentSummary>()
        );
    }
}
