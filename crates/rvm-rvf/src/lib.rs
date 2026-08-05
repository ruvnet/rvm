//! # RVF execution contract for RVM
//!
//! The boundary between the RVF container format and the machine. This crate
//! reads and verifies `.rvf` containers, maps their declared capabilities into
//! `rvm-cap` rights, and emits an `rvm-witness` record for every verification
//! result. It implements the RVM side of ADR-284 (RVF execution contract),
//! ADR-286 (capability schema mapping), and the policy-controlled size limits
//! of ADR-287.
//!
//! ## What this crate will not do
//!
//! **Nothing here executes an RVF.** ADR-284 §1.7 makes that a requirement
//! rather than a convention: inspection and packaging tools handle untrusted
//! artifacts constantly, and any path where "reading" an RVF can become
//! "running" one turns every such tool into an execution surface for
//! third-party code. So [`container::walk`] reads 64-byte headers and records
//! byte ranges; the only time an executable segment's payload is touched at
//! all is to hash it or to check a signature over it. No segment is mapped,
//! no entry point is resolved, no payload is interpreted.
//!
//! ## The four operations
//!
//! | Function | Produces | Purpose |
//! |---|---|---|
//! | [`container::walk`] | `Vec<ParsedSegment>` | Segment inventory: offsets and ranges only |
//! | [`verify`] | [`VerificationReport`] | Identity, manifest, hashes, signatures, size policy, capabilities |
//! | [`map_declared`] | [`CapabilityMapping`] | Declared classes into `rvm-cap` rights, default-deny |
//! | [`emit_report`] | witness records | One record per verification result, pass or fail |
//!
//! ## Verify before load
//!
//! ```ignore
//! use rvm_rvf::{emit_report, verify, VerifyOptions, WitnessContext};
//! use rvm_witness::WitnessLog;
//!
//! let log = WitnessLog::<256>::new();
//! let opts = VerifyOptions::with_trusted_keys(vec![publisher_key]);
//!
//! let report = verify(rvf_bytes, &opts)?;
//! emit_report(&report, &log, WitnessContext::new(partition, now_ns));
//!
//! let report = report.into_result()?;   // refuse unless every check passed
//! report.capabilities.install(&mut cap_table, partition, epoch, first_id)?;
//! // Only now may a caller allocate executable memory for a segment.
//! ```
//!
//! Allocation follows verification, never precedes it (ADR-284 §1.1), and the
//! witness record is emitted before the refusal is acted on, so a rejected RVF
//! is an auditable event rather than a silent error (§1.9).
//!
//! ## Errors versus failures
//!
//! [`verify`] returns `Err` only when the bytes are not a well-formed RVF.
//! Verification *failures* — a bad hash, an unsigned executable, an oversize
//! segment, an unrepresentable capability class — come back inside the report
//! with `ok == false`, because each of them needs a witness record and raising
//! on the first one would discard the rest of the evidence.
//!
//! ## Format compatibility
//!
//! [`format`] restates the RVF v1 wire layout rather than depending on
//! RuVector's `rvf-types` / `rvf-wire` / `rvf-crypto`, which are `std`-oriented
//! and live in a separate workspace. Every constant, offset, hash algorithm,
//! and signature-message layout is byte-compatible with those crates, and the
//! module's tests build containers from the same recipe the RuVector writer
//! uses.
//!
//! ## Allocation
//!
//! `no_std` with `alloc` required: a segment inventory is variable-length, so
//! the walk needs a `Vec`. Nothing else on the verification path allocates —
//! record details are typed codes rather than formatted strings, and the
//! 94-byte signature message is built on the stack.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod capability;
pub mod container;
pub mod detail;
pub mod error;
pub mod format;
pub mod hash;
pub mod policy;
pub mod verify;
pub mod witness;

#[cfg(test)]
mod compat_tests;
#[cfg(test)]
mod testkit;

pub use capability::{
    declared_classes, map_declared, CapabilityClass, CapabilityMapping, RvmBinding,
    CAPABILITY_DECLARATION_KEY,
};
pub use container::{root_manifest, walk, ParsedSegment};
pub use detail::DetailCode;
pub use error::{RvfError, RvfResult};
pub use format::{
    is_executable, SegmentClass, SegmentHeader, SignatureFooter, EXECUTABLE_SEGMENT_TYPES,
    MAX_SEGMENT_PAYLOAD, SEGMENT_ALIGNMENT, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC,
    SEGMENT_MAGIC_BYTES, SEGMENT_VERSION,
};
pub use hash::{content_hash, sha256, verify_content_hash};
pub use policy::{tally, SizePolicy, SizeTally, SizeViolation};
pub use verify::{
    verify, CheckKind, Outcome, VerificationRecord, VerificationReport, VerifiedExecutable,
    VerifyOptions,
};
pub use witness::{action_kind_for, build_record, emit_record, emit_report, WitnessContext};

/// The version of the RVF execution contract this crate implements.
///
/// This is what populates `rvmVersionMin` in the RVForge compatibility matrix
/// (ADR-291): a Forge build targeting `rvm-native` is only valid against a
/// runtime whose contract version it recognizes.
pub const RVF_CONTRACT_VERSION: u32 = 1;

/// The RVF container format version this crate reads.
pub const RVF_FORMAT_VERSION: u8 = format::SEGMENT_VERSION;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn a_signed_agent_verifies_maps_and_witnesses_end_to_end() {
        let kp = testkit::TestKeypair::deterministic(11);

        // A META segment declaring capabilities, a signed WASM runtime
        // segment, and a root manifest.
        let mut data = testkit::minimal_container("network,model,clock");
        data.extend(testkit::signed_segment(
            format::SEG_TYPE_WASM,
            b"\0asm\x01\0\0\0",
            3,
            &kp,
        ));
        data.extend(testkit::unsigned_segment(
            format::SEG_TYPE_MANIFEST,
            b"root",
            4,
        ));

        let opts = VerifyOptions::with_trusted_keys(vec![kp.public]);
        let report = verify(&data, &opts).unwrap();
        assert!(report.ok, "{:?}", report.failures());

        // Every result is witnessed before anything is acted on.
        let log = rvm_witness::WitnessLog::<128>::new();
        let emitted = emit_report(&report, &log, WitnessContext::new(1, 42));
        assert_eq!(emitted, report.records.len());

        // Declared classes become rvm-cap capabilities; the other twelve stay
        // closed.
        let report = report.into_result().unwrap();
        let mut table = rvm_cap::CapabilityTable::<32>::new();
        let installed = report
            .capabilities
            .install(&mut table, rvm_types::PartitionId::new(1), 0, 1)
            .unwrap();
        assert_eq!(installed, 3);
        assert_eq!(table.len(), 3);
        assert!(!report.capabilities.is_granted(CapabilityClass::Filesystem));
    }

    #[test]
    fn the_same_agent_with_one_flipped_byte_is_refused() {
        let kp = testkit::TestKeypair::deterministic(11);
        let mut data = testkit::minimal_container("network");
        data.extend(testkit::signed_segment(
            format::SEG_TYPE_WASM,
            b"\0asm\x01\0\0\0",
            3,
            &kp,
        ));
        data.extend(testkit::unsigned_segment(
            format::SEG_TYPE_MANIFEST,
            b"root",
            4,
        ));

        // Flip a byte inside the WASM payload. The minimal container is two
        // segments, each padded to 128 bytes, and the payload starts one
        // 64-byte header after that.
        let wasm_payload_start = 128 * 2 + 64;
        data[wasm_payload_start] ^= 0xff;

        let opts = VerifyOptions::with_trusted_keys(vec![kp.public]);
        let report = verify(&data, &opts).unwrap();
        assert!(!report.ok);
        assert!(report.first_failure(CheckKind::ContentHash).is_some());
        assert!(report.first_failure(CheckKind::Signature).is_some());
    }

    #[test]
    fn contract_and_format_versions_are_one() {
        assert_eq!(RVF_CONTRACT_VERSION, 1);
        assert_eq!(RVF_FORMAT_VERSION, 1);
    }
}
