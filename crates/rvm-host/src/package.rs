//! The verified package: the only thing an adapter will place into an
//! isolation context.
//!
//! ADR-284 §1.1 puts verification before allocation, and the cheapest way to
//! keep that true under later refactoring is to make it a type. Every entry
//! point in `rvm-host` and `rvm-launch` that can lead to execution takes a
//! [`VerifiedPackage`], and the only way to obtain one is
//! [`VerifiedPackage::from_report`], which refuses a report whose verification
//! failed. The report's trust-bearing fields are opaque outside `rvm-rvf`, so
//! safe downstream code cannot fabricate a pass or substitute payload hashes.
//! A caller cannot start an unverified artifact by forgetting a check because
//! there is no unverified value to pass.

use alloc::vec::Vec;
use rvm_rvf::{
    format::SEG_TYPE_WASM, CapabilityClass, CapabilityMapping, VerificationReport,
    VerifiedExecutable, VerifiedMetadata,
};

use crate::error::{HostError, HostResult};

/// An RVF that passed every verification check, with the capability mapping it
/// resolved to.
///
/// Holds no container bytes, but retains each executable payload's identity so
/// separately supplied runtime bytes can be bound back to what was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPackage {
    identity: [u8; 32],
    byte_length: u64,
    segment_count: usize,
    executables: Vec<VerifiedExecutable>,
    verified_metadata: Vec<VerifiedMetadata>,
    trusted_root_signer: Option<[u8; 32]>,
    capabilities: CapabilityMapping,
}

impl VerifiedPackage {
    /// Accept a passing verification report.
    ///
    /// # Errors
    ///
    /// [`HostError::Unverified`] when any check in the report failed. The
    /// caller has already witnessed those failures through
    /// [`rvm_rvf::emit_report`]; this is the refusal to act on them.
    pub fn from_report(report: &VerificationReport) -> HostResult<Self> {
        if !report.is_ok() {
            return Err(HostError::Unverified);
        }
        Ok(Self {
            identity: *report.rvf_identity(),
            byte_length: report.byte_length(),
            segment_count: report.segment_count(),
            executables: report.executables().to_vec(),
            verified_metadata: report.verified_metadata().to_vec(),
            trusted_root_signer: report.trusted_root_signer(),
            capabilities: report.capabilities().clone(),
        })
    }

    /// The container's SHA-256, which is its canonical `rvfIdentity`.
    ///
    /// Checkpoints bind to this value (ADR-288 §4), so state from a different
    /// lineage can be refused rather than replayed into the wrong agent.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// Container size in bytes.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// How many segments the container held.
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// The default-deny capability mapping.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilityMapping {
        &self.capabilities
    }

    /// Whether `module` exactly matches a WASM payload in this package.
    #[must_use]
    pub fn accepts_wasm(&self, module: &[u8]) -> bool {
        self.executables
            .iter()
            .any(|entry| entry.segment_type() == SEG_TYPE_WASM && entry.matches(module))
    }

    /// Whether `module` exactly matches a WASM payload whose signature
    /// independently verified against a trusted key.
    ///
    /// Production hosted runtimes use this stronger gate so a generic
    /// development report that allowed unsigned execution cannot be promoted
    /// into a distributable agent merely by wrapping it in `VerifiedPackage`.
    #[must_use]
    pub fn accepts_trusted_signed_wasm(&self, module: &[u8]) -> bool {
        self.executables.iter().any(|entry| {
            entry.segment_type() == SEG_TYPE_WASM
                && entry.has_trusted_signature()
                && entry.matches(module)
        })
    }

    /// Whether `module` exactly matches a WASM payload signed by `signer`.
    #[must_use]
    pub fn accepts_wasm_signed_by(&self, module: &[u8], signer: &[u8; 32]) -> bool {
        self.executables.iter().any(|entry| {
            entry.segment_type() == SEG_TYPE_WASM
                && entry.trusted_signer().as_ref() == Some(signer)
                && entry.matches(module)
        })
    }

    /// Whether `metadata` exactly matches a `META` payload whose content hash
    /// and Ed25519 signature both verified against a trusted key.
    ///
    /// Platform adapters use this before parsing fine-grained policy. It keeps
    /// unsigned metadata from widening sensor, network, model, or GPU rights.
    #[must_use]
    pub fn accepts_signed_metadata(&self, metadata: &[u8]) -> bool {
        self.verified_metadata
            .iter()
            .any(|entry| entry.matches(metadata))
    }

    /// Trusted signer of exact metadata bytes, when one was verified.
    #[must_use]
    pub fn trusted_metadata_signer(&self, metadata: &[u8]) -> Option<[u8; 32]> {
        self.verified_metadata
            .iter()
            .find(|entry| entry.matches(metadata))
            .map(VerifiedMetadata::trusted_signer)
    }

    /// Trusted signer of the selected root manifest, when one was verified.
    #[must_use]
    pub const fn trusted_root_signer(&self) -> Option<[u8; 32]> {
        self.trusted_root_signer
    }

    /// The classes this package declared and RVM will issue.
    #[must_use]
    pub fn granted_classes(&self) -> Vec<CapabilityClass> {
        self.capabilities
            .granted()
            .iter()
            .map(|b| b.class)
            .collect()
    }

    /// The classes that stay closed.
    #[must_use]
    pub fn denied_classes(&self) -> &[CapabilityClass] {
        self.capabilities.denied()
    }

    /// Whether `class` was declared.
    #[must_use]
    pub fn is_granted(&self, class: CapabilityClass) -> bool {
        self.capabilities.is_granted(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;
    use rvm_rvf::{verify, CheckKind, VerifyOptions};

    #[test]
    fn a_passing_report_becomes_a_package() {
        let data = testkit::container_declaring("memory,clock");
        let report = verify(&data, &testkit::lenient_options()).unwrap();
        assert!(report.is_ok(), "{:?}", report.failures());

        let pkg = VerifiedPackage::from_report(&report).unwrap();
        assert_eq!(pkg.identity(), report.rvf_identity());
        assert_eq!(pkg.byte_length(), report.byte_length());
        assert!(pkg.is_granted(CapabilityClass::Clock));
        assert!(!pkg.is_granted(CapabilityClass::Network));
        assert_eq!(pkg.denied_classes().len(), 13);
    }

    #[test]
    fn a_failing_report_yields_no_package_at_all() {
        // An unsigned executable under the strict default posture fails, and
        // there is no way to get a VerifiedPackage out of that report.
        let data = testkit::container_with_wasm("memory");
        let report = verify(&data, &VerifyOptions::default()).unwrap();
        assert!(!report.is_ok());
        assert!(report.first_failure(CheckKind::ExecutableSigned).is_some());

        assert_eq!(
            VerifiedPackage::from_report(&report),
            Err(HostError::Unverified)
        );
    }

    #[test]
    fn a_tampered_container_yields_no_package() {
        let mut data = testkit::container_with_wasm("memory");
        // Flip a byte inside the WASM payload; the content hash stops matching.
        let payload_start = 64 * 2 + 64;
        data[payload_start] ^= 0xff;

        let report = verify(&data, &testkit::lenient_options()).unwrap();
        assert!(report.first_failure(CheckKind::ContentHash).is_some());
        assert_eq!(
            VerifiedPackage::from_report(&report),
            Err(HostError::Unverified)
        );
    }

    #[test]
    fn executable_bytes_are_bound_to_the_verified_segment_identity() {
        let data = testkit::container_with_wasm("memory");
        let report = verify(&data, &testkit::lenient_options()).unwrap();
        let pkg = VerifiedPackage::from_report(&report).unwrap();
        let substitute = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];

        assert!(pkg.accepts_wasm(&testkit::MINIMAL_WASM));
        assert!(!pkg.accepts_trusted_signed_wasm(&testkit::MINIMAL_WASM));
        assert!(!pkg.accepts_wasm(&substitute));
    }

    #[test]
    fn unsigned_metadata_is_never_accepted_as_signed_policy() {
        let data = testkit::container_declaring("memory");
        let report = verify(&data, &testkit::lenient_options()).unwrap();
        let pkg = VerifiedPackage::from_report(&report).unwrap();
        assert!(!pkg.accepts_signed_metadata(b"rvf.capabilities=memory"));
    }

    #[test]
    fn granted_classes_come_back_in_declaration_order() {
        let data = testkit::container_declaring("clock,memory,model");
        let report = verify(&data, &testkit::lenient_options()).unwrap();
        let pkg = VerifiedPackage::from_report(&report).unwrap();
        assert_eq!(
            pkg.granted_classes(),
            [
                CapabilityClass::Memory,
                CapabilityClass::Model,
                CapabilityClass::Clock
            ]
        );
    }

    #[test]
    fn a_package_carries_no_container_bytes() {
        let data = testkit::container_declaring("memory");
        let report = verify(&data, &testkit::lenient_options()).unwrap();
        let pkg = VerifiedPackage::from_report(&report).unwrap();
        // Identities are retained; payload bytes are not, so holding a package
        // is never the same as holding runnable code.
        assert_eq!(pkg.byte_length(), data.len() as u64);
        assert_eq!(core::mem::size_of_val(pkg.identity()), 32);
    }
}
