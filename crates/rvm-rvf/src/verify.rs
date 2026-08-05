//! Verify-before-load: identity, root manifest, per-segment hashes,
//! signatures, size policy, and capability mapping.
//!
//! Two design points are load-bearing rather than stylistic.
//!
//! **Failure returns a report, not an error.** ADR-284 §1.9 calls for a
//! witness record for *every* verification result, and a refusal is a result.
//! Returning `Err` on the first bad hash would discard exactly the evidence
//! the refusal needs to be auditable. So [`verify`] returns `Ok(report)`
//! whenever the container parses, with `report.ok == false` and a record per
//! check. `Err` is reserved for bytes that are not an RVF at all. Callers who
//! want the failure as an error call [`VerificationReport::into_result`].
//!
//! **Nothing here executes anything.** The only bytes read from an executable
//! segment are read to hash them (ADR-284 §1.7).

use crate::capability::{declared_classes, map_declared, CapabilityMapping};
use crate::container::{root_manifest, walk, ParsedSegment};
use crate::detail::DetailCode;
use crate::error::{RvfError, RvfResult};
use crate::format::{decode_signature_footer, ED25519_SIGNATURE_LENGTH, SIG_ALGO_ED25519};
use crate::hash::{sha256, verify_content_hash};
use crate::policy::{check as check_sizes, SizePolicy, SizeViolation};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};

/// Which check a record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CheckKind {
    /// The container's SHA-256 matches the caller's expected identity.
    Identity = 0,
    /// A root manifest segment is present.
    RootManifestPresent = 1,
    /// A segment's payload matches the content hash in its header.
    ContentHash = 2,
    /// An executable segment carries a signature at all.
    ExecutableSigned = 3,
    /// A segment's Ed25519 signature verifies against a trusted key.
    Signature = 4,
    /// The container fits inside the signed size policy.
    SizePolicy = 5,
    /// Declared capability classes map into `rvm-cap`.
    CapabilityMapping = 6,
}

/// The result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// The check passed.
    Pass = 0,
    /// The check failed. Any failure makes the whole report `ok == false`.
    Fail = 1,
    /// The check did not apply, or could not run. A skip never makes a report
    /// fail on its own, and is never treated as a pass.
    Skip = 2,
}

/// One verification result. Every check performed produces exactly one,
/// whether it passed, failed, or was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationRecord {
    /// Which check this records.
    pub check: CheckKind,
    /// Its result.
    pub outcome: Outcome,
    /// Stream position of the segment checked, for per-segment checks.
    pub segment_index: Option<usize>,
    /// Ordinal of the segment checked, for per-segment checks.
    pub segment_id: Option<u64>,
    /// Type discriminator of the segment checked, or 0 for container-level.
    pub segment_type: u8,
    /// Why the check produced this outcome.
    pub detail: DetailCode,
}

/// The full result of verifying one artifact.
///
/// Carries no timestamp: two verifications of the same bytes under the same
/// options produce identical reports, which is what makes a report comparable
/// across backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// SHA-256 of the whole container — the canonical `rvfIdentity`.
    pub rvf_identity: [u8; 32],
    /// Container size in bytes.
    pub byte_length: u64,
    /// True when no record failed.
    pub ok: bool,
    /// How many segments were examined.
    pub segment_count: usize,
    /// One record per check performed, in check order.
    pub records: Vec<VerificationRecord>,
    /// The default-deny capability mapping this artifact resolves to.
    ///
    /// When the capability check failed, this is the deny-everything mapping:
    /// a refused artifact grants nothing.
    pub capabilities: CapabilityMapping,
    /// Every size limit the container exceeded.
    pub size_violations: Vec<SizeViolation>,
}

impl VerificationReport {
    /// The failing records.
    #[must_use]
    pub fn failures(&self) -> Vec<&VerificationRecord> {
        self.records
            .iter()
            .filter(|r| r.outcome == Outcome::Fail)
            .collect()
    }

    /// The first failing record for `check`, if any.
    #[must_use]
    pub fn first_failure(&self, check: CheckKind) -> Option<&VerificationRecord> {
        self.records
            .iter()
            .find(|r| r.outcome == Outcome::Fail && r.check == check)
    }

    /// Convert a failed report into the matching error.
    ///
    /// # Errors
    ///
    /// [`RvfError::UnsupportedCapability`] when a declared class is
    /// unrepresentable, and [`RvfError::MalformedFooter`] as the generic
    /// verification failure otherwise. Callers that need to distinguish the
    /// individual failures read [`VerificationReport::failures`] instead;
    /// this is the shorthand for "refuse and say roughly why".
    pub fn into_result(self) -> RvfResult<Self> {
        if self.ok {
            return Ok(self);
        }
        if self.first_failure(CheckKind::CapabilityMapping).is_some() {
            // The specific class is already in the record set; report the
            // first declared class RVM cannot represent.
            let class = crate::capability::CapabilityClass::ALL
                .into_iter()
                .find(|c| !c.is_representable())
                .unwrap_or(crate::capability::CapabilityClass::Clipboard);
            return Err(RvfError::UnsupportedCapability(class));
        }
        Err(RvfError::MalformedFooter)
    }
}

/// How to verify.
///
/// [`VerifyOptions::default`] is the strict posture: unsigned executables are
/// refused, no key is trusted until one is supplied, and the fail-closed size
/// policy applies.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Ed25519 public keys whose signatures are accepted. With none supplied,
    /// non-executable signature checks are recorded as skipped rather than
    /// passed. Executable signatures without a trust anchor fail strict
    /// eligibility: unverifiable code is never treated as verified code.
    pub trusted_keys: Vec<[u8; 32]>,
    /// Permit executable segments with no signature. Off by default; exists
    /// for unsigned development builds, which are labeled as such and are not
    /// eligible for distribution.
    pub allow_unsigned_executable: bool,
    /// When set, the container's SHA-256 must equal this value.
    pub expected_identity: Option<[u8; 32]>,
    /// The signed size limits to enforce at parse time.
    pub size_policy: SizePolicy,
}

impl VerifyOptions {
    /// Strict defaults with the given trusted keys.
    #[must_use]
    pub fn with_trusted_keys(keys: Vec<[u8; 32]>) -> Self {
        Self {
            trusted_keys: keys,
            ..Self::default()
        }
    }

    /// Require the container to hash to `identity`.
    #[must_use]
    pub fn expect_identity(mut self, identity: [u8; 32]) -> Self {
        self.expected_identity = Some(identity);
        self
    }

    /// Use `policy` instead of the fail-closed default.
    #[must_use]
    pub fn with_size_policy(mut self, policy: SizePolicy) -> Self {
        self.size_policy = policy;
        self
    }
}

/// Verify an in-memory RVF container without executing any of it.
///
/// # Errors
///
/// An [`RvfError`] when `data` is not a well-formed container. Verification
/// *failures* are reported in the returned value, not raised.
pub fn verify(data: &[u8], opts: &VerifyOptions) -> RvfResult<VerificationReport> {
    let segments = walk(data)?;
    let identity = sha256(data);
    let mut records = Vec::new();

    if let Some(expected) = opts.expected_identity {
        let matches = expected == identity;
        records.push(container_record(
            CheckKind::Identity,
            outcome(matches),
            if matches {
                DetailCode::IdentityMatches
            } else {
                DetailCode::IdentityMismatch
            },
        ));
    }

    records.push(root_manifest_record(&segments));

    let size_violations = check_sizes(data.len() as u64, &segments, &opts.size_policy);
    records.push(container_record(
        CheckKind::SizePolicy,
        outcome(size_violations.is_empty()),
        if size_violations.is_empty() {
            DetailCode::WithinSizePolicy
        } else {
            DetailCode::ExceedsSizePolicy
        },
    ));

    let (capabilities, cap_record) = capability_records(data, &segments);
    records.push(cap_record);

    for seg in &segments {
        records.push(content_hash_record(data, seg));
        if seg.is_executable() {
            records.push(executable_signed_record(seg, opts));
        }
        if seg.is_signed() {
            records.push(signature_record(data, seg, opts));
        }
    }

    let ok = !records.iter().any(|r| r.outcome == Outcome::Fail);
    Ok(VerificationReport {
        rvf_identity: identity,
        byte_length: data.len() as u64,
        ok,
        segment_count: segments.len(),
        records,
        capabilities,
        size_violations,
    })
}

const fn outcome(passed: bool) -> Outcome {
    if passed {
        Outcome::Pass
    } else {
        Outcome::Fail
    }
}

const fn container_record(
    check: CheckKind,
    outcome: Outcome,
    detail: DetailCode,
) -> VerificationRecord {
    VerificationRecord {
        check,
        outcome,
        segment_index: None,
        segment_id: None,
        segment_type: 0,
        detail,
    }
}

fn segment_record(
    check: CheckKind,
    outcome: Outcome,
    seg: &ParsedSegment,
    detail: DetailCode,
) -> VerificationRecord {
    VerificationRecord {
        check,
        outcome,
        segment_index: Some(seg.index),
        segment_id: Some(seg.header.segment_id),
        segment_type: seg.header.seg_type,
        detail,
    }
}

/// ADR-284 §1.1: the root manifest is verified before anything else.
fn root_manifest_record(segments: &[ParsedSegment]) -> VerificationRecord {
    match root_manifest(segments) {
        Some(seg) => segment_record(
            CheckKind::RootManifestPresent,
            Outcome::Pass,
            seg,
            DetailCode::RootManifestFound,
        ),
        None => container_record(
            CheckKind::RootManifestPresent,
            Outcome::Fail,
            DetailCode::RootManifestMissing,
        ),
    }
}

fn capability_records(
    data: &[u8],
    segments: &[ParsedSegment],
) -> (CapabilityMapping, VerificationRecord) {
    let declared = declared_classes(data, segments);
    match map_declared(&declared) {
        Ok(mapping) => (
            mapping,
            container_record(
                CheckKind::CapabilityMapping,
                Outcome::Pass,
                DetailCode::CapabilitiesMapped,
            ),
        ),
        Err(_) => (
            // A refused artifact grants nothing.
            map_declared(&[]).unwrap_or_else(|_| unreachable!("the empty declaration always maps")),
            container_record(
                CheckKind::CapabilityMapping,
                Outcome::Fail,
                DetailCode::CapabilityUnsupported,
            ),
        ),
    }
}

fn content_hash_record(data: &[u8], seg: &ParsedSegment) -> VerificationRecord {
    let matches = verify_content_hash(&seg.header, seg.payload(data));
    segment_record(
        CheckKind::ContentHash,
        outcome(matches),
        seg,
        if matches {
            DetailCode::ContentHashMatches
        } else {
            DetailCode::ContentHashMismatch
        },
    )
}

fn executable_signed_record(seg: &ParsedSegment, opts: &VerifyOptions) -> VerificationRecord {
    if seg.is_signed() {
        return segment_record(
            CheckKind::ExecutableSigned,
            Outcome::Pass,
            seg,
            DetailCode::ExecutableIsSigned,
        );
    }
    if opts.allow_unsigned_executable {
        return segment_record(
            CheckKind::ExecutableSigned,
            Outcome::Skip,
            seg,
            DetailCode::UnsignedExecutablePermitted,
        );
    }
    segment_record(
        CheckKind::ExecutableSigned,
        Outcome::Fail,
        seg,
        DetailCode::ExecutableIsUnsigned,
    )
}

fn signature_record(data: &[u8], seg: &ParsedSegment, opts: &VerifyOptions) -> VerificationRecord {
    let Some(range) = seg.footer.clone() else {
        return segment_record(
            CheckKind::Signature,
            Outcome::Fail,
            seg,
            DetailCode::FooterMalformed,
        );
    };
    let Ok(footer) = decode_signature_footer(&data[range]) else {
        return segment_record(
            CheckKind::Signature,
            Outcome::Fail,
            seg,
            DetailCode::FooterMalformed,
        );
    };

    if footer.sig_algo != SIG_ALGO_ED25519 || footer.sig_length != ED25519_SIGNATURE_LENGTH {
        return segment_record(
            CheckKind::Signature,
            signature_incomplete_outcome(seg),
            seg,
            DetailCode::UnsupportedSignatureAlgorithm,
        );
    }
    if opts.trusted_keys.is_empty() {
        return segment_record(
            CheckKind::Signature,
            signature_incomplete_outcome(seg),
            seg,
            DetailCode::NoTrustedKey,
        );
    }

    let verified = signature_verifies(data, seg, footer.signature, &opts.trusted_keys);
    segment_record(
        CheckKind::Signature,
        outcome(verified),
        seg,
        if verified {
            DetailCode::SignatureVerifies
        } else {
            DetailCode::SignatureRejected
        },
    )
}

/// Missing verifier support may remain informational for signed data, but it
/// is a hard refusal for code. ADR-155 requires every executable segment to be
/// authenticated before load; a signature footer alone proves no publisher
/// identity.
const fn signature_incomplete_outcome(seg: &ParsedSegment) -> Outcome {
    if seg.is_executable() {
        Outcome::Fail
    } else {
        Outcome::Skip
    }
}

/// Whether any trusted key signed this segment.
fn signature_verifies(
    data: &[u8],
    seg: &ParsedSegment,
    sig_bytes: &[u8],
    trusted: &[[u8; 32]],
) -> bool {
    let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_array);
    let message = crate::format::build_signed_message(&seg.header, seg.payload(data));

    trusted.iter().any(|raw| {
        VerifyingKey::from_bytes(raw)
            .is_ok_and(|key| key.verify_strict(&message, &signature).is_ok())
    })
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
