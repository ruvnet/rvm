//! Verify-before-load: identity, root manifest, per-segment hashes,
//! signatures, size policy, and capability mapping.
//!
//! Two design points are load-bearing rather than stylistic.
//!
//! **Failure returns a report, not an error.** ADR-284 §1.9 calls for a
//! witness record for *every* verification result, and a refusal is a result.
//! Returning `Err` on the first bad hash would discard exactly the evidence
//! the refusal needs to be auditable. So [`verify`] returns `Ok(report)`
//! whenever the container parses, with `report.is_ok() == false` and a record per
//! check. `Err` is reserved for bytes that are not an RVF at all. Callers who
//! want the failure as an error call [`VerificationReport::into_result`].
//!
//! **Nothing here executes anything.** The only bytes read from an executable
//! segment are read to hash them (ADR-284 §1.7).

use crate::capability::{
    declared_classes, has_unknown_class_name, map_declared, CapabilityMapping,
};
use crate::container::{
    root_manifest, root_manifest_page, walk, ParsedSegment, RootManifestPage, ROOT_MANIFEST_SIZE,
};
use crate::detail::DetailCode;
use crate::error::{RvfError, RvfResult};
use crate::format::{decode_signature_footer, ED25519_SIGNATURE_LENGTH, SIG_ALGO_ED25519};
use crate::hash::{is_supported_content_hash, sha256, verify_content_hash};
use crate::policy::{check as check_sizes, SizePolicy, SizeViolation};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};

const ROOT_SIG_ALGO_ED25519: u16 = 1;
const ROOT_SIGNATURE_OFFSET: usize = 0x09c;
const ROOT_CHECKSUM_OFFSET: usize = 0x0ffc;

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
    /// A trailing Level-0 root page passed structural and CRC checks.
    RootPageIntegrity = 7,
    /// The Level-0 root page points to the selected `MANIFEST` bytes.
    RootPageBinding = 8,
    /// The Level-0 root page signature verifies against a trusted key.
    RootPageSignature = 9,
    /// The Level-0 page and selected `MANIFEST` share one trusted signer.
    RootSignerBinding = 10,
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

/// Identity of executable payload bytes examined during RVF verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedExecutable {
    /// Ordinal assigned by the RVF writer.
    segment_id: u64,
    /// RVF segment type discriminator.
    segment_type: u8,
    /// Exact executable payload length.
    byte_length: u64,
    /// SHA-256 of the executable payload bytes.
    sha256: [u8; 32],
    /// Trusted Ed25519 public key that signed this exact segment, if any.
    trusted_signer: Option<[u8; 32]>,
}

impl VerifiedExecutable {
    /// Ordinal assigned by the RVF writer.
    #[must_use]
    pub const fn segment_id(&self) -> u64 {
        self.segment_id
    }

    /// RVF segment type discriminator.
    #[must_use]
    pub const fn segment_type(&self) -> u8 {
        self.segment_type
    }

    /// Exact executable payload length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// SHA-256 of the exact executable payload.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Whether `module` is exactly the payload represented by this identity.
    #[must_use]
    pub fn matches(&self, module: &[u8]) -> bool {
        self.byte_length == module.len() as u64 && self.sha256 == sha256(module)
    }

    /// Whether this executable was independently signed by a trusted key.
    #[must_use]
    pub const fn has_trusted_signature(&self) -> bool {
        self.trusted_signer.is_some()
    }

    /// Trusted signer of this exact executable, when verification established one.
    #[must_use]
    pub const fn trusted_signer(&self) -> Option<[u8; 32]> {
        self.trusted_signer
    }
}

/// Identity of a metadata payload whose content hash and signature both
/// verified against a caller-supplied trusted key.
///
/// Hosted platform policy must be signer-bound rather than inferred from an
/// unsigned `META` segment. Retaining only this digest lets a host bind the
/// exact policy bytes it later parses without retaining arbitrary metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedMetadata {
    /// Ordinal assigned by the RVF writer.
    segment_id: u64,
    /// Exact metadata payload length.
    byte_length: u64,
    /// SHA-256 of the metadata payload bytes.
    sha256: [u8; 32],
    /// Trusted Ed25519 public key that signed this exact metadata segment.
    trusted_signer: [u8; 32],
}

impl VerifiedMetadata {
    /// Ordinal assigned by the RVF writer.
    #[must_use]
    pub const fn segment_id(&self) -> u64 {
        self.segment_id
    }

    /// Exact metadata payload length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// SHA-256 of the exact metadata payload.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Trusted signer of this exact metadata payload.
    #[must_use]
    pub const fn trusted_signer(&self) -> [u8; 32] {
        self.trusted_signer
    }

    /// Whether `metadata` is exactly the payload represented by this identity.
    #[must_use]
    pub fn matches(&self, metadata: &[u8]) -> bool {
        self.byte_length == metadata.len() as u64 && self.sha256 == sha256(metadata)
    }
}

/// The full result of verifying one artifact.
///
/// Carries no timestamp: two verifications of the same bytes under the same
/// options produce identical reports, which is what makes a report comparable
/// across backends.
///
/// Trust-bearing fields are intentionally opaque. Safe downstream code may
/// inspect a report but cannot fabricate a passing result or substitute an
/// executable identity:
///
/// ```compile_fail
/// fn forge(report: &mut rvm_rvf::VerificationReport) {
///     report.ok = true;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// SHA-256 of the whole container — the canonical `rvfIdentity`.
    pub(crate) rvf_identity: [u8; 32],
    /// Container size in bytes.
    pub(crate) byte_length: u64,
    /// True when no record failed.
    pub(crate) ok: bool,
    /// How many segments were examined.
    pub(crate) segment_count: usize,
    /// Executable payload identities retained for verify-before-load binding.
    /// They become execution-eligible only when [`Self::ok`] is true.
    pub(crate) executables: Vec<VerifiedExecutable>,
    /// Signer-bound `META` payload identities. Unsigned metadata and metadata
    /// whose signature was skipped are deliberately absent.
    pub(crate) verified_metadata: Vec<VerifiedMetadata>,
    /// Trusted signer of the selected root manifest, if one was established.
    pub(crate) trusted_root_signer: Option<[u8; 32]>,
    /// One record per check performed, in check order.
    pub(crate) records: Vec<VerificationRecord>,
    /// The default-deny capability mapping this artifact resolves to.
    ///
    /// When the capability check failed, this is the deny-everything mapping:
    /// a refused artifact grants nothing.
    pub(crate) capabilities: CapabilityMapping,
    /// Every size limit the container exceeded.
    pub(crate) size_violations: Vec<SizeViolation>,
}

impl VerificationReport {
    /// SHA-256 of the whole verified container.
    #[must_use]
    pub const fn rvf_identity(&self) -> &[u8; 32] {
        &self.rvf_identity
    }

    /// Container size in bytes.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Whether every required verification check passed.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.ok
    }

    /// Number of parsed segments.
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Verified executable identities retained for verify-before-load binding.
    #[must_use]
    pub fn executables(&self) -> &[VerifiedExecutable] {
        &self.executables
    }

    /// Signer-bound metadata identities.
    #[must_use]
    pub fn verified_metadata(&self) -> &[VerifiedMetadata] {
        &self.verified_metadata
    }

    /// Trusted signer of the selected root manifest, when established.
    #[must_use]
    pub const fn trusted_root_signer(&self) -> Option<[u8; 32]> {
        self.trusted_root_signer
    }

    /// Ordered verification witness records.
    #[must_use]
    pub fn records(&self) -> &[VerificationRecord] {
        &self.records
    }

    /// Default-deny capability mapping derived by verification.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilityMapping {
        &self.capabilities
    }

    /// Signed size-policy violations.
    #[must_use]
    pub fn size_violations(&self) -> &[SizeViolation] {
        &self.size_violations
    }

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
            if self.records.iter().any(|record| {
                record.check == CheckKind::CapabilityMapping
                    && record.detail == DetailCode::CapabilityUnknown
            }) {
                return Err(RvfError::UnknownCapability);
            }
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
    /// signature checks are recorded as skipped rather than passed — an
    /// unverifiable signature is never treated as a valid one.
    pub trusted_keys: Vec<[u8; 32]>,
    /// Permit executable segments with no signature. Off by default; exists
    /// for unsigned development builds, which are labeled as such and are not
    /// eligible for distribution.
    pub allow_unsigned_executable: bool,
    /// When set, the container's SHA-256 must equal this value.
    ///
    /// Hosted execution must set this: the v1 MANIFEST payload has no
    /// canonical full segment directory, so signatures alone do not prevent
    /// remixing independently signed segments from the same publisher.
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
    let root_page = root_manifest_page(data)?;
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
    append_root_page_records(
        &mut records,
        data,
        root_page.as_ref(),
        root_manifest(&segments),
        opts,
    );

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
    let executables = segments
        .iter()
        .filter(|seg| seg.is_executable())
        .map(|seg| VerifiedExecutable {
            segment_id: seg.header.segment_id,
            segment_type: seg.header.seg_type,
            byte_length: seg.header.payload_length,
            sha256: sha256(seg.payload(data)),
            trusted_signer: trusted_signer_for(data, seg, opts),
        })
        .collect();
    let verified_metadata = segments
        .iter()
        .filter(|seg| seg.header.seg_type == crate::format::SEG_TYPE_META)
        .filter(|seg| {
            records.iter().any(|record| {
                record.segment_index == Some(seg.index)
                    && record.segment_id == Some(seg.header.segment_id)
                    && record.check == CheckKind::ContentHash
                    && record.outcome == Outcome::Pass
            }) && records.iter().any(|record| {
                record.segment_index == Some(seg.index)
                    && record.segment_id == Some(seg.header.segment_id)
                    && record.check == CheckKind::Signature
                    && record.outcome == Outcome::Pass
            })
        })
        .filter_map(|seg| {
            trusted_signer_for(data, seg, opts).map(|trusted_signer| VerifiedMetadata {
                segment_id: seg.header.segment_id,
                byte_length: seg.header.payload_length,
                sha256: sha256(seg.payload(data)),
                trusted_signer,
            })
        })
        .collect();
    let trusted_root_signer =
        trusted_root_signer(data, root_manifest(&segments), root_page.as_ref(), opts);
    Ok(VerificationReport {
        rvf_identity: identity,
        byte_length: data.len() as u64,
        ok,
        segment_count: segments.len(),
        executables,
        verified_metadata,
        trusted_root_signer,
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

fn append_root_page_records(
    records: &mut Vec<VerificationRecord>,
    data: &[u8],
    page: Option<&RootManifestPage>,
    root: Option<&ParsedSegment>,
    opts: &VerifyOptions,
) {
    let Some(page) = page else {
        return;
    };
    records.push(container_record(
        CheckKind::RootPageIntegrity,
        Outcome::Pass,
        DetailCode::RootPageIntegrityValid,
    ));
    records.push(root_page_binding_record(page, root));
    records.push(root_page_signature_record(data, page, opts));
    records.push(root_signer_binding_record(data, page, root, opts));
}

fn root_page_binding_record(
    page: &RootManifestPage,
    root: Option<&ParsedSegment>,
) -> VerificationRecord {
    let matches = root.is_some_and(|segment| root_page_binds(page, segment));
    container_record(
        CheckKind::RootPageBinding,
        outcome(matches),
        if matches {
            DetailCode::RootPageBindingMatches
        } else {
            DetailCode::RootPageBindingMismatch
        },
    )
}

fn root_page_binds(page: &RootManifestPage, root: &ParsedSegment) -> bool {
    let Ok(start) = usize::try_from(page.l1_manifest_offset) else {
        return false;
    };
    let Ok(length) = usize::try_from(page.l1_manifest_length) else {
        return false;
    };
    let Some(end) = start.checked_add(length) else {
        return false;
    };

    let embedded = page.range.start >= root.payload.start && page.range.end <= root.payload.end;
    if embedded {
        // `rvf-manifest` places the Level-1 TLV immediately before the page,
        // both inside the selected MANIFEST payload.
        length != 0
            && page.range.end == root.payload.end
            && start >= root.payload.start
            && end == page.range.start
    } else {
        // RVForge's hosted-agent shape appends a standalone page whose pointer
        // names the complete encoded MANIFEST segment.
        page.range.start == root.encoded.end
            && start == root.encoded.start
            && end == root.encoded.end
    }
}

fn root_page_signature_record(
    data: &[u8],
    page: &RootManifestPage,
    opts: &VerifyOptions,
) -> VerificationRecord {
    if page.signature_algo == 0 && page.signature_length == 0 {
        return container_record(
            CheckKind::RootPageSignature,
            Outcome::Skip,
            DetailCode::RootPageUnsigned,
        );
    }
    if page.signature_algo != ROOT_SIG_ALGO_ED25519 || page.signature_length != 64 {
        return container_record(
            CheckKind::RootPageSignature,
            Outcome::Fail,
            DetailCode::UnsupportedSignatureAlgorithm,
        );
    }
    if opts.trusted_keys.is_empty() {
        return container_record(
            CheckKind::RootPageSignature,
            Outcome::Skip,
            DetailCode::NoTrustedKey,
        );
    }

    let verified = trusted_signer_for_root_page(data, page, &opts.trusted_keys).is_some();
    container_record(
        CheckKind::RootPageSignature,
        outcome(verified),
        if verified {
            DetailCode::SignatureVerifies
        } else {
            DetailCode::SignatureRejected
        },
    )
}

fn root_signer_binding_record(
    data: &[u8],
    page: &RootManifestPage,
    root: Option<&ParsedSegment>,
    opts: &VerifyOptions,
) -> VerificationRecord {
    let root_declares_signature = root.is_some_and(ParsedSegment::is_signed);
    let page_declares_signature = page.signature_algo != 0 || page.signature_length != 0;
    if !root_declares_signature && !page_declares_signature {
        return container_record(
            CheckKind::RootSignerBinding,
            Outcome::Skip,
            DetailCode::RootSignerBindingUnavailable,
        );
    }
    if root_declares_signature != page_declares_signature {
        return container_record(
            CheckKind::RootSignerBinding,
            Outcome::Fail,
            DetailCode::RootSignerBindingMismatch,
        );
    }
    if opts.trusted_keys.is_empty() {
        return container_record(
            CheckKind::RootSignerBinding,
            Outcome::Skip,
            DetailCode::RootSignerBindingUnavailable,
        );
    }

    let root_signer = root.and_then(|segment| trusted_signer_for(data, segment, opts));
    let page_signer = trusted_signer_for_root_page(data, page, &opts.trusted_keys);
    let matches = root_signer.is_some() && root_signer == page_signer;
    container_record(
        CheckKind::RootSignerBinding,
        outcome(matches),
        if matches {
            DetailCode::RootSignerBindingMatches
        } else {
            DetailCode::RootSignerBindingMismatch
        },
    )
}

fn trusted_root_signer(
    data: &[u8],
    root: Option<&ParsedSegment>,
    page: Option<&RootManifestPage>,
    opts: &VerifyOptions,
) -> Option<[u8; 32]> {
    let root = root?;
    let root_signer = trusted_signer_for(data, root, opts)?;
    let Some(page) = page else {
        return Some(root_signer);
    };
    if !root_page_binds(page, root) {
        return None;
    }
    let page_signer = trusted_signer_for_root_page(data, page, &opts.trusted_keys)?;
    (page_signer == root_signer).then_some(root_signer)
}

fn trusted_signer_for_root_page(
    data: &[u8],
    page: &RootManifestPage,
    trusted: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if page.signature_algo != ROOT_SIG_ALGO_ED25519 || page.signature_length != 64 {
        return None;
    }
    let raw_signature = <[u8; 64]>::try_from(page.signature(data)).ok()?;
    let signature = Signature::from_bytes(&raw_signature);
    let mut signed = [0u8; ROOT_MANIFEST_SIZE];
    signed.copy_from_slice(page.bytes(data));
    signed[ROOT_SIGNATURE_OFFSET..ROOT_SIGNATURE_OFFSET + 64].fill(0);
    signed[ROOT_CHECKSUM_OFFSET..].fill(0);

    trusted.iter().copied().find(|raw| {
        VerifyingKey::from_bytes(raw)
            .is_ok_and(|key| key.verify_strict(&signed, &signature).is_ok())
    })
}

fn capability_records(
    data: &[u8],
    segments: &[ParsedSegment],
) -> (CapabilityMapping, VerificationRecord) {
    if has_unknown_class_name(data, segments) {
        return (
            map_declared(&[]).unwrap_or_else(|_| unreachable!("the empty declaration always maps")),
            container_record(
                CheckKind::CapabilityMapping,
                Outcome::Fail,
                DetailCode::CapabilityUnknown,
            ),
        );
    }
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
    if !is_supported_content_hash(seg.header.checksum_algo) {
        return segment_record(
            CheckKind::ContentHash,
            Outcome::Fail,
            seg,
            DetailCode::UnsupportedContentHashAlgorithm,
        );
    }
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
            if seg.is_executable() {
                Outcome::Fail
            } else {
                Outcome::Skip
            },
            seg,
            DetailCode::UnsupportedSignatureAlgorithm,
        );
    }
    if opts.trusted_keys.is_empty() {
        return segment_record(
            CheckKind::Signature,
            if seg.is_executable() && !opts.allow_unsigned_executable {
                Outcome::Fail
            } else {
                Outcome::Skip
            },
            seg,
            DetailCode::NoTrustedKey,
        );
    }

    let verified =
        trusted_signer_for_footer(data, seg, footer.signature, &opts.trusted_keys).is_some();
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

/// Whether any trusted key signed this segment.
fn trusted_signer_for(data: &[u8], seg: &ParsedSegment, opts: &VerifyOptions) -> Option<[u8; 32]> {
    let range = seg.footer.clone()?;
    let footer = decode_signature_footer(&data[range]).ok()?;
    if footer.sig_algo != SIG_ALGO_ED25519 || footer.sig_length != ED25519_SIGNATURE_LENGTH {
        return None;
    }
    trusted_signer_for_footer(data, seg, footer.signature, &opts.trusted_keys)
}

fn trusted_signer_for_footer(
    data: &[u8],
    seg: &ParsedSegment,
    sig_bytes: &[u8],
    trusted: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else {
        return None;
    };
    let signature = Signature::from_bytes(&sig_array);
    let message = crate::format::build_signed_message(&seg.header, seg.payload(data));

    trusted.iter().copied().find(|raw| {
        VerifyingKey::from_bytes(raw)
            .is_ok_and(|key| key.verify_strict(&message, &signature).is_ok())
    })
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
