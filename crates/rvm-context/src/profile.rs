//! Deterministic RVF profile binding progressive context views to segments.
//!
//! The canonical RVF registry already assigns `PROFILE_SEG` (`0x0B`). This
//! module defines a versioned payload for that existing segment and does not
//! mint RVM-only RVF discriminants. A `ruv://` revision always identifies the
//! complete RVF by SHA-256; the profile only maps abstract, overview, and
//! content views to verified segment IDs inside those bytes.

use crate::uri::{ProgressiveView, Revision};
use alloc::vec::Vec;
use rvm_rvf::{
    sha256, verify, walk, CheckKind, Outcome, VerificationReport, VerifyOptions, SEG_TYPE_PROFILE,
};

/// Magic at the start of a `ruv.context/1` RVF profile payload.
pub const CONTEXT_PROFILE_MAGIC: [u8; 4] = *b"RUVC";

/// Version of the context profile payload.
pub const CONTEXT_PROFILE_VERSION: u8 = 1;

/// Maximum complete RVF size accepted by the v1 context profile verifier.
pub const MAX_CONTEXT_RVF_BYTES: usize = 16 * 1024 * 1024;

const HEADER_SIZE: usize = 8;
const VIEW_RECORD_SIZE: usize = 204;
const MAX_VIEWS: usize = 3;

/// Trust requirement applied to the RVF profile segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTrust {
    /// Require the profile segment's signature check to have passed against a
    /// trusted Ed25519 key in the supplied `rvm-rvf` verification report.
    TrustedSignature,
    /// Accept an unsigned profile because its complete RVF identity was
    /// authenticated out of band and supplied as `expected_identity`.
    PinnedIdentity,
}

/// Failure while decoding or binding a context profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextProfileError {
    /// The byte payload has the wrong magic, version, length, or reserved bits.
    Encoding(&'static str),
    /// A profile does not contain exactly one content view.
    ContentViewRequired,
    /// The same progressive view occurs more than once.
    DuplicateView,
    /// Two views name the same RVF segment.
    DuplicateSegment,
    /// A derived representation has missing or inconsistent provenance.
    InvalidProvenance,
    /// A zero digest was used where a content identity is required.
    ZeroDigest,
    /// The supplied RVF verification report did not pass.
    UnverifiedRvf,
    /// The report, bytes, and expected whole-RVF identity do not agree.
    IdentityMismatch,
    /// The RVF does not contain exactly one readable context profile segment.
    ProfileSegment,
    /// A trusted signature was required but did not pass for the profile.
    UntrustedProfile,
    /// A view names no unique, uncompressed RVF segment.
    ViewSegment,
    /// A view's SHA-256 digest does not match its segment payload.
    ViewDigestMismatch,
    /// The supplied bytes are not a structurally valid RVF.
    InvalidRvf,
    /// The complete RVF exceeds the context ingress ceiling.
    RvfTooLarge,
}

impl core::fmt::Display for ContextProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(message) => write!(f, "context profile encoding: {message}"),
            Self::ContentViewRequired => f.write_str("context profile needs one content view"),
            Self::DuplicateView => f.write_str("context profile repeats a view"),
            Self::DuplicateSegment => f.write_str("context profile repeats a segment"),
            Self::InvalidProvenance => f.write_str("derived view provenance is invalid"),
            Self::ZeroDigest => f.write_str("context profile contains a zero digest"),
            Self::UnverifiedRvf => f.write_str("RVF verification report did not pass"),
            Self::IdentityMismatch => f.write_str("RVF identity does not match pinned revision"),
            Self::ProfileSegment => f.write_str("RVF context profile segment is invalid"),
            Self::UntrustedProfile => f.write_str("RVF context profile is not trusted"),
            Self::ViewSegment => f.write_str("context view segment is unavailable"),
            Self::ViewDigestMismatch => f.write_str("context view payload digest does not match"),
            Self::InvalidRvf => f.write_str("bytes are not a valid RVF"),
            Self::RvfTooLarge => f.write_str("RVF exceeds the context ingress limit"),
        }
    }
}

/// Provenance required for a derived progressive view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedView {
    /// SHA-256 digest of the full content bytes this view summarizes.
    source: Revision,
    /// Identity of the deterministic generator implementation.
    generator: Revision,
    /// Identity of the model or algorithm weights.
    model: Revision,
    /// Digest of the exact prompt or transformation configuration.
    prompt: Revision,
    /// Digest of the policy governing generation and disclosure.
    policy: Revision,
}

impl DerivedView {
    /// Construct a complete derived-view provenance binding.
    ///
    /// # Errors
    ///
    /// Refuses an all-zero digest, which is reserved as the absent sentinel in
    /// the fixed profile encoding.
    pub fn new(
        source: Revision,
        generator: Revision,
        model: Revision,
        prompt: Revision,
        policy: Revision,
    ) -> Result<Self, ContextProfileError> {
        for digest in [source, generator, model, prompt, policy] {
            if is_zero(digest) {
                return Err(ContextProfileError::ZeroDigest);
            }
        }
        Ok(Self {
            source,
            generator,
            model,
            prompt,
            policy,
        })
    }

    /// Return the source content digest.
    #[must_use]
    pub const fn source(self) -> Revision {
        self.source
    }

    /// Return the generator implementation identity.
    #[must_use]
    pub const fn generator(self) -> Revision {
        self.generator
    }

    /// Return the model or algorithm identity.
    #[must_use]
    pub const fn model(self) -> Revision {
        self.model
    }

    /// Return the prompt or transformation digest.
    #[must_use]
    pub const fn prompt(self) -> Revision {
        self.prompt
    }

    /// Return the generation policy digest.
    #[must_use]
    pub const fn policy(self) -> Revision {
        self.policy
    }
}

/// Mapping from one progressive view to an RVF segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileView {
    /// Abstract, overview, or full content.
    view: ProgressiveView,
    /// RVF segment ordinal containing the representation bytes.
    segment_id: u64,
    /// SHA-256 digest of the exact stored segment payload.
    payload: Revision,
    /// Required derivation binding for abstract and overview views.
    derived: Option<DerivedView>,
}

impl ProfileView {
    /// Construct the authoritative full-content mapping.
    ///
    /// # Errors
    ///
    /// Refuses segment ID zero and a zero payload digest.
    pub fn content(segment_id: u64, payload: Revision) -> Result<Self, ContextProfileError> {
        if segment_id == 0 {
            return Err(ContextProfileError::ViewSegment);
        }
        if is_zero(payload) {
            return Err(ContextProfileError::ZeroDigest);
        }
        Ok(Self {
            view: ProgressiveView::Content,
            segment_id,
            payload,
            derived: None,
        })
    }

    /// Construct an abstract or overview mapping with provenance.
    ///
    /// # Errors
    ///
    /// Refuses `content` as a derived selector, segment ID zero, or a zero
    /// payload digest.
    pub fn derived(
        view: ProgressiveView,
        segment_id: u64,
        payload: Revision,
        derived: DerivedView,
    ) -> Result<Self, ContextProfileError> {
        if view == ProgressiveView::Content || segment_id == 0 {
            return Err(ContextProfileError::InvalidProvenance);
        }
        if is_zero(payload) {
            return Err(ContextProfileError::ZeroDigest);
        }
        Ok(Self {
            view,
            segment_id,
            payload,
            derived: Some(derived),
        })
    }

    /// Return the progressive view selector.
    #[must_use]
    pub const fn view(&self) -> ProgressiveView {
        self.view
    }

    /// Return the referenced RVF segment ordinal.
    #[must_use]
    pub const fn segment_id(&self) -> u64 {
        self.segment_id
    }

    /// Return the digest of the exact stored segment payload.
    #[must_use]
    pub const fn payload(&self) -> Revision {
        self.payload
    }

    /// Return provenance for an abstract or overview representation.
    #[must_use]
    pub const fn provenance(&self) -> Option<DerivedView> {
        self.derived
    }
}

/// Canonical `ruv.context/1` profile decoded from an RVF `PROFILE_SEG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextProfile {
    views: Vec<ProfileView>,
}

impl ContextProfile {
    /// Validate and canonicalize view mappings into L0, L1, L2 order.
    ///
    /// # Errors
    ///
    /// Refuses missing or duplicate views, duplicate segment IDs, zero
    /// digests, and derived views not bound to the content digest.
    pub fn new(mut views: Vec<ProfileView>) -> Result<Self, ContextProfileError> {
        if views.is_empty() || views.len() > MAX_VIEWS {
            return Err(ContextProfileError::ContentViewRequired);
        }
        views.sort_by_key(|view| view.view);
        for pair in views.windows(2) {
            if pair[0].view == pair[1].view {
                return Err(ContextProfileError::DuplicateView);
            }
        }
        for (index, view) in views.iter().enumerate() {
            if view.segment_id == 0 || is_zero(view.payload) {
                return Err(ContextProfileError::ViewSegment);
            }
            if views[..index]
                .iter()
                .any(|prior| prior.segment_id == view.segment_id)
            {
                return Err(ContextProfileError::DuplicateSegment);
            }
        }
        let content = views
            .iter()
            .find(|view| view.view == ProgressiveView::Content)
            .ok_or(ContextProfileError::ContentViewRequired)?;
        if content.derived.is_some() {
            return Err(ContextProfileError::InvalidProvenance);
        }
        for view in &views {
            if view.view != ProgressiveView::Content {
                let derived = view.derived.ok_or(ContextProfileError::InvalidProvenance)?;
                for digest in [
                    derived.source,
                    derived.generator,
                    derived.model,
                    derived.prompt,
                    derived.policy,
                ] {
                    if is_zero(digest) {
                        return Err(ContextProfileError::ZeroDigest);
                    }
                }
                if derived.source != content.payload {
                    return Err(ContextProfileError::InvalidProvenance);
                }
            }
        }
        Ok(Self { views })
    }

    /// Progressive view mappings in canonical abstract, overview, content order.
    #[must_use]
    pub fn views(&self) -> &[ProfileView] {
        &self.views
    }

    /// Return one progressive view mapping.
    #[must_use]
    pub fn view(&self, requested: ProgressiveView) -> Option<&ProfileView> {
        self.views.iter().find(|view| view.view == requested)
    }

    /// Encode the deterministic fixed-record profile payload.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.views.len() * VIEW_RECORD_SIZE);
        out.extend_from_slice(&CONTEXT_PROFILE_MAGIC);
        out.push(CONTEXT_PROFILE_VERSION);
        out.push(u8::try_from(self.views.len()).unwrap_or(0));
        out.extend_from_slice(&[0; 2]);
        for view in &self.views {
            encode_view(&mut out, view);
        }
        out
    }

    /// Decode and validate a deterministic profile payload.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical byte length, order, reserved values, digest
    /// sentinels, and invalid derivation bindings.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ContextProfileError> {
        if data.len() < HEADER_SIZE || data[..4] != CONTEXT_PROFILE_MAGIC {
            return Err(ContextProfileError::Encoding(
                "wrong magic or truncated header",
            ));
        }
        if data[4] != CONTEXT_PROFILE_VERSION {
            return Err(ContextProfileError::Encoding("unsupported version"));
        }
        if data[6..8] != [0; 2] {
            return Err(ContextProfileError::Encoding(
                "reserved header bytes are nonzero",
            ));
        }
        let count = usize::from(data[5]);
        if count == 0 || count > MAX_VIEWS || data.len() != HEADER_SIZE + count * VIEW_RECORD_SIZE {
            return Err(ContextProfileError::Encoding("wrong view count or length"));
        }
        let mut views = Vec::with_capacity(count);
        for index in 0..count {
            let start = HEADER_SIZE + index * VIEW_RECORD_SIZE;
            views.push(decode_view(&data[start..start + VIEW_RECORD_SIZE])?);
        }
        let profile = Self::new(views)?;
        if profile.to_bytes() != data {
            return Err(ContextProfileError::Encoding("noncanonical view order"));
        }
        Ok(profile)
    }
}

/// Profile proven to belong to a particular complete RVF identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContextProfile {
    rvf_identity: Revision,
    profile: ContextProfile,
    segments: Vec<BoundSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundSegment {
    view: ProgressiveView,
    segment_type: u8,
    start: usize,
    end: usize,
}

impl VerifiedContextProfile {
    /// Verify an RVF and bind its decoded profile to a pinned identity.
    ///
    /// This operation only inspects and hashes bytes. It does not map or
    /// execute any referenced segment. Verification is performed internally;
    /// callers cannot supply a forgeable success report. `trusted_keys` are
    /// the Ed25519 publisher keys accepted when `trust` requires a signature.
    ///
    /// # Errors
    ///
    /// Refuses an unsuccessful or replayed report, a missing or unsigned
    /// profile under the selected trust posture, ambiguous segment mappings,
    /// compression, and payload digest mismatches.
    pub fn from_rvf(
        data: &[u8],
        expected_identity: Revision,
        trust: ProfileTrust,
        trusted_keys: &[[u8; 32]],
    ) -> Result<Self, ContextProfileError> {
        if data.len() > MAX_CONTEXT_RVF_BYTES {
            return Err(ContextProfileError::RvfTooLarge);
        }
        let mut options = VerifyOptions::with_trusted_keys(trusted_keys.to_vec())
            .expect_identity(*expected_identity.as_bytes());
        if trust == ProfileTrust::PinnedIdentity {
            // The complete byte identity is the out-of-band trust anchor in
            // this posture. Execution remains separately capability-gated and
            // the launch boundary must still apply its own publisher policy.
            options.allow_unsigned_executable = true;
        }
        let report = verify(data, &options).map_err(|_| ContextProfileError::InvalidRvf)?;
        Self::bind_verified(data, &report, expected_identity, trust)
    }

    fn bind_verified(
        data: &[u8],
        report: &VerificationReport,
        expected_identity: Revision,
        trust: ProfileTrust,
    ) -> Result<Self, ContextProfileError> {
        let actual = sha256(data);
        if actual != *report.rvf_identity() || actual != *expected_identity.as_bytes() {
            return Err(ContextProfileError::IdentityMismatch);
        }
        if !report.is_ok() {
            return Err(ContextProfileError::UnverifiedRvf);
        }
        let segments = walk(data).map_err(|_| ContextProfileError::InvalidRvf)?;
        let mut profiles = segments
            .iter()
            .filter(|segment| segment.header.seg_type == SEG_TYPE_PROFILE);
        let profile_segment = profiles.next().ok_or(ContextProfileError::ProfileSegment)?;
        if profiles.next().is_some()
            || profile_segment.header.is_encrypted()
            || profile_segment.header.compression != 0
        {
            return Err(ContextProfileError::ProfileSegment);
        }
        if trust == ProfileTrust::TrustedSignature {
            let signature_passed = profile_segment.header.is_signed()
                && report.records().iter().any(|record| {
                    record.check == CheckKind::Signature
                        && record.outcome == Outcome::Pass
                        && record.segment_index == Some(profile_segment.index)
                        && record.segment_id == Some(profile_segment.header.segment_id)
                });
            if !signature_passed {
                return Err(ContextProfileError::UntrustedProfile);
            }
        }

        let profile = ContextProfile::from_bytes(profile_segment.payload(data))?;
        let mut bound = Vec::with_capacity(profile.views().len());
        for view in profile.views() {
            let mut matching = segments
                .iter()
                .filter(|segment| segment.header.segment_id == view.segment_id);
            let segment = matching.next().ok_or(ContextProfileError::ViewSegment)?;
            if matching.next().is_some()
                || segment.header.seg_type == SEG_TYPE_PROFILE
                || segment.header.compression != 0
            {
                return Err(ContextProfileError::ViewSegment);
            }
            if view.view != ProgressiveView::Content && segment.header.is_executable() {
                return Err(ContextProfileError::ViewSegment);
            }
            if sha256(segment.payload(data)) != *view.payload.as_bytes() {
                return Err(ContextProfileError::ViewDigestMismatch);
            }
            bound.push(BoundSegment {
                view: view.view,
                segment_type: segment.header.seg_type,
                start: segment.payload.start,
                end: segment.payload.end,
            });
        }

        Ok(Self {
            rvf_identity: expected_identity,
            profile,
            segments: bound,
        })
    }

    /// Complete RVF identity suitable for a pinned `ruv://` revision.
    #[must_use]
    pub const fn rvf_identity(&self) -> Revision {
        self.rvf_identity
    }

    /// Decoded progressive view profile.
    #[must_use]
    pub const fn profile(&self) -> &ContextProfile {
        &self.profile
    }

    /// Whether the mapped segment is executable code.
    #[must_use]
    pub fn is_executable(&self, view: ProgressiveView) -> bool {
        self.segments
            .iter()
            .find(|segment| segment.view == view)
            .is_some_and(|segment| rvm_rvf::is_executable(segment.segment_type))
    }

    /// Borrow one verified stored representation from the same RVF bytes.
    ///
    /// This is inspection only. Returning executable bytes does not execute
    /// them and does not confer RVM `EXECUTE` authority.
    ///
    /// # Errors
    ///
    /// Refuses different RVF bytes or a view absent from the profile.
    pub fn payload<'a>(
        &self,
        data: &'a [u8],
        view: ProgressiveView,
    ) -> Result<&'a [u8], ContextProfileError> {
        if sha256(data) != *self.rvf_identity.as_bytes() {
            return Err(ContextProfileError::IdentityMismatch);
        }
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.view == view)
            .ok_or(ContextProfileError::ViewSegment)?;
        data.get(segment.start..segment.end)
            .ok_or(ContextProfileError::ViewSegment)
    }
}

fn encode_view(out: &mut Vec<u8>, view: &ProfileView) {
    out.push(view_code(view.view));
    out.push(u8::from(view.derived.is_some()));
    out.extend_from_slice(&[0; 2]);
    out.extend_from_slice(&view.segment_id.to_le_bytes());
    out.extend_from_slice(view.payload.as_bytes());
    if let Some(derived) = view.derived {
        for digest in [
            derived.source,
            derived.generator,
            derived.model,
            derived.prompt,
            derived.policy,
        ] {
            out.extend_from_slice(digest.as_bytes());
        }
    } else {
        out.extend_from_slice(&[0; 160]);
    }
}

fn decode_view(data: &[u8]) -> Result<ProfileView, ContextProfileError> {
    if data.len() != VIEW_RECORD_SIZE || data[2..4] != [0; 2] {
        return Err(ContextProfileError::Encoding("view record is malformed"));
    }
    let view = match data[0] {
        0 => ProgressiveView::Abstract,
        1 => ProgressiveView::Overview,
        2 => ProgressiveView::Content,
        _ => return Err(ContextProfileError::Encoding("unknown view")),
    };
    let segment_id = u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]));
    let payload = Revision::from_bytes(array32(data, 12));
    match data[1] {
        0 => {
            if data[44..].iter().any(|byte| *byte != 0) {
                return Err(ContextProfileError::Encoding(
                    "absent provenance is nonzero",
                ));
            }
            Ok(ProfileView {
                view,
                segment_id,
                payload,
                derived: None,
            })
        }
        1 => Ok(ProfileView {
            view,
            segment_id,
            payload,
            derived: Some(DerivedView::new(
                Revision::from_bytes(array32(data, 44)),
                Revision::from_bytes(array32(data, 76)),
                Revision::from_bytes(array32(data, 108)),
                Revision::from_bytes(array32(data, 140)),
                Revision::from_bytes(array32(data, 172)),
            )?),
        }),
        _ => Err(ContextProfileError::Encoding("invalid provenance flag")),
    }
}

const fn view_code(view: ProgressiveView) -> u8 {
    match view {
        ProgressiveView::Abstract => 0,
        ProgressiveView::Overview => 1,
        ProgressiveView::Content => 2,
    }
}

fn is_zero(revision: Revision) -> bool {
    revision.as_bytes().iter().all(|byte| *byte == 0)
}

fn array32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[offset..offset + 32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer, SigningKey};
    use rvm_rvf::{
        content_hash, SegmentHeader, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
    };

    const SEG_TYPE_META: u8 = 0x07;
    const SEG_TYPE_MANIFEST: u8 = 0x05;

    fn revision(byte: u8) -> Revision {
        Revision::from_bytes([byte; 32])
    }

    fn profile() -> ContextProfile {
        let content_bytes = b"full content";
        let content = Revision::from_bytes(sha256(content_bytes));
        let overview = ProfileView::derived(
            ProgressiveView::Overview,
            2,
            Revision::from_bytes(sha256(b"overview")),
            DerivedView::new(content, revision(2), revision(3), revision(4), revision(5)).unwrap(),
        )
        .unwrap();
        ContextProfile::new(vec![ProfileView::content(1, content).unwrap(), overview]).unwrap()
    }

    fn segment(segment_type: u8, segment_id: u64, payload: &[u8]) -> Vec<u8> {
        let total = SEGMENT_HEADER_SIZE + payload.len();
        let padded = total.div_ceil(64) * 64;
        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            seg_type: segment_type,
            flags: 0,
            segment_id,
            payload_length: u64::try_from(payload.len()).unwrap(),
            timestamp_ns: segment_id,
            checksum_algo: 2,
            compression: 0,
            reserved_0: 0,
            reserved_1: 0,
            content_hash: content_hash(2, payload),
            uncompressed_len: 0,
            alignment_pad: u32::try_from(padded - total).unwrap(),
        };
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes.resize(padded, 0);
        bytes
    }

    fn signed_segment(
        segment_type: u8,
        segment_id: u64,
        payload: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32]) {
        use rvm_rvf::format::{
            build_signed_message, compute_footer_length, FLAG_SIGNED, SIG_ALGO_ED25519,
        };

        let footer_length = usize::try_from(compute_footer_length(64)).unwrap();
        let total = SEGMENT_HEADER_SIZE + payload.len() + footer_length;
        let padded = total.div_ceil(64) * 64;
        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            seg_type: segment_type,
            flags: FLAG_SIGNED,
            segment_id,
            payload_length: u64::try_from(payload.len()).unwrap(),
            timestamp_ns: segment_id,
            checksum_algo: 2,
            compression: 0,
            reserved_0: 0,
            reserved_1: 0,
            content_hash: content_hash(2, payload),
            uncompressed_len: 0,
            alignment_pad: u32::try_from(padded - total).unwrap(),
        };
        let secret = sha256(&[seed; 32]);
        let signing_key = SigningKey::from_bytes(&secret);
        let signature = signing_key
            .sign(&build_signed_message(&header, payload))
            .to_bytes();
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&SIG_ALGO_ED25519.to_le_bytes());
        bytes.extend_from_slice(&64u16.to_le_bytes());
        bytes.extend_from_slice(&signature);
        bytes.extend_from_slice(&compute_footer_length(64).to_le_bytes());
        bytes.resize(padded, 0);
        (bytes, signing_key.verifying_key().to_bytes())
    }

    fn rvf(profile: &ContextProfile) -> Vec<u8> {
        let mut bytes = segment(SEG_TYPE_META, 1, b"full content");
        bytes.extend(segment(SEG_TYPE_META, 2, b"overview"));
        bytes.extend(segment(SEG_TYPE_PROFILE, 3, &profile.to_bytes()));
        bytes.extend(segment(SEG_TYPE_MANIFEST, 4, b"root"));
        bytes
    }

    fn signed_profile_rvf(profile: &ContextProfile, seed: u8) -> (Vec<u8>, [u8; 32]) {
        let mut bytes = segment(SEG_TYPE_META, 1, b"full content");
        bytes.extend(segment(SEG_TYPE_META, 2, b"overview"));
        let (signed_profile, public_key) =
            signed_segment(SEG_TYPE_PROFILE, 3, &profile.to_bytes(), seed);
        bytes.extend(signed_profile);
        bytes.extend(segment(SEG_TYPE_MANIFEST, 4, b"root"));
        (bytes, public_key)
    }

    #[test]
    fn deterministic_profile_round_trip() {
        let profile = profile();
        let encoded = profile.to_bytes();
        assert_eq!(ContextProfile::from_bytes(&encoded).unwrap(), profile);
        assert_eq!(profile.views()[0].view, ProgressiveView::Overview);
        assert_eq!(profile.views()[1].view, ProgressiveView::Content);
    }

    #[test]
    fn derived_view_must_bind_the_content_digest() {
        let derived = DerivedView::new(
            revision(9),
            revision(2),
            revision(3),
            revision(4),
            revision(5),
        )
        .unwrap();
        let result = ContextProfile::new(vec![
            ProfileView::content(1, revision(1)).unwrap(),
            ProfileView::derived(ProgressiveView::Abstract, 2, revision(6), derived).unwrap(),
        ]);
        assert_eq!(result, Err(ContextProfileError::InvalidProvenance));
    }

    #[test]
    fn pinned_rvf_identity_binds_verified_view_bytes() {
        let profile = profile();
        let data = rvf(&profile);
        let identity = Revision::from_bytes(sha256(&data));
        let verified =
            VerifiedContextProfile::from_rvf(&data, identity, ProfileTrust::PinnedIdentity, &[])
                .unwrap();
        assert_eq!(
            verified.payload(&data, ProgressiveView::Overview).unwrap(),
            b"overview"
        );
        assert!(!verified.is_executable(ProgressiveView::Content));
    }

    #[test]
    fn different_identity_and_unsigned_trust_are_refused() {
        let data = rvf(&profile());
        let identity = Revision::from_bytes(sha256(&data));
        assert_eq!(
            VerifiedContextProfile::from_rvf(
                &data,
                revision(99),
                ProfileTrust::PinnedIdentity,
                &[],
            ),
            Err(ContextProfileError::IdentityMismatch)
        );
        assert_eq!(
            VerifiedContextProfile::from_rvf(&data, identity, ProfileTrust::TrustedSignature, &[],),
            Err(ContextProfileError::UntrustedProfile)
        );
    }

    #[test]
    fn trusted_profile_is_verified_internally_against_publisher_keys() {
        let (data, trusted_key) = signed_profile_rvf(&profile(), 7);
        let identity = Revision::from_bytes(sha256(&data));
        let verified = VerifiedContextProfile::from_rvf(
            &data,
            identity,
            ProfileTrust::TrustedSignature,
            &[trusted_key],
        )
        .unwrap();
        assert_eq!(verified.rvf_identity(), identity);

        assert_eq!(
            VerifiedContextProfile::from_rvf(
                &data,
                identity,
                ProfileTrust::TrustedSignature,
                &[[0x44; 32]],
            ),
            Err(ContextProfileError::UnverifiedRvf)
        );
    }

    #[test]
    fn profile_payload_hash_mismatch_is_refused() {
        let mut profile = profile();
        profile.views[0].payload = revision(0x44);
        let data = rvf(&profile);
        let identity = Revision::from_bytes(sha256(&data));
        assert_eq!(
            VerifiedContextProfile::from_rvf(&data, identity, ProfileTrust::PinnedIdentity, &[],),
            Err(ContextProfileError::ViewDigestMismatch)
        );
    }
}
