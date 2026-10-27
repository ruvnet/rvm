//! Streamed admission: the ADR-155 loading rules applied to released chunks.
//!
//! [`StreamVerifier`] proves that bytes are the bytes a trusted signer
//! committed to. That is authenticity, not admission: ADR-155 also requires
//! the root manifest, a signed executable, matching content hashes, the size
//! policy and a capability mapping. [`StreamAdmission`] wraps the verifier,
//! checks each segment incrementally as its chunks are released, and at
//! `Complete` builds the very [`VerificationReport`] [`crate::verify()`] would
//! have produced for the same body, with the same records in the same order.
//!
//! Executable and metadata payloads are handed to the consumer chunk by chunk
//! ([`AdmissionEvent::Chunk::payload`]) so an incremental module validator can
//! run while bytes arrive. Memory beyond the verifier's is a few hasher states
//! per segment that is open, the plaintext `META` payloads, and one small
//! record per segment.

use super::descriptor::{FLAG_IDENTITY_PRESENT, SEG_TYPE_ROOT_PAGE};
use super::error::StreamError;
use super::events::{Event, IdentityStatus, StreamState, VerifiedChunk};
use super::frame::FrameTarget;
use super::segment::{SegmentChecker, SegmentFault};
use super::verifier::StreamVerifier;
use super::StreamPolicy;
use crate::container::{is_level0_page, ParsedSegment, ROOT_PAGE_SIZE};
use crate::error::RvfError;
use crate::format::SEG_TYPE_META;
use crate::report::{build_report, Declarations, Delivery, ReportInput, SegmentFacts};
use crate::verify::{VerificationReport, VerifyOptions};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Why admission refused, beyond what the verifier itself refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// The frame was refused by the stream verifier.
    Stream(StreamError),
    /// A released segment is not a well-formed RVF segment; [`crate::verify()`]
    /// would return this error for the same body. The stream is poisoned.
    Malformed {
        /// The segment.
        seg_id: u64,
        /// What is wrong with it.
        error: RvfError,
    },
    /// A segment header disagrees with its signed table entry. The stream is
    /// poisoned.
    DescriptorMismatch {
        /// The segment.
        seg_id: u64,
    },
    /// The descriptor carries no `rvf_identity`, which admission needs to
    /// bind the package to its lineage (ADR-155 section 5).
    IdentityRequired,
    /// More segments were open at once than the policy allows. The stream is
    /// poisoned.
    TooManyOpenSegments,
}

impl AdmissionError {
    /// The stream-level reason this failure is recorded under.
    #[must_use]
    pub const fn reason(&self) -> StreamError {
        match self {
            Self::Stream(e) => *e,
            Self::Malformed { .. } => StreamError::SegmentMalformed,
            Self::DescriptorMismatch { .. } => StreamError::SegmentMismatch,
            Self::IdentityRequired => StreamError::IdentityRequired,
            Self::TooManyOpenSegments => StreamError::TooManyOpenSegments,
        }
    }
}

impl From<StreamError> for AdmissionError {
    fn from(e: StreamError) -> Self {
        Self::Stream(e)
    }
}

impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Stream(e) => write!(f, "stream refused the frame: {e}"),
            Self::Malformed { seg_id, error } => write!(f, "segment {seg_id} malformed: {error}"),
            Self::DescriptorMismatch { seg_id } => {
                write!(f, "segment {seg_id} header contradicts the signed table")
            }
            Self::IdentityRequired => f.write_str("descriptor carries no rvf_identity"),
            Self::TooManyOpenSegments => f.write_str("too many segments open at once"),
        }
    }
}

/// What a frame produced, after admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionEvent<'a> {
    /// The descriptor was accepted.
    DescriptorVerified {
        /// SHA-256 of the signed descriptor.
        descriptor_hash: [u8; 32],
        /// Number of segments.
        seg_count: u32,
        /// Total body bytes.
        body_len: u64,
    },
    /// A chunk table matched its commitment.
    TableVerified {
        /// Segment id.
        seg_id: u64,
    },
    /// A repeat of an already-verified chunk or table; ignored.
    Duplicate {
        /// Segment id.
        seg_id: u64,
        /// Chunk index (0 for a table).
        chunk_index: u32,
    },
    /// A late chunk of a finished multi-chunk segment; unverifiable, ignored.
    Unverified {
        /// Segment id.
        seg_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// The descriptor frame was repeated byte for byte; ignored.
    DuplicateDescriptor,
    /// A chunk was released.
    Chunk {
        /// The released chunk (the whole stored-segment slice).
        chunk: VerifiedChunk<'a>,
        /// The part of the chunk inside the segment payload; empty for the
        /// header, signature footer and padding.
        payload: &'a [u8],
        /// Offset of `payload[0]` within the segment payload.
        payload_offset: u64,
        /// This chunk completed its segment.
        segment_verified: bool,
        /// This chunk completed its stage.
        stage_verified: Option<u8>,
        /// Set when this chunk completed the stream.
        complete: Option<IdentityStatus>,
    },
}

/// A [`StreamVerifier`] plus the ADR-155 loading rules.
pub struct StreamAdmission<'p> {
    verifier: StreamVerifier<'p>,
    opts: VerifyOptions,
    max_open: usize,
    open: BTreeMap<u32, SegmentChecker>,
    done: Vec<Option<(ParsedSegment, SegmentFacts)>>,
    meta: BTreeMap<u32, Vec<u8>>,
    report: Option<VerificationReport>,
    failure: Option<AdmissionError>,
}

impl<'p> StreamAdmission<'p> {
    /// Admission waiting for the descriptor frame. `opts` supplies the trusted
    /// segment-signing keys and the policy the report's records are built
    /// under; `policy` supplies the stream limits and the descriptor trust.
    #[must_use]
    pub fn new(policy: StreamPolicy<'p>, opts: VerifyOptions) -> Self {
        Self {
            max_open: policy.max_open_segments,
            verifier: StreamVerifier::new(policy),
            opts,
            open: BTreeMap::new(),
            done: Vec::new(),
            meta: BTreeMap::new(),
            report: None,
            failure: None,
        }
    }

    /// The wrapped verifier.
    #[must_use]
    pub const fn verifier(&self) -> &StreamVerifier<'p> {
        &self.verifier
    }

    /// The verifier's state.
    #[must_use]
    pub const fn state(&self) -> StreamState {
        self.verifier.state()
    }

    /// The report, once the stream completed and admission did not fail.
    #[must_use]
    pub const fn report(&self) -> Option<&VerificationReport> {
        self.report.as_ref()
    }

    /// Mark the report refused after a later gate (module validation, replay)
    /// failed. The report stays readable to explain the failure, but it must
    /// never read `ok`, because `VerifiedPackage::from_report` trusts that flag.
    pub fn refuse_report(&mut self) {
        if let Some(r) = self.report.as_mut() {
            r.ok = false;
        }
    }

    /// Take the report.
    #[must_use]
    pub fn into_report(self) -> Option<VerificationReport> {
        self.report
    }

    /// The first admission-level failure, if any.
    #[must_use]
    pub const fn failure(&self) -> Option<AdmissionError> {
        self.failure
    }

    /// Accept one complete frame.
    ///
    /// # Errors
    ///
    /// The frame was refused (by the verifier or by a segment rule); nothing
    /// from it reaches the consumer.
    pub fn push<'a>(&mut self, frame: &'a [u8]) -> Result<AdmissionEvent<'a>, AdmissionError> {
        if let Some(f) = self.failure {
            return Err(f);
        }
        match self.verifier.push(frame)? {
            Event::DescriptorVerified {
                descriptor_hash,
                seg_count,
                body_len,
            } => {
                let n = seg_count as usize;
                self.done = (0..n).map(|_| None).collect();
                Ok(AdmissionEvent::DescriptorVerified {
                    descriptor_hash,
                    seg_count,
                    body_len,
                })
            }
            Event::TableVerified { seg_id } => Ok(AdmissionEvent::TableVerified { seg_id }),
            Event::DuplicateDescriptor => Ok(AdmissionEvent::DuplicateDescriptor),
            Event::Unverified {
                seg_id,
                chunk_index,
            } => Ok(AdmissionEvent::Unverified {
                seg_id,
                chunk_index,
            }),
            Event::Duplicate {
                seg_id,
                chunk_index,
            } => Ok(AdmissionEvent::Duplicate {
                seg_id,
                chunk_index,
            }),
            Event::Chunk {
                chunk,
                segment_verified,
                stage_verified,
                complete,
            } => self
                .admit(chunk, segment_verified, complete)
                .map(|(payload, payload_offset)| AdmissionEvent::Chunk {
                    chunk,
                    payload,
                    payload_offset,
                    segment_verified,
                    stage_verified,
                    complete,
                }),
        }
    }

    /// Poison the wrapped verifier from outside (a reader-level size lie).
    pub fn verifier_poison(&mut self, reason: StreamError) -> StreamError {
        self.verifier.poison(reason)
    }

    /// [`StreamVerifier::finish_identity`] on the wrapped verifier.
    ///
    /// # Errors
    ///
    /// As the verifier; a mismatch poisons the stream.
    pub fn finish_identity(
        &mut self,
        read_at: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<(), StreamError> {
        self.verifier.finish_identity(read_at)
    }

    /// Drop everything derived from released bytes: open segment checkers,
    /// collected metadata and finished segment facts.
    ///
    /// A live stream cannot continue without that state, so calling this on
    /// one poisons it first (`StreamBadState`) instead of leaving a later
    /// panic. A stream that is already terminal is left as it is.
    pub fn discard_derived_state(&mut self) {
        if !matches!(
            self.verifier.state(),
            StreamState::Poisoned(_) | StreamState::Rejected(_)
        ) {
            self.verifier.poison(StreamError::BadState);
        }
        self.open.clear();
        self.meta.clear();
        self.done.clear();
        self.report = None;
    }

    fn fail(&mut self, e: AdmissionError, seg: Option<u64>, chunk: u32) -> AdmissionError {
        self.verifier.force_poison(e.reason(), seg, chunk);
        self.discard_derived_state();
        self.failure = Some(e);
        e
    }

    fn admit<'a>(
        &mut self,
        chunk: VerifiedChunk<'a>,
        segment_verified: bool,
        complete: Option<IdentityStatus>,
    ) -> Result<(&'a [u8], u64), AdmissionError> {
        let seg_id = chunk.seg_id;
        let (entry_idx, entries) = {
            let d = self.verifier.descriptor().expect("descriptor installed");
            (
                d.find(seg_id).expect("released chunk has an entry"),
                d.entries.len(),
            )
        };
        let i = entry_idx as u32;
        if chunk.seg_type == SEG_TYPE_ROOT_PAGE {
            return self.admit_root_page(chunk, complete);
        }
        if chunk.chunk_index == 0 && !self.open.contains_key(&i) {
            if self.open.len() >= self.max_open {
                return Err(self.fail(
                    AdmissionError::TooManyOpenSegments,
                    Some(seg_id),
                    chunk.chunk_index,
                ));
            }
            let entry = self
                .verifier
                .descriptor()
                .expect("descriptor installed")
                .entries[entry_idx];
            let (stored, uncompressed) = (entry.stored_len, entry.uncompressed_len);
            self.open.insert(
                i,
                SegmentChecker::new(
                    seg_id,
                    chunk.seg_type,
                    chunk.body_offset,
                    stored,
                    uncompressed,
                ),
            );
        }
        let Some(checker) = self.open.get_mut(&i) else {
            return Err(self.fail(
                AdmissionError::DescriptorMismatch { seg_id },
                Some(seg_id),
                chunk.chunk_index,
            ));
        };
        let span = match checker.push(chunk.bytes) {
            Ok(s) => s,
            Err(f) => return Err(self.fail(fault(seg_id, f), Some(seg_id), chunk.chunk_index)),
        };
        let payload = &chunk.bytes[span.start..span.end];
        if let Some(h) = checker.header() {
            if h.seg_type == SEG_TYPE_META && !h.is_encrypted() {
                self.meta.entry(i).or_default().extend_from_slice(payload);
            }
        }
        if segment_verified {
            let checker = self.open.remove(&i).expect("open segment");
            let root_last = self
                .verifier
                .descriptor()
                .expect("descriptor installed")
                .entries
                .last()
                .is_some_and(|e| e.seg_type == SEG_TYPE_ROOT_PAGE);
            let is_last = entry_idx + 1 == entries - usize::from(root_last);
            match checker.finish(entry_idx, is_last) {
                Ok(done) => self.done[entry_idx] = Some(done),
                Err(f) => return Err(self.fail(fault(seg_id, f), Some(seg_id), chunk.chunk_index)),
            }
        }
        if complete.is_some() {
            self.finish_report(complete)?;
        }
        Ok((payload, span.payload_offset))
    }

    fn admit_root_page<'a>(
        &mut self,
        chunk: VerifiedChunk<'a>,
        complete: Option<IdentityStatus>,
    ) -> Result<(&'a [u8], u64), AdmissionError> {
        let seg_id = chunk.seg_id;
        let bad = chunk.chunk_index == 0
            && (!is_level0_page(chunk.bytes) || self.root_page_len() != ROOT_PAGE_SIZE as u64);
        if bad {
            return Err(self.fail(
                AdmissionError::Malformed {
                    seg_id,
                    error: RvfError::TrailingBytes,
                },
                Some(seg_id),
                0,
            ));
        }
        if complete.is_some() {
            self.finish_report(complete)?;
        }
        Ok((&chunk.bytes[..0], 0))
    }

    fn root_page_len(&self) -> u64 {
        self.verifier
            .descriptor()
            .and_then(|d| d.entries.last())
            .map_or(0, |e| e.stored_len)
    }

    fn finish_report(&mut self, complete: Option<IdentityStatus>) -> Result<(), AdmissionError> {
        let (header, mut segments, mut facts) = {
            let d = self.verifier.descriptor().expect("descriptor installed");
            (d.header, Vec::new(), Vec::new())
        };
        if header.flags & FLAG_IDENTITY_PRESENT == 0 || complete == Some(IdentityStatus::NotPresent)
        {
            return Err(self.fail(AdmissionError::IdentityRequired, None, 0));
        }
        for slot in &mut self.done {
            if let Some((seg, f)) = slot.take() {
                segments.push(seg);
                facts.push(f);
            }
        }
        if segments.is_empty() {
            return Err(self.fail(
                AdmissionError::Malformed {
                    seg_id: 0,
                    error: RvfError::NoSegments,
                },
                None,
                0,
            ));
        }
        let meta_payloads = self.meta.values().map(Vec::as_slice).collect();
        let report = build_report(
            &ReportInput {
                identity: header.rvf_identity,
                container_bytes: header.body_len,
                segments: &segments,
                facts: &facts,
                meta: Declarations { meta_payloads },
                delivery: Delivery::Streamed,
            },
            &self.opts,
        );
        self.report = Some(report);
        Ok(())
    }
}

fn fault(seg_id: u64, f: SegmentFault) -> AdmissionError {
    match f {
        SegmentFault::Malformed(error) => AdmissionError::Malformed { seg_id, error },
        SegmentFault::DescriptorMismatch => AdmissionError::DescriptorMismatch { seg_id },
    }
}

impl FrameTarget for StreamAdmission<'_> {
    type Out<'a> = AdmissionEvent<'a>;
    type Error = AdmissionError;

    fn state(&self) -> StreamState {
        self.verifier.state()
    }

    fn frame_payload_limit(&self, frame_type: u8) -> u64 {
        self.verifier.frame_payload_limit(frame_type)
    }

    fn poison(&mut self, reason: StreamError) -> StreamError {
        self.verifier.poison(reason)
    }

    fn push_frame<'a>(&mut self, frame: &'a [u8]) -> Result<AdmissionEvent<'a>, AdmissionError> {
        self.push(frame)
    }
}

impl FrameTarget for StreamVerifier<'_> {
    type Out<'a> = Event<'a>;
    type Error = StreamError;

    fn state(&self) -> StreamState {
        Self::state(self)
    }

    fn frame_payload_limit(&self, frame_type: u8) -> u64 {
        Self::frame_payload_limit(self, frame_type)
    }

    fn poison(&mut self, reason: StreamError) -> StreamError {
        Self::poison(self, reason)
    }

    fn push_frame<'a>(&mut self, frame: &'a [u8]) -> Result<Event<'a>, StreamError> {
        self.push(frame)
    }
}
