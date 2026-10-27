//! A verified streaming session: bytes in, a startable module out.
//!
//! [`StreamSession`] joins the three stages ADR-160 puts between a socket and
//! an agent slot:
//!
//! ```text
//! frames -> StreamAdmission -> WASM payload -> StreamingModuleValidator -> VerifiedModule
//!           (authenticate +     (only released     (limits from signed
//!            ADR-155 rules)      payload bytes)     SizePolicy)
//! ```
//!
//! # Why it lives in `rvm-launch`
//!
//! It must name three things at once: the admission layer (`rvm-rvf`), the
//! module validator (`rvm-wasm`), and the instances that a poisoned stream has
//! to terminate (`rvm-launch`). `rvm-host` sits below `Instance` and cannot
//! name it; `rvm-rvf` and `rvm-wasm` must not depend on each other. `rvm-launch`
//! is the lowest crate that sees all three, and it already owns the lifecycle
//! that `start_verified` extends.
//!
//! # When a module becomes available
//!
//! [`StreamSession::take_module`] returns a [`VerifiedModule`](crate::VerifiedModule) only after the
//! stream is `Complete` and admission produced a passing report. That is
//! stricter than ADR-160 item 5 (which only requires the module's own segment
//! to be verified): the capability mapping and the root-manifest rule are
//! package-level facts that need the whole descriptor's worth of segments. A
//! stage-ordered stream could release a component earlier; this session does
//! not, and says so rather than guessing at a partial package.
//!
//! # Identity
//!
//! Chunks that arrive in stage order cannot be hashed in file order, so the
//! stream completes with an `Unverifiable` identity. [`take_module`] refuses
//! such a session ([`SessionError::IdentityUnverified`]) until
//! [`finish_identity`] has re-read the persisted body and matched it to the
//! signed `rvf_identity`; the status is readable at [`identity_status`].
//!
//! # Poison
//!
//! A poisoned stream is terminal ([`SessionState::Poisoned`]). The session
//! drops every byte it derived from the stream and refuses [`take_module`].
//! What it granted and started is the host's to undo, and the session says
//! exactly what: [`take_obligation`] returns a [`PoisonObligation`](crate::PoisonObligation) naming the
//! capabilities this session installed and the instances it started. There is
//! no global epoch bump and no selection by descriptor hash: a junk frame on
//! one link, or a replayed one, can end that session and nothing else.
//!
//! # Replay protection
//!
//! The session records `(epoch, descriptor_hash)` into the policy's
//! [`PinStore`](rvm_rvf::stream::PinStore) exactly once, when the stream is
//! `Complete`, its identity is verified and the package passed admission.
//!
//! # Frame buffering
//!
//! [`push`](StreamSession::push) takes a whole frame the caller already
//! buffered. [`feed`](StreamSession::feed) takes arbitrary byte splits and
//! checks every declared frame size against limits derived from the signed
//! descriptor before buffering anything, so a hostile size claim costs the
//! policy bound at most.
//!
//! [`take_module`]: StreamSession::take_module
//! [`finish_identity`]: StreamSession::finish_identity
//! [`identity_status`]: StreamSession::identity_status
//! [`take_obligation`]: StreamSession::take_obligation

use crate::stream_session_types::{PoisonReport, SessionError, SessionEvent, SessionState};
use crate::stream_target::Witnessed;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rvm_host::VerifiedPackage;
use rvm_rvf::stream::witness::{binding_of, emit_event, push_witnessed_with, StreamEvent};
use rvm_rvf::stream::{
    AdmissionError, AdmissionEvent, FrameReader, IdentityStatus, PoisonInfo, ReplayProtection,
    StreamAdmission, StreamPolicy, StreamState,
};
use rvm_rvf::{SizePolicy, VerificationReport, VerifyOptions, WitnessContext};
use rvm_wasm::{ModuleError, ModulePolicy, StreamingModuleValidator};
use rvm_witness::WitnessLog;

/// The `seg_type` of a WASM runtime segment.
const SEG_TYPE_WASM: u8 = rvm_rvf::format::SEG_TYPE_WASM;

/// Session ids are handed out from here: unique within the process (for the
/// first 2^32 sessions), never derived from anything the transport controls.
static NEXT_SESSION: AtomicU32 = AtomicU32::new(1);

/// Writes a stream event to the caller's witness log.
pub(crate) type Emit<'a> = Option<&'a dyn Fn(&StreamEvent, &[u8; 32])>;

pub(crate) struct ExecProgress {
    validator: StreamingModuleValidator,
    bytes: Vec<u8>,
}

/// The module validation limits a signed [`SizePolicy`] implies.
///
/// `base` supplies the structural limits (function body size, locals, the
/// import policy, the largest buffered section); the signed policy supplies
/// the module size: `max_runtime_bytes`, which may exceed the 1 MiB constant.
/// A section is never allowed to be larger than the module itself.
/// [`rvm_wasm::MAX_MODULE_SIZE`] stays the executor backstop at start (ADR-155
/// section 4), so a module the policy admits but the backstop refuses is
/// witnessed and refused there, not here.
#[must_use]
pub fn module_policy_for(size: &SizePolicy, base: ModulePolicy) -> ModulePolicy {
    let limit = usize::try_from(size.max_runtime_bytes).unwrap_or(usize::MAX);
    ModulePolicy {
        max_module_bytes: limit,
        max_section_bytes: limit.min(base.max_section_bytes),
        ..base
    }
}

/// Stream in, startable module out. See the [module documentation](self).
pub struct StreamSession<'p> {
    pub(crate) admission: StreamAdmission<'p>,
    pub(crate) module_policy: ModulePolicy,
    pub(crate) replay: ReplayProtection<'p>,
    pub(crate) session_id: u64,
    pub(crate) reader: FrameReader,
    pub(crate) exec: BTreeMap<u64, ExecProgress>,
    pub(crate) ready: BTreeMap<u64, (Vec<u8>, rvm_wasm::ValidatedModule)>,
    pub(crate) package: Option<VerifiedPackage>,
    pub(crate) pending_package: Option<VerifiedPackage>,
    pub(crate) state: SessionState,
    pub(crate) failure: Option<SessionError>,
    pub(crate) poison: Option<PoisonReport>,
    pub(crate) installed: Vec<(u32, u32)>,
    pub(crate) obligation_issued: bool,
    pub(crate) pin_recorded: bool,
}

impl<'p> StreamSession<'p> {
    /// A session whose module limits derive from `policy.size` and `base`.
    #[must_use]
    pub fn new(policy: StreamPolicy<'p>, opts: VerifyOptions, base: ModulePolicy) -> Self {
        let module_policy = module_policy_for(&policy.size, base);
        Self::with_module_policy(policy, opts, module_policy)
    }

    /// A session with exactly `module_policy`, not derived from the size
    /// policy.
    #[must_use]
    pub fn with_module_policy(
        policy: StreamPolicy<'p>,
        opts: VerifyOptions,
        module_policy: ModulePolicy,
    ) -> Self {
        Self {
            replay: policy.replay,
            admission: StreamAdmission::new(policy, opts),
            module_policy,
            session_id: u64::from(NEXT_SESSION.fetch_add(1, Ordering::Relaxed)),
            reader: FrameReader::new(),
            exec: BTreeMap::new(),
            ready: BTreeMap::new(),
            package: None,
            pending_package: None,
            state: SessionState::Receiving,
            failure: None,
            poison: None,
            installed: Vec::new(),
            obligation_issued: false,
            pin_recorded: false,
        }
    }

    /// This session's id: what instances started from it remember.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// The session state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// The first failure, if the session failed.
    #[must_use]
    pub const fn failure(&self) -> Option<&SessionError> {
        self.failure.as_ref()
    }

    /// The admission report, once the stream completed.
    #[must_use]
    pub fn report(&self) -> Option<&VerificationReport> {
        self.admission.report()
    }

    /// The verified package, once the stream completed, passed admission and
    /// its identity is verified. An `Unverifiable` stage-ordered completion
    /// exposes no package until [`Self::finish_identity`] succeeds: nothing is
    /// derived from an identity the signer merely claimed.
    #[must_use]
    pub const fn package(&self) -> Option<&VerifiedPackage> {
        self.package.as_ref()
    }

    /// The verifier's view of the stream.
    #[must_use]
    pub fn stream_state(&self) -> StreamState {
        self.admission.state()
    }

    /// Whether the package identity was checked against the body:
    /// `Some(Verified)` once it was, `Some(Unverifiable)` after a stage-ordered
    /// completion until [`Self::finish_identity`] succeeds.
    #[must_use]
    pub fn identity_status(&self) -> Option<IdentityStatus> {
        self.admission.verifier().identity_status()
    }

    /// The hash of the signed descriptor, once accepted.
    #[must_use]
    pub fn descriptor_hash(&self) -> Option<[u8; 32]> {
        self.admission
            .verifier()
            .descriptor()
            .map(|d| d.descriptor_hash)
    }

    /// Why the stream was poisoned, once it is.
    #[must_use]
    pub const fn poison(&self) -> Option<&PoisonReport> {
        self.poison.as_ref()
    }

    /// Accept one complete, already-buffered frame. To bound what is buffered
    /// before a frame is judged, use [`Self::feed`].
    ///
    /// # Errors
    ///
    /// The frame was refused, or a module in it failed validation. Nothing
    /// refused reaches the validator or the module buffer.
    pub fn push(&mut self, frame: &[u8]) -> Result<SessionEvent, SessionError> {
        if self.state != SessionState::Receiving {
            return Err(SessionError::Unusable);
        }
        let result = self.admission.push(frame);
        self.after(result, None)
    }

    /// [`Self::push`], writing the stream's witness records: the descriptor
    /// verdict, each verified segment, each counted fault, module validation,
    /// completion (only once the package has been admitted), the failing checks
    /// of a refused package, and poisoning.
    ///
    /// # Errors
    ///
    /// As [`Self::push`]; the records are in the log either way.
    pub fn push_witnessed<const N: usize>(
        &mut self,
        frame: &[u8],
        log: &WitnessLog<N>,
        ctx: WitnessContext,
    ) -> Result<SessionEvent, SessionError> {
        if self.state != SessionState::Receiving {
            return Err(SessionError::Unusable);
        }
        let result = push_witnessed_with(&mut self.admission, frame, log, ctx, false);
        self.after(
            result,
            Some(&|ev: &StreamEvent, b: &[u8; 32]| {
                emit_event(ev, b, log, ctx);
            }),
        )
    }

    /// Accept bytes in arbitrary splits. Frames are reassembled one at a time
    /// and each declared size is checked against limits derived from the signed
    /// descriptor *before* a payload byte is buffered, so a size lie costs at
    /// most the policy bound. `sink` receives the result of every completed
    /// frame.
    ///
    /// # Errors
    ///
    /// The stream can accept no more input, or a header declared an illegal
    /// size or an unknown frame type (the stream is poisoned).
    pub fn feed(
        &mut self,
        data: &[u8],
        sink: impl FnMut(Result<SessionEvent, SessionError>),
    ) -> Result<(), SessionError> {
        let mut reader = core::mem::take(&mut self.reader);
        let r = reader.feed(self, data, sink);
        self.reader = reader;
        self.check_poisoned();
        r.map_err(|e| SessionError::Stream(AdmissionError::Stream(e)))
    }

    /// [`Self::feed`] with the witness records of [`Self::push_witnessed`],
    /// including the reader-level poison a size lie causes.
    ///
    /// # Errors
    ///
    /// As [`Self::feed`].
    pub fn feed_witnessed<const N: usize>(
        &mut self,
        data: &[u8],
        log: &WitnessLog<N>,
        ctx: WitnessContext,
        sink: impl FnMut(Result<SessionEvent, SessionError>),
    ) -> Result<(), SessionError> {
        let mut reader = core::mem::take(&mut self.reader);
        let mut target = Witnessed {
            session: self,
            log,
            ctx,
        };
        let r = reader.feed(&mut target, data, sink);
        self.reader = reader;
        self.check_poisoned();
        r.map_err(|e| SessionError::Stream(AdmissionError::Stream(e)))
    }

    fn after(
        &mut self,
        result: Result<AdmissionEvent<'_>, AdmissionError>,
        witness: Emit<'_>,
    ) -> Result<SessionEvent, SessionError> {
        let ev = match result {
            Ok(ev) => ev,
            Err(e) => {
                self.check_poisoned();
                return Err(SessionError::Stream(e));
            }
        };
        let (out, complete) = match ev {
            AdmissionEvent::DescriptorVerified { .. } => (SessionEvent::Descriptor, false),
            AdmissionEvent::TableVerified { .. } => (SessionEvent::Table, false),
            AdmissionEvent::Duplicate { seg_id, .. } => (SessionEvent::Duplicate { seg_id }, false),
            AdmissionEvent::Unverified { seg_id, .. } => {
                (SessionEvent::Unverified { seg_id }, false)
            }
            AdmissionEvent::DuplicateDescriptor => (SessionEvent::DuplicateDescriptor, false),
            AdmissionEvent::Chunk {
                chunk,
                payload,
                segment_verified,
                stage_verified,
                complete,
                ..
            } => {
                if chunk.seg_type == SEG_TYPE_WASM {
                    if let Err(e) =
                        self.feed_module(chunk.seg_id, payload, segment_verified, witness)
                    {
                        self.fail(e.clone());
                        return Err(e);
                    }
                }
                (
                    SessionEvent::Chunk {
                        seg_id: chunk.seg_id,
                        segment_verified,
                        stage_verified,
                    },
                    complete.is_some(),
                )
            }
        };
        if complete {
            return self.on_complete(witness);
        }
        Ok(out)
    }

    fn feed_module(
        &mut self,
        seg_id: u64,
        payload: &[u8],
        segment_verified: bool,
        witness: Emit<'_>,
    ) -> Result<(), SessionError> {
        let policy = &self.module_policy;
        let progress = self.exec.entry(seg_id).or_insert_with(|| ExecProgress {
            validator: StreamingModuleValidator::new(policy.clone()),
            bytes: Vec::new(),
        });
        let binding = binding_of(&self.admission).unwrap_or([0; 32]);
        let reject = |error: ModuleError| {
            if let Some(w) = witness {
                w(&StreamEvent::ModuleRejected { seg_id }, &binding);
            }
            SessionError::Module { seg_id, error }
        };
        if !payload.is_empty() {
            progress.validator.push(payload).map_err(reject)?;
            progress.bytes.extend_from_slice(payload);
        }
        if segment_verified {
            let done = self.exec.remove(&seg_id).expect("module in progress");
            let validated = done.validator.finish().map_err(reject)?;
            if let Some(w) = witness {
                w(&StreamEvent::ModuleValidated { seg_id }, &binding);
            }
            self.ready.insert(seg_id, (done.bytes, validated));
        }
        Ok(())
    }

    fn on_complete(&mut self, witness: Emit<'_>) -> Result<SessionEvent, SessionError> {
        let package = self
            .admission
            .report()
            .and_then(|r| VerifiedPackage::from_report(r).ok());
        let Some(p) = package else {
            // The failing checks were written by the witnessed push; the
            // refusal itself is the session's failure.
            self.fail(SessionError::PackageRefused);
            return Err(SessionError::PackageRefused);
        };
        if let (Some(w), Some(b)) = (witness, binding_of(&self.admission)) {
            w(&StreamEvent::StreamComplete, &b);
        }
        self.pending_package = Some(p);
        self.state = SessionState::Complete;
        self.promote(witness)?;
        Ok(SessionEvent::Complete)
    }

    pub(crate) fn fail(&mut self, e: SessionError) {
        self.state = SessionState::Failed;
        self.exec.clear();
        self.ready.clear();
        self.package = None;
        self.pending_package = None;
        // A report built before this refusal (the final chunk completed the stream
        // before module validation or the replay check ran) must not stay `ok`.
        self.admission.refuse_report();
        self.failure = Some(e);
    }

    pub(crate) fn check_poisoned(&mut self) {
        if let StreamState::Poisoned(reason) = self.admission.state() {
            if self.poison.is_none() {
                let info = self
                    .admission
                    .verifier()
                    .poison_info()
                    .unwrap_or(PoisonInfo {
                        seg_id: None,
                        chunk_index: 0,
                        reason,
                    });
                self.poison = Some(PoisonReport {
                    descriptor_hash: self.descriptor_hash(),
                    info,
                });
            }
            self.state = SessionState::Poisoned;
            self.exec.clear();
            self.ready.clear();
            self.package = None;
            self.pending_package = None;
            self.admission.discard_derived_state();
        }
    }
}
