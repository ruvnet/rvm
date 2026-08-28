//! Effective grant evaluation and governed native dispatch.

use crate::{
    receipt::AgentExecutionContext, AgentExecutionLimits, AgentExecutionOutcome,
    AgentExecutionSeal, HostedIosProfile, IosAuthorization, IosPlatformFacts, IosPolicy, IosScope,
    ReceiptChain, ReceiptEvent, ReceiptIntegrityError, ReceiptSessionIdentity,
};
use sha2::{Digest, Sha256};

const OPERATOR_POLICY_DOMAIN: &[u8] = b"RVM-HOSTED-IOS-OPERATOR-POLICY-V1";

/// Guest-visible result for a denied, well-formed scope request.
pub const IOS_GUEST_DENIED: i64 = -1;
/// Guest-visible result for an unknown scope code or malformed arguments.
pub const IOS_GUEST_INVALID_SCOPE: i64 = -2;
/// Stable native failure recorded when a callback completes after its
/// requested admission deadline. This does not imply callback preemption.
pub const IOS_NATIVE_DEADLINE_EXCEEDED: u32 = u32::MAX - 1;
/// Absolute call allowance admitted for one scope in a runtime session.
pub const MAX_IOS_CALLS_PER_SCOPE: u64 = 32_768;
/// Absolute abstract work-unit allowance admitted for one native operation.
pub const MAX_IOS_UNITS_PER_CALL: u64 = 1 << 40;
/// Absolute requested-duration allowance admitted for one native operation.
pub const MAX_IOS_DURATION_MS: u32 = 30_000;

/// Host-asserted source class for executable RVF bytes.
///
/// Stock App Store integrations must use [`Self::EmbeddedAppBundle`]. This
/// Rust type records and authenticates the assertion but cannot inspect the
/// native application bundle or its code signature by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IosArtifactOrigin {
    /// Exact bytes embedded in and identity-pinned by the signed app bundle.
    EmbeddedAppBundle = 1,
    /// Explicit local development/test artifact; not an App Store execution path.
    DevelopmentOnly = 2,
}

/// Stable reason recorded for every HostedIOS decision/outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IosReason {
    /// All package, operator, platform, and budget gates passed.
    Allowed = 1,
    /// Signed RVF policy did not request the scope.
    ManifestMissing = 2,
    /// Operator policy did not enable the scope or resource.
    OperatorDenied = 3,
    /// OS authorization is `notDetermined`; UI may request it, but it is not granted.
    OsPermissionNotDetermined = 4,
    /// OS authorization is denied or restricted.
    OsPermissionDenied = 5,
    /// Required hardware/API is unavailable.
    PlatformUnsupported = 6,
    /// Calls, work units, or duration exceed the operator envelope.
    BudgetExceeded = 7,
    /// Request was malformed or lacked a required resource digest.
    InvalidRequest = 8,
    /// Thermal state is serious, critical, or unknown for this accelerator path.
    ThermalDenied = 9,
    /// Native bridge returned an application-specific failure.
    NativeFailure = 10,
    /// The host monotonic clock moved backward; native work was not started or
    /// its already-completed outcome was retained with a clamped timestamp.
    ClockRegression = 11,
    /// The runtime could not reserve its bounded evidence store before use.
    EvidenceUnavailable = 12,
    /// Whole-container identity is not the exact artifact pinned by local policy.
    AgentIdentityDenied = 13,
    /// The host did not evidence explicit consent for the sensor session.
    UserConsentMissing = 14,
    /// The host did not evidence a visible or audible recording indicator.
    RecordingIndicatorMissing = 15,
}

/// Per-operation and per-session limits supplied by local operator policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosBudget {
    /// Maximum calls to each scope in one runtime session.
    pub max_calls_per_scope: u64,
    /// Maximum abstract work/sample/byte units in one call.
    pub max_units_per_call: u64,
    /// Maximum requested duration in milliseconds.
    pub max_duration_ms: u32,
    /// Maximum in-memory receipt records in one session.
    pub max_receipts: usize,
}

impl IosBudget {
    /// Conservative default for a short governed edge-agent turn.
    pub const DEFAULT: Self = Self {
        max_calls_per_scope: 256,
        max_units_per_call: 1_000_000,
        max_duration_ms: 30_000,
        max_receipts: 8_192,
    };

    fn valid(self) -> bool {
        (1..=MAX_IOS_CALLS_PER_SCOPE).contains(&self.max_calls_per_scope)
            && (1..=MAX_IOS_UNITS_PER_CALL).contains(&self.max_units_per_call)
            && (1..=MAX_IOS_DURATION_MS).contains(&self.max_duration_ms)
            && (2..=65_536).contains(&self.max_receipts)
    }
}

impl Default for IosBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Local policy intersected with signed artifact policy and iOS facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosOperatorPolicy {
    allowed_scopes: Vec<IosScope>,
    allowed_resources: Vec<(IosScope, [u8; 32])>,
    expected_rvf_identity: [u8; 32],
    artifact_origin: IosArtifactOrigin,
    budget: IosBudget,
    digest: [u8; 32],
}

impl IosOperatorPolicy {
    /// Construct a bounded operator policy.
    ///
    /// `allowed_resources` stores only digests of allowlisted endpoints,
    /// service sets, models, Metal pipelines, and logical memory regions.
    ///
    /// # Errors
    ///
    /// Refuses zero/unbounded budgets, duplicate scopes/resources, more than
    /// 64 resource entries, a zero resource digest, or a resource for a
    /// disabled scope.
    pub fn new(
        allowed_scopes: Vec<IosScope>,
        allowed_resources: Vec<(IosScope, [u8; 32])>,
        expected_rvf_identity: [u8; 32],
        artifact_origin: IosArtifactOrigin,
        budget: IosBudget,
    ) -> Result<Self, IosReason> {
        if !budget.valid() || allowed_resources.len() > 64 || expected_rvf_identity == [0; 32] {
            return Err(IosReason::InvalidRequest);
        }
        if has_duplicates(&allowed_scopes)
            || allowed_resources
                .iter()
                .any(|(_, digest)| *digest == [0; 32])
            || allowed_resources
                .iter()
                .any(|(scope, _)| !allowed_scopes.contains(scope))
        {
            return Err(IosReason::InvalidRequest);
        }
        for (index, item) in allowed_resources.iter().enumerate() {
            if allowed_resources[..index].contains(item) {
                return Err(IosReason::InvalidRequest);
            }
        }
        let digest = operator_policy_digest(
            &allowed_scopes,
            &allowed_resources,
            &expected_rvf_identity,
            artifact_origin,
            budget,
        );
        Ok(Self {
            allowed_scopes,
            allowed_resources,
            expected_rvf_identity,
            artifact_origin,
            budget,
            digest,
        })
    }

    /// SHA-256 of the complete bounded local policy and artifact-origin assertion.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Host-asserted artifact origin authenticated into operation evidence.
    #[must_use]
    pub const fn artifact_origin(&self) -> IosArtifactOrigin {
        self.artifact_origin
    }

    fn allows_scope(&self, scope: IosScope) -> bool {
        self.allowed_scopes.contains(&scope)
    }

    fn allows_resource(&self, scope: IosScope, digest: &[u8; 32]) -> bool {
        if scope_requires_resource(scope) || *digest != [0; 32] {
            return *digest != [0; 32] && self.allowed_resources.contains(&(scope, *digest));
        }
        true
    }
}

/// One proposed native operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosOperationRequest {
    /// Exact signed fine-grained scope.
    pub scope: IosScope,
    /// Digest of the allowlisted resource, or zero for unbound camera/IMU/clock reads.
    pub resource_digest: [u8; 32],
    /// Abstract work/sample/byte units.
    pub units: u64,
    /// Requested operation duration in milliseconds.
    pub duration_ms: u32,
    /// Scope-specific requested option code, interpreted by the typed adapter.
    pub options: u32,
}

/// Application-specific native failure code. Raw framework strings and sensor
/// data must not be placed in receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchFailure {
    /// Stable application-owned numeric failure code.
    pub code: u32,
}

/// Governed dispatch refusal or native failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    /// Authorization failed and the native callback did not execute.
    Denied(IosReason),
    /// Authorization passed, intent was recorded, and native dispatch failed.
    Native(DispatchFailure),
    /// No receipt capacity remained, so native work was not started or its
    /// outcome could not be durably represented in this in-memory chain.
    EvidenceUnavailable,
}

/// Stateful HostedIOS policy and receipt boundary for one RVF session.
pub struct GovernedIosRuntime {
    policy: IosPolicy,
    operator: IosOperatorPolicy,
    facts: IosPlatformFacts,
    interpreter_active: bool,
    next_operation_id: u64,
    used_calls: [u64; IosScope::ALL.len()],
    receipts: ReceiptChain,
    pub(crate) rvf_identity: [u8; 32],
}

impl GovernedIosRuntime {
    /// Build a session from already signer-bound policy and a caller-supplied
    /// HMAC key/session nonce. There is deliberately no default receipt key.
    ///
    /// # Errors
    ///
    /// Refuses an all-zero receipt key/session nonce, or a policy whose
    /// package identity is not exactly pinned by local operator policy.
    pub fn new(
        policy: IosPolicy,
        operator: IosOperatorPolicy,
        facts: IosPlatformFacts,
        receipt_key: [u8; 32],
        session_nonce: [u8; 16],
    ) -> Result<Self, IosReason> {
        if receipt_key == [0; 32] || session_nonce == [0; 16] {
            return Err(IosReason::InvalidRequest);
        }
        let rvf_identity = *policy.rvf_identity();
        if operator.expected_rvf_identity != rvf_identity {
            return Err(IosReason::AgentIdentityDenied);
        }
        let max_receipts = operator.budget.max_receipts;
        let receipts = ReceiptChain::new(
            receipt_key,
            ReceiptSessionIdentity {
                rvf_identity,
                policy_digest: *policy.digest(),
                operator_policy_digest: *operator.digest(),
                artifact_origin: operator.artifact_origin(),
                session_nonce,
                profile: HostedIosProfile::derive(&facts),
                platform_facts_digest: facts.evidence_digest(),
            },
            max_receipts,
        )
        .map_err(|_| IosReason::EvidenceUnavailable)?;
        Ok(Self {
            policy,
            operator,
            facts,
            interpreter_active: false,
            next_operation_id: 0,
            used_calls: [0; IosScope::ALL.len()],
            receipts,
            rvf_identity,
        })
    }

    /// Replace dynamic iOS facts before the next operation. Permission and
    /// thermal changes therefore revoke access without rebuilding the agent.
    pub fn update_platform_facts(&mut self, facts: IosPlatformFacts) {
        self.facts = facts;
        self.receipts.set_platform_evidence(
            HostedIosProfile::derive_for_turn(&self.facts, self.interpreter_active),
            self.facts.evidence_digest(),
        );
    }

    pub(crate) fn set_interpreter_active(&mut self, active: bool) {
        self.interpreter_active = active;
        self.receipts.set_platform_evidence(
            HostedIosProfile::derive_for_turn(&self.facts, self.interpreter_active),
            self.facts.evidence_digest(),
        );
    }

    /// Current honestly derived profile.
    #[must_use]
    pub const fn profile(&self) -> HostedIosProfile {
        HostedIosProfile::derive_for_turn(&self.facts, self.interpreter_active)
    }

    pub(crate) const fn policy_signer(&self) -> &[u8; 32] {
        self.policy.trusted_signer()
    }

    pub(crate) fn begin_agent_execution(
        &mut self,
        reported_started_ns: u64,
        module_digest: [u8; 32],
        entrypoint_digest: [u8; 32],
        runtime_digest: [u8; 32],
        limits: AgentExecutionLimits,
    ) -> Result<AgentExecutionContext, ReceiptIntegrityError> {
        self.receipts.begin_execution(
            reported_started_ns,
            module_digest,
            entrypoint_digest,
            runtime_digest,
            limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_agent_execution(
        &mut self,
        context: &AgentExecutionContext,
        reported_ended_ns: u64,
        outcome: AgentExecutionOutcome,
        result: i64,
        fuel_consumed: u64,
        host_calls_attempted: u64,
        host_calls_dispatched: u64,
    ) -> Result<AgentExecutionSeal, ReceiptIntegrityError> {
        self.receipts.seal_execution(
            context,
            reported_ended_ns,
            outcome,
            result,
            fuel_consumed,
            host_calls_attempted,
            host_calls_dispatched,
        )
    }

    /// Full-content receipt chain accumulated so far.
    #[must_use]
    pub const fn receipts(&self) -> &ReceiptChain {
        &self.receipts
    }

    /// Consume the runtime and return its receipt chain.
    #[must_use]
    pub fn into_receipts(self) -> ReceiptChain {
        self.receipts
    }

    /// Record and return an adapter-side malformed-request refusal.
    ///
    /// Typed native adapters call this when their own schema or framework
    /// bounds reject a request before the general policy evaluator runs. This
    /// keeps those refusals in the same full-content receipt chain and never
    /// consumes a call budget or invokes native code.
    #[must_use]
    pub fn refuse_invalid_request(
        &mut self,
        request: IosOperationRequest,
        timestamp_ns: u64,
    ) -> DispatchError {
        let Some(operation_id) = self.allocate_operation_id() else {
            return DispatchError::EvidenceUnavailable;
        };
        let receipt = self
            .receipts
            .append(
                timestamp_ns,
                operation_id,
                ReceiptEvent::Denied,
                request.scope,
                IosReason::InvalidRequest,
                request.resource_digest,
                request.units,
                request.duration_ms,
                request.options,
                0,
            )
            .map_err(|_| DispatchError::EvidenceUnavailable);
        match receipt {
            Ok(receipt) if receipt.timestamp_ns == receipt.reported_timestamp_ns => {
                DispatchError::Denied(IosReason::InvalidRequest)
            }
            Ok(_) | Err(_) => DispatchError::EvidenceUnavailable,
        }
    }

    /// Authorize, record intent, execute, then record completion/failure.
    ///
    /// The callback is never evaluated when authorization fails. It supplies
    /// the completion timestamp alongside its result so receipts can use a
    /// host monotonic clock without granting the guest clock authority.
    ///
    /// # Errors
    ///
    /// Returns a witnessed denial, or a witnessed native failure after intent.
    pub fn dispatch<T>(
        &mut self,
        request: IosOperationRequest,
        started_ns: u64,
        operation: impl FnOnce() -> Result<(T, u64), (DispatchFailure, u64)>,
    ) -> Result<T, DispatchError> {
        let Some(operation_id) = self.allocate_operation_id() else {
            return Err(DispatchError::EvidenceUnavailable);
        };
        if self
            .receipts
            .last_timestamp_ns()
            .is_some_and(|last| started_ns < last)
        {
            self.receipts
                .append(
                    started_ns,
                    operation_id,
                    ReceiptEvent::Denied,
                    request.scope,
                    IosReason::ClockRegression,
                    request.resource_digest,
                    request.units,
                    request.duration_ms,
                    request.options,
                    0,
                )
                .map_err(|_| DispatchError::EvidenceUnavailable)?;
            return Err(DispatchError::EvidenceUnavailable);
        }
        if let Err(reason) = self.authorize(request) {
            self.receipts
                .append(
                    started_ns,
                    operation_id,
                    ReceiptEvent::Denied,
                    request.scope,
                    reason,
                    request.resource_digest,
                    request.units,
                    request.duration_ms,
                    request.options,
                    0,
                )
                .map_err(|_| DispatchError::EvidenceUnavailable)?;
            return Err(DispatchError::Denied(reason));
        }

        if !self.receipts.can_append(2) {
            return Err(DispatchError::EvidenceUnavailable);
        }
        self.used_calls[scope_index(request.scope)] =
            self.used_calls[scope_index(request.scope)].saturating_add(1);
        self.receipts
            .append(
                started_ns,
                operation_id,
                ReceiptEvent::Intent,
                request.scope,
                IosReason::Allowed,
                request.resource_digest,
                request.units,
                request.duration_ms,
                request.options,
                0,
            )
            .map_err(|_| DispatchError::EvidenceUnavailable)?;
        self.record_dispatch_outcome(operation_id, request, started_ns, operation())
    }

    fn record_dispatch_outcome<T>(
        &mut self,
        operation_id: u64,
        request: IosOperationRequest,
        started_ns: u64,
        outcome: Result<(T, u64), (DispatchFailure, u64)>,
    ) -> Result<T, DispatchError> {
        match outcome {
            Ok((value, completed_ns)) => {
                if completion_exceeded_deadline(started_ns, completed_ns, request.duration_ms) {
                    self.record_failed_outcome(
                        operation_id,
                        request,
                        completed_ns,
                        DispatchFailure {
                            code: IOS_NATIVE_DEADLINE_EXCEEDED,
                        },
                    )?;
                    return Err(DispatchError::Native(DispatchFailure {
                        code: IOS_NATIVE_DEADLINE_EXCEEDED,
                    }));
                }
                let receipt = self
                    .receipts
                    .append(
                        completed_ns,
                        operation_id,
                        ReceiptEvent::Completed,
                        request.scope,
                        IosReason::Allowed,
                        request.resource_digest,
                        request.units,
                        request.duration_ms,
                        request.options,
                        0,
                    )
                    .map_err(|_| DispatchError::EvidenceUnavailable)?;
                if receipt.timestamp_ns == receipt.reported_timestamp_ns {
                    Ok(value)
                } else {
                    Err(DispatchError::EvidenceUnavailable)
                }
            }
            Err((failure, completed_ns)) => {
                self.record_failed_outcome(operation_id, request, completed_ns, failure)?;
                Err(DispatchError::Native(failure))
            }
        }
    }

    fn record_failed_outcome(
        &mut self,
        operation_id: u64,
        request: IosOperationRequest,
        completed_ns: u64,
        failure: DispatchFailure,
    ) -> Result<(), DispatchError> {
        let receipt = self
            .receipts
            .append(
                completed_ns,
                operation_id,
                ReceiptEvent::Failed,
                request.scope,
                IosReason::NativeFailure,
                request.resource_digest,
                request.units,
                request.duration_ms,
                request.options,
                failure.code,
            )
            .map_err(|_| DispatchError::EvidenceUnavailable)?;
        if receipt.timestamp_ns == receipt.reported_timestamp_ns {
            Ok(())
        } else {
            Err(DispatchError::EvidenceUnavailable)
        }
    }

    fn allocate_operation_id(&mut self) -> Option<u64> {
        self.next_operation_id = self.next_operation_id.checked_add(1)?;
        Some(self.next_operation_id)
    }

    fn authorize(&self, request: IosOperationRequest) -> Result<(), IosReason> {
        if request.units == 0 || request.duration_ms == 0 {
            return Err(IosReason::InvalidRequest);
        }
        if !self.policy.permits(request.scope) {
            return Err(IosReason::ManifestMissing);
        }
        if !self.operator.allows_scope(request.scope)
            || !self
                .operator
                .allows_resource(request.scope, &request.resource_digest)
        {
            return Err(IosReason::OperatorDenied);
        }
        if request.units > self.operator.budget.max_units_per_call
            || request.duration_ms > self.operator.budget.max_duration_ms
            || self.used_calls[scope_index(request.scope)]
                >= self.operator.budget.max_calls_per_scope
        {
            return Err(IosReason::BudgetExceeded);
        }
        platform_allows(request.scope, &self.facts)
    }
}

fn completion_exceeded_deadline(started_ns: u64, completed_ns: u64, duration_ms: u32) -> bool {
    match completed_ns.checked_sub(started_ns) {
        Some(elapsed) => elapsed > u64::from(duration_ms) * 1_000_000,
        None => true,
    }
}

fn platform_allows(scope: IosScope, facts: &IosPlatformFacts) -> Result<(), IosReason> {
    match scope {
        IosScope::CameraRead => {
            sensor_recording_preconditions(facts)?;
            authorization_result(facts.camera)
        }
        IosScope::LidarRead => {
            sensor_recording_preconditions(facts)?;
            authorization_result(facts.camera)?;
            if facts.lidar_supported {
                Ok(())
            } else {
                Err(IosReason::PlatformUnsupported)
            }
        }
        IosScope::ImuRead => {
            sensor_recording_preconditions(facts)?;
            authorization_result(facts.motion)
        }
        IosScope::BleScan => authorization_result(facts.bluetooth),
        IosScope::NetworkConnect if facts.network_enabled => Ok(()),
        IosScope::NetworkConnect => Err(IosReason::PlatformUnsupported),
        IosScope::GpuExecute => {
            if facts.thermal_state >= 2 {
                Err(IosReason::ThermalDenied)
            } else if facts.metal_available {
                Ok(())
            } else {
                Err(IosReason::PlatformUnsupported)
            }
        }
        IosScope::ModelInfer => {
            if facts.thermal_state >= 3 {
                Err(IosReason::ThermalDenied)
            } else if facts.core_ml_available {
                Ok(())
            } else {
                Err(IosReason::PlatformUnsupported)
            }
        }
        IosScope::MemoryRead | IosScope::MemoryWrite | IosScope::ClockRead => Ok(()),
    }
}

fn sensor_recording_preconditions(facts: &IosPlatformFacts) -> Result<(), IosReason> {
    if !facts.explicit_sensor_consent {
        Err(IosReason::UserConsentMissing)
    } else if !facts.recording_indicator_active {
        Err(IosReason::RecordingIndicatorMissing)
    } else {
        Ok(())
    }
}

fn authorization_result(status: IosAuthorization) -> Result<(), IosReason> {
    match status {
        IosAuthorization::Authorized => Ok(()),
        IosAuthorization::NotDetermined => Err(IosReason::OsPermissionNotDetermined),
        IosAuthorization::Denied | IosAuthorization::Restricted => {
            Err(IosReason::OsPermissionDenied)
        }
        IosAuthorization::Unavailable => Err(IosReason::PlatformUnsupported),
    }
}

pub(crate) const fn scope_requires_resource(scope: IosScope) -> bool {
    matches!(
        scope,
        IosScope::BleScan
            | IosScope::NetworkConnect
            | IosScope::GpuExecute
            | IosScope::ModelInfer
            | IosScope::MemoryRead
            | IosScope::MemoryWrite
    )
}

fn scope_index(scope: IosScope) -> usize {
    usize::from(scope as u8 - 1)
}

fn has_duplicates(values: &[IosScope]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, item)| values[..index].contains(item))
}

fn operator_policy_digest(
    allowed_scopes: &[IosScope],
    allowed_resources: &[(IosScope, [u8; 32])],
    expected_rvf_identity: &[u8; 32],
    artifact_origin: IosArtifactOrigin,
    budget: IosBudget,
) -> [u8; 32] {
    let mut scopes = allowed_scopes.to_vec();
    scopes.sort_unstable();
    let mut resources = allowed_resources.to_vec();
    resources.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(OPERATOR_POLICY_DOMAIN);
    hasher.update(expected_rvf_identity);
    hasher.update([artifact_origin as u8]);
    hasher.update(budget.max_calls_per_scope.to_le_bytes());
    hasher.update(budget.max_units_per_call.to_le_bytes());
    hasher.update(budget.max_duration_ms.to_le_bytes());
    hasher.update(
        u64::try_from(budget.max_receipts)
            .expect("bounded receipt count fits u64")
            .to_le_bytes(),
    );
    hasher.update(
        u64::try_from(scopes.len())
            .expect("bounded scope count fits u64")
            .to_le_bytes(),
    );
    for scope in scopes {
        hasher.update([scope as u8]);
    }
    hasher.update(
        u64::try_from(resources.len())
            .expect("bounded resource count fits u64")
            .to_le_bytes(),
    );
    for (scope, digest) in resources {
        hasher.update([scope as u8]);
        hasher.update(digest);
    }
    let bytes = hasher.finalize();
    let mut digest = [0; 32];
    digest.copy_from_slice(&bytes);
    digest
}
