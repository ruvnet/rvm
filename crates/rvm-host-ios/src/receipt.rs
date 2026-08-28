//! Full-content, keyed HostedIOS operation receipts.

use crate::{HostedIosProfile, IosArtifactOrigin, IosReason, IosScope};
use hmac::{Hmac, Mac};
use rvm_wasm_hosted::HostedWasmLimits;
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;
const DOMAIN: &[u8] = b"RVM-HOSTED-IOS-RECEIPT-V1";
const SEAL_DOMAIN: &[u8] = b"RVM-HOSTED-IOS-RECEIPT-SEAL-V1";
const EXECUTION_DOMAIN: &[u8] = b"RVM-HOSTED-IOS-EXECUTION-SEAL-V2";

/// Phase/outcome represented by one operation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptEvent {
    /// Authorization succeeded and native dispatch is about to begin.
    Intent = 1,
    /// Authorization failed; native dispatch did not run.
    Denied = 2,
    /// Native dispatch returned success.
    Completed = 3,
    /// Native dispatch returned failure.
    Failed = 4,
}

/// One privacy-bounded HostedIOS audit record.
///
/// `resource_digest` binds an allowlisted model, Metal pipeline, endpoint,
/// service set, or logical region without storing its raw name or contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosReceipt {
    /// Monotonic sequence within this session.
    pub sequence: u64,
    /// Monotonic operation identifier. Intent and outcome share one ID.
    pub operation_id: u64,
    /// Effective monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Timestamp reported by the host before monotonic clamping.
    /// A value below `timestamp_ns` records a host-clock regression.
    pub reported_timestamp_ns: u64,
    /// RVF container SHA-256.
    pub rvf_identity: [u8; 32],
    /// SHA-256 of canonical signed HostedIOS policy bytes.
    pub policy_digest: [u8; 32],
    /// SHA-256 of the complete local operator policy and artifact-origin assertion.
    pub operator_policy_digest: [u8; 32],
    /// Host-asserted source class for the exact executable RVF bytes.
    pub artifact_origin: IosArtifactOrigin,
    /// Random per-session nonce supplied by the embedding app.
    pub session_nonce: [u8; 16],
    /// Honest isolation profile at decision time.
    pub profile: HostedIosProfile,
    /// Digest of all native-host platform facts evaluated at decision time.
    /// This binds the host assertion; it is not Apple remote attestation.
    pub platform_facts_digest: [u8; 32],
    /// Operation phase/outcome.
    pub event: ReceiptEvent,
    /// Fine-grained operation scope.
    pub scope: IosScope,
    /// Authorization or dispatch reason.
    pub reason: IosReason,
    /// Digest of the allowlisted resource, never raw sensor/model data.
    pub resource_digest: [u8; 32],
    /// Abstract bounded work units requested or consumed.
    pub units: u64,
    /// Requested operation duration in milliseconds.
    pub duration_ms: u32,
    /// Scope-specific requested option code (for example Core ML compute policy).
    pub options: u32,
    /// Stable scope-specific result detail (for example a native failure code).
    /// Zero means no additional detail.
    pub detail_code: u32,
    /// MAC of the preceding receipt, or zero at genesis.
    pub previous_mac: [u8; 32],
    /// HMAC-SHA256 over every preceding field and `previous_mac`.
    pub mac: [u8; 32],
}

/// In-memory append-only chain for one HostedIOS session.
///
/// The app must export/seal this chain with a per-install key and durable
/// storage if it needs evidence across process termination. The key should be
/// random and Keychain-protected; optional Secure Enclave-backed wrapping or
/// signing belongs to the native app and is not assumed here. A compiled
/// default is never provided.
pub struct ReceiptChain {
    key: [u8; 32],
    rvf_identity: [u8; 32],
    policy_digest: [u8; 32],
    operator_policy_digest: [u8; 32],
    artifact_origin: IosArtifactOrigin,
    session_nonce: [u8; 16],
    profile: HostedIosProfile,
    platform_facts_digest: [u8; 32],
    max_receipts: usize,
    receipts: Vec<IosReceipt>,
    next_invocation_id: u64,
    active_invocation_id: Option<u64>,
    previous_execution_mac: [u8; 32],
}

/// Authenticated terminal commitment required for complete-chain verification.
///
/// A bare receipt prefix can verify its internal links but cannot prove that a
/// valid tail was not omitted. Requiring this seal binds the expected record
/// count and terminal head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptSeal {
    /// Exact number of records committed by this seal.
    pub count: u64,
    /// Terminal receipt MAC committed by this seal.
    pub chain_head: [u8; 32],
    /// HMAC-SHA256 over the domain, count, and terminal head.
    pub mac: [u8; 32],
}

/// Fixed identity and platform evidence for one in-memory receipt session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptSessionIdentity {
    /// Exact whole-RVF SHA-256.
    pub rvf_identity: [u8; 32],
    /// Signer-bound HostedIOS policy digest.
    pub policy_digest: [u8; 32],
    /// Complete local operator policy digest.
    pub operator_policy_digest: [u8; 32],
    /// Host-asserted executable RVF source class.
    pub artifact_origin: IosArtifactOrigin,
    /// Random per-session nonce.
    pub session_nonce: [u8; 16],
    /// Honest isolation profile at session construction.
    pub profile: HostedIosProfile,
    /// Digest of host-reported platform facts at session construction.
    pub platform_facts_digest: [u8; 32],
}

/// Authenticated terminal outcome for one hosted guest invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentExecutionOutcome {
    /// Guest entrypoint returned normally.
    Completed = 1,
    /// RVF identity, signer, or exact executable bytes did not match.
    ExecutableNotVerified = 2,
    /// Interpreter limits were invalid.
    InvalidLimits = 3,
    /// WASM validation/translation failed.
    InvalidModule = 4,
    /// Guest imports could not be linked under the one-import policy.
    LinkRefused = 5,
    /// Module start trapped or exhausted its envelope.
    StartRefused = 6,
    /// Requested guest entrypoint was missing or incompatible.
    InvalidEntrypoint = 7,
    /// Guest execution trapped or exhausted fuel.
    ExecutionRefused = 8,
    /// Interpreter fuel accounting was unexpectedly unavailable.
    FuelUnavailable = 9,
}

/// Exact interpreter envelope authenticated for one guest invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentExecutionLimits {
    /// Maximum encoded module bytes admitted by the interpreter.
    pub module_bytes: u64,
    /// Interpreter fuel supplied to this invocation.
    pub fuel: u64,
    /// Maximum linear-memory bytes per guest memory.
    pub memory_bytes: u64,
    /// Maximum guest tables.
    pub tables: u64,
    /// Maximum elements in each guest table.
    pub table_elements: u64,
    /// Maximum guest memories.
    pub memories: u64,
    /// Maximum guest calls forwarded to the governed host.
    pub host_calls: u64,
}

impl AgentExecutionLimits {
    pub(crate) fn from_hosted(limits: HostedWasmLimits) -> Option<Self> {
        Some(Self {
            module_bytes: u64::try_from(limits.module_bytes).ok()?,
            fuel: limits.fuel,
            memory_bytes: u64::try_from(limits.memory_bytes).ok()?,
            tables: u64::try_from(limits.tables).ok()?,
            table_elements: u64::from(limits.table_elements),
            memories: u64::try_from(limits.memories).ok()?,
            host_calls: limits.host_calls,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AgentExecutionContext {
    invocation_id: u64,
    reported_started_ns: u64,
    started_ns: u64,
    start_receipt_count: u64,
    start_receipt_head: [u8; 32],
    previous_execution_mac: [u8; 32],
    profile: HostedIosProfile,
    platform_facts_digest: [u8; 32],
    module_digest: [u8; 32],
    entrypoint_digest: [u8; 32],
    runtime_digest: [u8; 32],
    limits: AgentExecutionLimits,
}

/// HMAC-bound guest result plus the exact terminal operation-receipt head.
///
/// Export this record together with its receipt chain. It detects an omitted
/// valid receipt suffix, but preventing rollback of an older complete
/// chain+seal still requires a native monotonic counter or durable anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentExecutionSeal {
    /// Monotonic invocation identifier within this receipt session.
    pub invocation_id: u64,
    /// RVF container identity whose executable was considered.
    pub rvf_identity: [u8; 32],
    /// Signer-bound HostedIOS policy digest.
    pub policy_digest: [u8; 32],
    /// Complete local operator policy digest.
    pub operator_policy_digest: [u8; 32],
    /// Host-asserted executable RVF source class.
    pub artifact_origin: IosArtifactOrigin,
    /// Per-session nonce.
    pub session_nonce: [u8; 16],
    /// Isolation profile active while the outcome was produced.
    pub profile: HostedIosProfile,
    /// Platform facts sampled at invocation start. Per-operation receipts bind
    /// any later dynamic authorization or thermal changes independently.
    pub platform_facts_digest: [u8; 32],
    /// Timestamp reported by the host at invocation start.
    pub reported_started_ns: u64,
    /// Monotonic-clamped invocation start timestamp.
    pub started_ns: u64,
    /// Timestamp reported by the host at invocation end.
    pub reported_ended_ns: u64,
    /// Monotonic-clamped invocation end timestamp.
    pub ended_ns: u64,
    /// Receipt count before the invocation began.
    pub start_receipt_count: u64,
    /// Receipt-chain head before the invocation began.
    pub start_receipt_head: [u8; 32],
    /// SHA-256 of the exact selected WASM module bytes.
    pub module_digest: [u8; 32],
    /// SHA-256 of the requested entrypoint name.
    pub entrypoint_digest: [u8; 32],
    /// SHA-256 of the hosted interpreter implementation/ABI identifier.
    pub runtime_digest: [u8; 32],
    /// Exact interpreter resource envelope used for the invocation.
    pub limits: AgentExecutionLimits,
    /// Terminal guest outcome.
    pub outcome: AgentExecutionOutcome,
    /// Guest return value for [`AgentExecutionOutcome::Completed`], zero otherwise.
    pub result: i64,
    /// Interpreter fuel consumed when available.
    pub fuel_consumed: u64,
    /// Total guest import calls attempted.
    pub host_calls_attempted: u64,
    /// Guest import calls forwarded to the governed host.
    pub host_calls_dispatched: u64,
    /// Exact number of operation receipts at invocation end.
    pub receipt_count: u64,
    /// Exact terminal operation-receipt MAC at invocation end.
    pub receipt_head: [u8; 32],
    /// Execution-seal MAC from the preceding invocation, or zero at genesis.
    pub previous_execution_mac: [u8; 32],
    /// HMAC-SHA256 over every preceding field.
    pub mac: [u8; 32],
}

impl Drop for ReceiptChain {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ReceiptChain {
    /// Create an empty chain from caller-supplied secret and session identity.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIntegrityError::Capacity`] when `max_receipts` is
    /// outside the fixed supported range or the complete bounded allocation
    /// cannot be reserved before the session starts.
    pub fn new(
        key: [u8; 32],
        identity: ReceiptSessionIdentity,
        max_receipts: usize,
    ) -> Result<Self, ReceiptIntegrityError> {
        if !(2..=65_536).contains(&max_receipts) {
            return Err(ReceiptIntegrityError::Capacity);
        }
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(max_receipts)
            .map_err(|_| ReceiptIntegrityError::Capacity)?;
        Ok(Self {
            key,
            rvf_identity: identity.rvf_identity,
            policy_digest: identity.policy_digest,
            operator_policy_digest: identity.operator_policy_digest,
            artifact_origin: identity.artifact_origin,
            session_nonce: identity.session_nonce,
            profile: identity.profile,
            platform_facts_digest: identity.platform_facts_digest,
            max_receipts,
            // Reserve the complete, policy-bounded evidence budget up front so
            // a successful pre-dispatch `can_append(2)` check cannot be
            // invalidated by a second allocation after native work starts.
            receipts,
            next_invocation_id: 0,
            active_invocation_id: None,
            previous_execution_mac: [0; 32],
        })
    }

    /// Append one fully-bound event and return its receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIntegrityError::Capacity`] when the fixed session
    /// evidence budget has been exhausted.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        reported_timestamp_ns: u64,
        operation_id: u64,
        event: ReceiptEvent,
        scope: IosScope,
        reason: IosReason,
        resource_digest: [u8; 32],
        units: u64,
        duration_ms: u32,
        options: u32,
        detail_code: u32,
    ) -> Result<IosReceipt, ReceiptIntegrityError> {
        if !self.can_append(1) {
            return Err(ReceiptIntegrityError::Capacity);
        }
        if !valid_next_event(
            self.receipts.last(),
            operation_id,
            event,
            reason,
            scope,
            &resource_digest,
            units,
            duration_ms,
            options,
            detail_code,
        ) {
            return Err(ReceiptIntegrityError::Pair {
                sequence: self.receipts.len() as u64,
            });
        }
        let sequence = self.receipts.len() as u64;
        let previous_mac = self.receipts.last().map_or([0; 32], |receipt| receipt.mac);
        let timestamp_ns = self
            .receipts
            .last()
            .map_or(reported_timestamp_ns, |receipt| {
                receipt.timestamp_ns.max(reported_timestamp_ns)
            });
        let mut receipt = IosReceipt {
            sequence,
            operation_id,
            timestamp_ns,
            reported_timestamp_ns,
            rvf_identity: self.rvf_identity,
            policy_digest: self.policy_digest,
            operator_policy_digest: self.operator_policy_digest,
            artifact_origin: self.artifact_origin,
            session_nonce: self.session_nonce,
            profile: self.profile,
            platform_facts_digest: self.platform_facts_digest,
            event,
            scope,
            reason,
            resource_digest,
            units,
            duration_ms,
            options,
            detail_code,
            previous_mac,
            mac: [0; 32],
        };
        receipt.mac = compute_mac(&self.key, &receipt);
        self.receipts.push(receipt);
        Ok(receipt)
    }

    /// Whether `additional` records fit without exceeding the fixed session
    /// evidence budget.
    #[must_use]
    pub fn can_append(&self, additional: usize) -> bool {
        self.receipts
            .len()
            .checked_add(additional)
            .is_some_and(|required| required <= self.max_receipts)
    }

    /// Receipts in append order.
    #[must_use]
    pub fn receipts(&self) -> &[IosReceipt] {
        &self.receipts
    }

    /// Current 256-bit chain head, or zero for an empty chain.
    #[must_use]
    pub fn chain_head(&self) -> [u8; 32] {
        self.receipts.last().map_or([0; 32], |receipt| receipt.mac)
    }

    pub(crate) fn last_timestamp_ns(&self) -> Option<u64> {
        self.receipts.last().map(|receipt| receipt.timestamp_ns)
    }

    /// Authenticated terminal record count and chain head.
    #[must_use]
    pub fn seal(&self) -> ReceiptSeal {
        compute_seal(&self.key, self.receipts.len() as u64, self.chain_head())
    }

    /// Open one non-overlapping guest invocation and bind its starting chain state.
    ///
    /// # Errors
    ///
    /// Refuses nested/counter-exhausted invocations or zero module/runtime digests.
    pub(crate) fn begin_execution(
        &mut self,
        reported_started_ns: u64,
        module_digest: [u8; 32],
        entrypoint_digest: [u8; 32],
        runtime_digest: [u8; 32],
        limits: AgentExecutionLimits,
    ) -> Result<AgentExecutionContext, ReceiptIntegrityError> {
        if self.active_invocation_id.is_some()
            || runtime_digest == [0; 32]
            || module_digest == [0; 32]
        {
            return Err(ReceiptIntegrityError::Invocation);
        }
        let invocation_id = self
            .next_invocation_id
            .checked_add(1)
            .ok_or(ReceiptIntegrityError::Invocation)?;
        let started_ns = self
            .last_timestamp_ns()
            .map_or(reported_started_ns, |last| last.max(reported_started_ns));
        self.next_invocation_id = invocation_id;
        self.active_invocation_id = Some(invocation_id);
        Ok(AgentExecutionContext {
            invocation_id,
            reported_started_ns,
            started_ns,
            start_receipt_count: self.receipts.len() as u64,
            start_receipt_head: self.chain_head(),
            previous_execution_mac: self.previous_execution_mac,
            profile: self.profile,
            platform_facts_digest: self.platform_facts_digest,
            module_digest,
            entrypoint_digest,
            runtime_digest,
            limits,
        })
    }

    /// Authenticate one terminal guest outcome against its invocation start
    /// and the current receipt head.
    ///
    /// # Errors
    ///
    /// Refuses a stale context, inconsistent outcome/counters, or counters
    /// outside the authenticated interpreter envelope.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_execution(
        &mut self,
        context: &AgentExecutionContext,
        reported_ended_ns: u64,
        outcome: AgentExecutionOutcome,
        result: i64,
        fuel_consumed: u64,
        host_calls_attempted: u64,
        host_calls_dispatched: u64,
    ) -> Result<AgentExecutionSeal, ReceiptIntegrityError> {
        if self.active_invocation_id != Some(context.invocation_id)
            || !valid_execution_outcome(
                outcome,
                result,
                fuel_consumed,
                host_calls_attempted,
                host_calls_dispatched,
                context.limits,
            )
        {
            return Err(ReceiptIntegrityError::Invocation);
        }
        let ended_ns = context
            .started_ns
            .max(self.last_timestamp_ns().unwrap_or(context.started_ns))
            .max(reported_ended_ns);
        let mut seal = AgentExecutionSeal {
            invocation_id: context.invocation_id,
            rvf_identity: self.rvf_identity,
            policy_digest: self.policy_digest,
            operator_policy_digest: self.operator_policy_digest,
            artifact_origin: self.artifact_origin,
            session_nonce: self.session_nonce,
            profile: context.profile,
            platform_facts_digest: context.platform_facts_digest,
            reported_started_ns: context.reported_started_ns,
            started_ns: context.started_ns,
            reported_ended_ns,
            ended_ns,
            start_receipt_count: context.start_receipt_count,
            start_receipt_head: context.start_receipt_head,
            module_digest: context.module_digest,
            entrypoint_digest: context.entrypoint_digest,
            runtime_digest: context.runtime_digest,
            limits: context.limits,
            outcome,
            result,
            fuel_consumed,
            host_calls_attempted,
            host_calls_dispatched,
            receipt_count: self.receipts.len() as u64,
            receipt_head: self.chain_head(),
            previous_execution_mac: context.previous_execution_mac,
            mac: [0; 32],
        };
        seal.mac = compute_execution_mac(&self.key, &seal);
        self.previous_execution_mac = seal.mac;
        self.active_invocation_id = None;
        Ok(seal)
    }

    /// Set the derived profile and fact digest used for future receipts.
    /// Existing evidence is never relabelled after the fact.
    pub(crate) fn set_platform_evidence(
        &mut self,
        profile: HostedIosProfile,
        platform_facts_digest: [u8; 32],
    ) {
        self.profile = profile;
        self.platform_facts_digest = platform_facts_digest;
    }

    /// Verify this in-memory chain with its configured secret.
    ///
    /// # Errors
    ///
    /// Refuses an empty chain, sequence/previous-link break, a decreasing host
    /// timestamp, or content MAC mismatch.
    pub fn verify(&self) -> Result<usize, ReceiptIntegrityError> {
        verify_receipt_chain(&self.receipts, &self.key)
    }
}

/// Verify a copied HostedIOS receipt chain with its per-install/session key.
///
/// # Errors
///
/// Refuses an empty chain, sequence/previous-link break, a decreasing host
/// timestamp, or content MAC mismatch.
pub fn verify_receipt_chain(
    receipts: &[IosReceipt],
    key: &[u8; 32],
) -> Result<usize, ReceiptIntegrityError> {
    if receipts.is_empty() {
        return Err(ReceiptIntegrityError::Empty);
    }
    let mut previous = [0; 32];
    let mut previous_timestamp = 0;
    let mut previous_receipt: Option<&IosReceipt> = None;
    for (index, receipt) in receipts.iter().enumerate() {
        if receipt.sequence != index as u64 || receipt.previous_mac != previous {
            return Err(ReceiptIntegrityError::Link {
                sequence: receipt.sequence,
            });
        }
        let expected_timestamp = if index == 0 {
            receipt.reported_timestamp_ns
        } else {
            previous_timestamp.max(receipt.reported_timestamp_ns)
        };
        if receipt.timestamp_ns != expected_timestamp {
            return Err(ReceiptIntegrityError::Timestamp {
                sequence: receipt.sequence,
            });
        }
        if !valid_next_event(
            previous_receipt,
            receipt.operation_id,
            receipt.event,
            receipt.reason,
            receipt.scope,
            &receipt.resource_digest,
            receipt.units,
            receipt.duration_ms,
            receipt.options,
            receipt.detail_code,
        ) {
            return Err(ReceiptIntegrityError::Pair {
                sequence: receipt.sequence,
            });
        }
        let expected = compute_mac(key, receipt);
        if !constant_time_equal(&expected, &receipt.mac) {
            return Err(ReceiptIntegrityError::Content {
                sequence: receipt.sequence,
            });
        }
        previous = receipt.mac;
        previous_timestamp = receipt.timestamp_ns;
        previous_receipt = Some(receipt);
    }
    if matches!(
        receipts.last().map(|receipt| receipt.event),
        Some(ReceiptEvent::Intent)
    ) {
        return Err(ReceiptIntegrityError::Pair {
            sequence: receipts.len() as u64,
        });
    }
    Ok(receipts.len())
}

/// Verify a complete receipt chain against an authenticated terminal seal.
///
/// # Errors
///
/// Refuses an internally invalid chain, a truncated or extended record count,
/// a different terminal head, or a modified seal MAC.
pub fn verify_sealed_receipt_chain(
    receipts: &[IosReceipt],
    key: &[u8; 32],
    seal: &ReceiptSeal,
) -> Result<usize, ReceiptIntegrityError> {
    let count = verify_receipt_chain(receipts, key)?;
    if seal.count != count as u64
        || seal.chain_head != receipts.last().map_or([0; 32], |receipt| receipt.mac)
        || !constant_time_equal(
            &compute_seal(key, seal.count, seal.chain_head).mac,
            &seal.mac,
        )
    {
        return Err(ReceiptIntegrityError::Seal);
    }
    Ok(count)
}

/// Verify an authenticated guest outcome and its complete operation-receipt chain.
///
/// # Errors
///
/// Refuses an internally invalid non-empty receipt chain, omitted/appended
/// records, a different terminal head, or any changed execution field/MAC.
pub fn verify_agent_execution_seal(
    receipts: &[IosReceipt],
    key: &[u8; 32],
    seal: &AgentExecutionSeal,
) -> Result<usize, ReceiptIntegrityError> {
    if !receipts.is_empty() {
        verify_receipt_chain(receipts, key)?;
    }
    let count = receipts.len();
    let head = receipts.last().map_or([0; 32], |receipt| receipt.mac);
    let start_count = usize::try_from(seal.start_receipt_count)
        .map_err(|_| ReceiptIntegrityError::ExecutionSeal)?;
    if start_count > count {
        return Err(ReceiptIntegrityError::ExecutionSeal);
    }
    let start_head = if start_count == 0 {
        [0; 32]
    } else {
        receipts
            .get(start_count - 1)
            .map_or([0; 32], |receipt| receipt.mac)
    };
    let expected_started_ns = if start_count == 0 {
        seal.reported_started_ns
    } else {
        receipts[start_count - 1]
            .timestamp_ns
            .max(seal.reported_started_ns)
    };
    let expected_ended_ns = seal
        .started_ns
        .max(
            receipts
                .last()
                .map_or(seal.started_ns, |receipt| receipt.timestamp_ns),
        )
        .max(seal.reported_ended_ns);
    if seal.invocation_id == 0
        || seal.module_digest == [0; 32]
        || seal.runtime_digest == [0; 32]
        || seal.start_receipt_head != start_head
        || seal.started_ns != expected_started_ns
        || seal.ended_ns != expected_ended_ns
        || seal.receipt_count != count as u64
        || seal.receipt_head != head
        || !valid_execution_outcome(
            seal.outcome,
            seal.result,
            seal.fuel_consumed,
            seal.host_calls_attempted,
            seal.host_calls_dispatched,
            seal.limits,
        )
        || !constant_time_equal(&compute_execution_mac(key, seal), &seal.mac)
    {
        return Err(ReceiptIntegrityError::ExecutionSeal);
    }
    Ok(count)
}

/// Receipt-chain verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptIntegrityError {
    /// No evidence was supplied.
    Empty,
    /// The fixed in-memory evidence budget is exhausted.
    Capacity,
    /// Sequence or previous-MAC link is broken.
    Link {
        /// Record sequence that failed.
        sequence: u64,
    },
    /// Host timestamps decreased within one receipt session.
    Timestamp {
        /// Record sequence that moved backward.
        sequence: u64,
    },
    /// Intent/outcome operation pairing or monotonic operation IDs are invalid.
    Pair {
        /// Record sequence that failed pairing.
        sequence: u64,
    },
    /// A content field or MAC was modified.
    Content {
        /// Record sequence that failed.
        sequence: u64,
    },
    /// Terminal record count, head, or seal MAC did not match.
    Seal,
    /// Guest outcome, terminal receipt head/count, or execution MAC did not match.
    ExecutionSeal,
    /// Invocation order, active state, limits, counters, or outcome was inconsistent.
    Invocation,
}

fn compute_mac(key: &[u8; 32], receipt: &IosReceipt) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(DOMAIN);
    mac.update(&receipt.sequence.to_le_bytes());
    mac.update(&receipt.operation_id.to_le_bytes());
    mac.update(&receipt.timestamp_ns.to_le_bytes());
    mac.update(&receipt.reported_timestamp_ns.to_le_bytes());
    mac.update(&receipt.rvf_identity);
    mac.update(&receipt.policy_digest);
    mac.update(&receipt.operator_policy_digest);
    mac.update(&[receipt.artifact_origin as u8]);
    mac.update(&receipt.session_nonce);
    mac.update(&[receipt.profile.code()]);
    mac.update(&receipt.platform_facts_digest);
    mac.update(&[receipt.event as u8]);
    mac.update(&[receipt.scope as u8]);
    mac.update(&[receipt.reason as u8]);
    mac.update(&receipt.resource_digest);
    mac.update(&receipt.units.to_le_bytes());
    mac.update(&receipt.duration_ms.to_le_bytes());
    mac.update(&receipt.options.to_le_bytes());
    mac.update(&receipt.detail_code.to_le_bytes());
    mac.update(&receipt.previous_mac);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0; 32];
    output.copy_from_slice(&bytes);
    output
}

fn compute_seal(key: &[u8; 32], count: u64, chain_head: [u8; 32]) -> ReceiptSeal {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(SEAL_DOMAIN);
    mac.update(&count.to_le_bytes());
    mac.update(&chain_head);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0; 32];
    output.copy_from_slice(&bytes);
    ReceiptSeal {
        count,
        chain_head,
        mac: output,
    }
}

fn compute_execution_mac(key: &[u8; 32], seal: &AgentExecutionSeal) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(EXECUTION_DOMAIN);
    mac.update(&seal.invocation_id.to_le_bytes());
    mac.update(&seal.rvf_identity);
    mac.update(&seal.policy_digest);
    mac.update(&seal.operator_policy_digest);
    mac.update(&[seal.artifact_origin as u8]);
    mac.update(&seal.session_nonce);
    mac.update(&[seal.profile.code()]);
    mac.update(&seal.platform_facts_digest);
    mac.update(&seal.reported_started_ns.to_le_bytes());
    mac.update(&seal.started_ns.to_le_bytes());
    mac.update(&seal.reported_ended_ns.to_le_bytes());
    mac.update(&seal.ended_ns.to_le_bytes());
    mac.update(&seal.start_receipt_count.to_le_bytes());
    mac.update(&seal.start_receipt_head);
    mac.update(&seal.module_digest);
    mac.update(&seal.entrypoint_digest);
    mac.update(&seal.runtime_digest);
    mac.update(&seal.limits.module_bytes.to_le_bytes());
    mac.update(&seal.limits.fuel.to_le_bytes());
    mac.update(&seal.limits.memory_bytes.to_le_bytes());
    mac.update(&seal.limits.tables.to_le_bytes());
    mac.update(&seal.limits.table_elements.to_le_bytes());
    mac.update(&seal.limits.memories.to_le_bytes());
    mac.update(&seal.limits.host_calls.to_le_bytes());
    mac.update(&[seal.outcome as u8]);
    mac.update(&seal.result.to_le_bytes());
    mac.update(&seal.fuel_consumed.to_le_bytes());
    mac.update(&seal.host_calls_attempted.to_le_bytes());
    mac.update(&seal.host_calls_dispatched.to_le_bytes());
    mac.update(&seal.receipt_count.to_le_bytes());
    mac.update(&seal.receipt_head);
    mac.update(&seal.previous_execution_mac);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0; 32];
    output.copy_from_slice(&bytes);
    output
}

fn valid_execution_outcome(
    outcome: AgentExecutionOutcome,
    result: i64,
    fuel_consumed: u64,
    host_calls_attempted: u64,
    host_calls_dispatched: u64,
    limits: AgentExecutionLimits,
) -> bool {
    let valid_limits = valid_execution_limits(limits);
    if fuel_consumed > limits.fuel
        || host_calls_dispatched > host_calls_attempted
        || host_calls_dispatched > limits.host_calls
    {
        return false;
    }
    match outcome {
        AgentExecutionOutcome::Completed => valid_limits,
        AgentExecutionOutcome::ExecutableNotVerified => {
            result == 0
                && fuel_consumed == 0
                && host_calls_attempted == 0
                && host_calls_dispatched == 0
        }
        AgentExecutionOutcome::InvalidLimits => {
            !valid_limits
                && result == 0
                && fuel_consumed == 0
                && host_calls_attempted == 0
                && host_calls_dispatched == 0
        }
        AgentExecutionOutcome::InvalidModule => {
            valid_limits
                && result == 0
                && fuel_consumed == 0
                && host_calls_attempted == 0
                && host_calls_dispatched == 0
        }
        AgentExecutionOutcome::LinkRefused
        | AgentExecutionOutcome::StartRefused
        | AgentExecutionOutcome::InvalidEntrypoint
        | AgentExecutionOutcome::ExecutionRefused
        | AgentExecutionOutcome::FuelUnavailable => valid_limits && result == 0,
    }
}

fn valid_execution_limits(limits: AgentExecutionLimits) -> bool {
    let Ok(maximum_module_bytes) = u64::try_from(rvm_wasm_hosted::MAX_HOSTED_MODULE_BYTES) else {
        return false;
    };
    let Ok(maximum_memory_bytes) = u64::try_from(rvm_wasm_hosted::MAX_HOSTED_MEMORY_BYTES) else {
        return false;
    };
    let Ok(maximum_tables) = u64::try_from(rvm_wasm_hosted::MAX_HOSTED_TABLES) else {
        return false;
    };
    (8..=maximum_module_bytes).contains(&limits.module_bytes)
        && (1..=rvm_wasm_hosted::MAX_HOSTED_FUEL).contains(&limits.fuel)
        && (65_536..=maximum_memory_bytes).contains(&limits.memory_bytes)
        && (1..=maximum_tables).contains(&limits.tables)
        && (1..=u64::from(rvm_wasm_hosted::MAX_HOSTED_TABLE_ELEMENTS))
            .contains(&limits.table_elements)
        && limits.memories == 1
        && (1..=rvm_wasm_hosted::MAX_HOSTED_HOST_CALLS).contains(&limits.host_calls)
}

#[allow(clippy::too_many_arguments)]
fn valid_next_event(
    previous: Option<&IosReceipt>,
    operation_id: u64,
    event: ReceiptEvent,
    reason: IosReason,
    scope: IosScope,
    resource_digest: &[u8; 32],
    units: u64,
    duration_ms: u32,
    options: u32,
    detail_code: u32,
) -> bool {
    if operation_id == 0 || !valid_event_outcome(event, reason, detail_code) {
        return false;
    }
    match previous {
        None => matches!(event, ReceiptEvent::Intent | ReceiptEvent::Denied),
        Some(previous) if previous.event == ReceiptEvent::Intent => {
            operation_id == previous.operation_id
                && matches!(event, ReceiptEvent::Completed | ReceiptEvent::Failed)
                && scope == previous.scope
                && resource_digest == &previous.resource_digest
                && units == previous.units
                && duration_ms == previous.duration_ms
                && options == previous.options
        }
        Some(previous) => {
            operation_id > previous.operation_id
                && matches!(event, ReceiptEvent::Intent | ReceiptEvent::Denied)
        }
    }
}

const fn valid_event_outcome(event: ReceiptEvent, reason: IosReason, detail_code: u32) -> bool {
    match event {
        ReceiptEvent::Intent | ReceiptEvent::Completed => {
            matches!(reason, IosReason::Allowed) && detail_code == 0
        }
        ReceiptEvent::Denied => {
            !matches!(reason, IosReason::Allowed | IosReason::NativeFailure) && detail_code == 0
        }
        ReceiptEvent::Failed => matches!(reason, IosReason::NativeFailure),
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> ReceiptChain {
        ReceiptChain::new(
            [7; 32],
            ReceiptSessionIdentity {
                rvf_identity: [1; 32],
                policy_digest: [2; 32],
                operator_policy_digest: [6; 32],
                artifact_origin: IosArtifactOrigin::EmbeddedAppBundle,
                session_nonce: [3; 16],
                profile: HostedIosProfile::IosAppSandboxWasm,
                platform_facts_digest: [8; 32],
            },
            16,
        )
        .expect("bounded test receipt chain reserves")
    }

    #[test]
    fn every_content_field_is_bound_into_the_chain() {
        let mut chain = chain();
        let _ = chain.append(
            1,
            1,
            ReceiptEvent::Intent,
            IosScope::CameraRead,
            IosReason::Allowed,
            [4; 32],
            5,
            6,
            0,
            0,
        );
        let _ = chain.append(
            2,
            1,
            ReceiptEvent::Completed,
            IosScope::CameraRead,
            IosReason::Allowed,
            [4; 32],
            5,
            6,
            0,
            0,
        );
        assert_eq!(chain.verify(), Ok(2));

        let mut copied = chain.receipts().to_vec();
        copied[0].scope = IosScope::LidarRead;
        assert_eq!(
            verify_receipt_chain(&copied, &[7; 32]),
            Err(ReceiptIntegrityError::Content { sequence: 0 })
        );

        let mut copied = chain.receipts().to_vec();
        copied[1].platform_facts_digest[0] ^= 1;
        assert_eq!(
            verify_receipt_chain(&copied, &[7; 32]),
            Err(ReceiptIntegrityError::Content { sequence: 1 })
        );

        let mut copied = chain.receipts().to_vec();
        copied[0].operator_policy_digest[0] ^= 1;
        assert_eq!(
            verify_receipt_chain(&copied, &[7; 32]),
            Err(ReceiptIntegrityError::Content { sequence: 0 })
        );

        let mut copied = chain.receipts().to_vec();
        copied[0].artifact_origin = IosArtifactOrigin::DevelopmentOnly;
        assert_eq!(
            verify_receipt_chain(&copied, &[7; 32]),
            Err(ReceiptIntegrityError::Content { sequence: 0 })
        );
    }

    #[test]
    fn deletion_and_reordering_break_links() {
        let mut chain = chain();
        for timestamp in 1..=3 {
            let _ = chain.append(
                timestamp,
                timestamp,
                ReceiptEvent::Denied,
                IosScope::ClockRead,
                IosReason::InvalidRequest,
                [0; 32],
                1,
                0,
                1,
                0,
            );
        }
        let mut copied = chain.receipts().to_vec();
        copied.swap(0, 1);
        assert!(matches!(
            verify_receipt_chain(&copied, &[7; 32]),
            Err(ReceiptIntegrityError::Link { .. })
        ));

        let copied = vec![chain.receipts()[0], chain.receipts()[2]];
        assert!(matches!(
            verify_receipt_chain(&copied, &[7; 32]),
            Err(ReceiptIntegrityError::Link { .. })
        ));
    }

    #[test]
    fn a_decreasing_host_clock_is_explicitly_clamped_and_authenticated() {
        let mut chain = chain();
        let _ = chain.append(
            2,
            1,
            ReceiptEvent::Intent,
            IosScope::ClockRead,
            IosReason::Allowed,
            [0; 32],
            1,
            1,
            0,
            0,
        );
        let _ = chain.append(
            1,
            1,
            ReceiptEvent::Completed,
            IosScope::ClockRead,
            IosReason::Allowed,
            [0; 32],
            1,
            1,
            0,
            0,
        );
        assert_eq!(chain.receipts()[1].reported_timestamp_ns, 1);
        assert_eq!(chain.receipts()[1].timestamp_ns, 2);
        assert_eq!(chain.verify(), Ok(2));
    }

    #[test]
    fn fixed_capacity_refuses_growth_without_mutating_the_chain() {
        let mut chain = ReceiptChain::new(
            [7; 32],
            ReceiptSessionIdentity {
                rvf_identity: [1; 32],
                policy_digest: [2; 32],
                operator_policy_digest: [6; 32],
                artifact_origin: IosArtifactOrigin::EmbeddedAppBundle,
                session_nonce: [3; 16],
                profile: HostedIosProfile::IosAppSandboxWasm,
                platform_facts_digest: [8; 32],
            },
            2,
        )
        .expect("two-record test chain reserves");
        assert!(chain
            .append(
                1,
                1,
                ReceiptEvent::Denied,
                IosScope::ClockRead,
                IosReason::InvalidRequest,
                [0; 32],
                1,
                1,
                0,
                0,
            )
            .is_ok());
        assert!(chain
            .append(
                2,
                2,
                ReceiptEvent::Denied,
                IosScope::ClockRead,
                IosReason::InvalidRequest,
                [0; 32],
                1,
                1,
                0,
                0,
            )
            .is_ok());
        assert_eq!(
            chain.append(
                3,
                3,
                ReceiptEvent::Denied,
                IosScope::ClockRead,
                IosReason::InvalidRequest,
                [0; 32],
                1,
                1,
                0,
                0,
            ),
            Err(ReceiptIntegrityError::Capacity)
        );
        assert_eq!(chain.receipts().len(), 2);
        assert_eq!(chain.verify(), Ok(2));
    }

    #[test]
    fn pathological_evidence_capacity_is_refused_without_allocating() {
        assert!(matches!(
            ReceiptChain::new(
                [7; 32],
                ReceiptSessionIdentity {
                    rvf_identity: [1; 32],
                    policy_digest: [2; 32],
                    operator_policy_digest: [6; 32],
                    artifact_origin: IosArtifactOrigin::EmbeddedAppBundle,
                    session_nonce: [3; 16],
                    profile: HostedIosProfile::IosAppSandboxWasm,
                    platform_facts_digest: [8; 32],
                },
                usize::MAX,
            ),
            Err(ReceiptIntegrityError::Capacity)
        ));
    }

    #[test]
    fn terminal_seal_detects_valid_prefix_truncation() {
        let mut chain = chain();
        let _ = chain.append(
            1,
            1,
            ReceiptEvent::Intent,
            IosScope::ClockRead,
            IosReason::Allowed,
            [0; 32],
            1,
            1,
            0,
            0,
        );
        let _ = chain.append(
            2,
            1,
            ReceiptEvent::Completed,
            IosScope::ClockRead,
            IosReason::Allowed,
            [0; 32],
            1,
            1,
            0,
            0,
        );
        let _ = chain.append(
            3,
            2,
            ReceiptEvent::Denied,
            IosScope::CameraRead,
            IosReason::ManifestMissing,
            [0; 32],
            1,
            1,
            0,
            0,
        );
        let seal = chain.seal();
        assert_eq!(
            verify_sealed_receipt_chain(chain.receipts(), &[7; 32], &seal),
            Ok(3)
        );
        assert_eq!(
            verify_receipt_chain(&chain.receipts()[..2], &[7; 32]),
            Ok(2)
        );
        assert_eq!(
            verify_sealed_receipt_chain(&chain.receipts()[..2], &[7; 32], &seal),
            Err(ReceiptIntegrityError::Seal)
        );
    }

    #[test]
    fn an_outcome_cannot_change_the_authorized_request() {
        let mut chain = chain();
        assert!(chain
            .append(
                1,
                1,
                ReceiptEvent::Intent,
                IosScope::CameraRead,
                IosReason::Allowed,
                [4; 32],
                5,
                6,
                7,
                0,
            )
            .is_ok());

        assert_eq!(
            chain.append(
                2,
                1,
                ReceiptEvent::Completed,
                IosScope::LidarRead,
                IosReason::Allowed,
                [9; 32],
                5,
                6,
                7,
                0,
            ),
            Err(ReceiptIntegrityError::Pair { sequence: 1 })
        );
        assert_eq!(chain.receipts().len(), 1);
        assert_eq!(
            chain.verify(),
            Err(ReceiptIntegrityError::Pair { sequence: 1 })
        );
    }

    #[test]
    fn execution_seal_binds_guest_outcome_and_complete_receipt_tail() {
        let mut chain = chain();
        let context = chain
            .begin_execution(
                1,
                [7; 32],
                [9; 32],
                [10; 32],
                AgentExecutionLimits::from_hosted(HostedWasmLimits::default()).unwrap(),
            )
            .unwrap();
        chain
            .append(
                1,
                1,
                ReceiptEvent::Intent,
                IosScope::ClockRead,
                IosReason::Allowed,
                [0; 32],
                1,
                1,
                0,
                0,
            )
            .unwrap();
        chain
            .append(
                2,
                1,
                ReceiptEvent::Completed,
                IosScope::ClockRead,
                IosReason::Allowed,
                [0; 32],
                1,
                1,
                0,
                0,
            )
            .unwrap();
        chain
            .append(
                3,
                2,
                ReceiptEvent::Denied,
                IosScope::CameraRead,
                IosReason::OperatorDenied,
                [0; 32],
                1,
                1,
                0,
                0,
            )
            .unwrap();
        let seal = chain
            .seal_execution(&context, 4, AgentExecutionOutcome::Completed, 42, 100, 1, 1)
            .unwrap();
        assert_eq!(
            verify_agent_execution_seal(chain.receipts(), &[7; 32], &seal),
            Ok(3)
        );
        assert_eq!(
            verify_agent_execution_seal(&chain.receipts()[..2], &[7; 32], &seal),
            Err(ReceiptIntegrityError::ExecutionSeal)
        );
        let mut modified = seal;
        modified.result = 43;
        assert_eq!(
            verify_agent_execution_seal(chain.receipts(), &[7; 32], &modified),
            Err(ReceiptIntegrityError::ExecutionSeal)
        );
    }

    #[test]
    fn invocation_ids_and_previous_seals_disambiguate_empty_guest_turns() {
        let mut chain = chain();
        let limits = AgentExecutionLimits::from_hosted(HostedWasmLimits::default()).unwrap();
        let first_context = chain
            .begin_execution(10, [7; 32], [8; 32], [9; 32], limits)
            .unwrap();
        let first = chain
            .seal_execution(
                &first_context,
                11,
                AgentExecutionOutcome::Completed,
                0,
                1,
                0,
                0,
            )
            .unwrap();
        let second_context = chain
            .begin_execution(12, [7; 32], [8; 32], [9; 32], limits)
            .unwrap();
        let second = chain
            .seal_execution(
                &second_context,
                13,
                AgentExecutionOutcome::Completed,
                0,
                1,
                0,
                0,
            )
            .unwrap();

        assert_eq!(first.invocation_id, 1);
        assert_eq!(second.invocation_id, 2);
        assert_eq!(second.previous_execution_mac, first.mac);
        assert_ne!(first.mac, second.mac);
        assert_eq!(
            verify_agent_execution_seal(chain.receipts(), &[7; 32], &second),
            Ok(0)
        );
    }

    #[test]
    fn failure_outcomes_reject_success_values_and_impossible_counters() {
        let mut chain = chain();
        let limits = AgentExecutionLimits::from_hosted(HostedWasmLimits::default()).unwrap();
        let context = chain
            .begin_execution(1, [7; 32], [8; 32], [9; 32], limits)
            .unwrap();
        assert_eq!(
            chain.seal_execution(
                &context,
                2,
                AgentExecutionOutcome::InvalidModule,
                42,
                1,
                2,
                3,
            ),
            Err(ReceiptIntegrityError::Invocation)
        );
    }
}
