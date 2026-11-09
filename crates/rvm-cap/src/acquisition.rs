//! Quarantine and activation checks for resources acquired by autonomous agents.
//!
//! This module deliberately separates provider evidence from RVM authority. A
//! successful acquisition, payment, MCP response, or provider receipt can prove
//! that a resource exists without proving that the resource may become usable
//! authority inside RVM.
//!
//! The types here therefore produce an [`ActivationReceipt`], never a
//! [`rvm_types::CapToken`]. A host that chooses to mint a capability after a
//! successful activation must still perform the ordinary RVM authorization and
//! witness steps against current policy.

use rvm_types::{CapRights, CapType};

/// A fixed-width digest used to bind identities, policy, purpose, and evidence.
pub type Digest32 = [u8; 32];

/// Coarse class of an externally acquired resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquiredResourceKind {
    /// Compute capacity such as a VM, container, accelerator, or worker.
    Compute,
    /// Credential material or an authenticated access handle.
    Credential,
    /// An external account or principal.
    Account,
    /// A network or application service.
    Service,
    /// Another autonomous or delegated agent.
    Agent,
    /// A physical or virtual device.
    Device,
}

/// Authenticated provider evidence after resolution into an RVM-facing shape.
///
/// This structure is evidence only. The `requested_rights` field describes the
/// rights the caller wants mapped into RVM; it does not grant them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedResourceManifest {
    /// Provider-scoped resource identifier.
    pub resource_id: u64,
    /// Resource class resolved from provider evidence.
    pub kind: AcquiredResourceKind,
    /// RVM capability type requested for the resource.
    pub requested_cap_type: CapType,
    /// RVM rights requested for the resource.
    pub requested_rights: CapRights,
    /// Principal for whom the resource was acquired.
    pub principal_digest: Digest32,
    /// Purpose to which the acquisition is bound.
    pub purpose_digest: Digest32,
    /// Authenticated provider identity.
    pub provider_digest: Digest32,
    /// Digest of the provider evidence used by the resolver.
    pub evidence_digest: Digest32,
    /// Version of the resolver that produced this manifest.
    pub resolver_version: u32,
    /// Policy epoch observed during resolution.
    pub policy_epoch: u64,
    /// Provider lifecycle epoch observed during resolution.
    pub provider_epoch: u64,
    /// Graph-wide acquisition epoch observed during resolution.
    pub graph_epoch: u64,
    /// Requested maximum delegation depth for the acquired authority.
    pub delegation_depth: u8,
    /// Maximum privileged effects requested for this resource.
    pub effect_budget: u32,
    /// Maximum data volume requested for this resource.
    pub data_budget_bytes: u64,
    /// Maximum child resources this resource may introduce.
    pub child_budget: u32,
    /// Time at which the provider evidence was resolved, in milliseconds.
    pub resolved_at_ms: u64,
}

/// Host-controlled activation limits for one acquisition graph.
///
/// The envelope must be supplied by an authority outside model-controlled
/// context. It is intentionally exact rather than permissive: resource class,
/// provider, principal, purpose, epochs, and capability type all have to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationEnvelope {
    /// Principal permitted to activate acquired resources.
    pub principal_digest: Digest32,
    /// Purpose under which activation is permitted.
    pub purpose_digest: Digest32,
    /// Provider whose evidence is accepted.
    pub provider_digest: Digest32,
    /// Only resource class permitted by this envelope.
    pub allowed_kind: AcquiredResourceKind,
    /// Only RVM capability type permitted by this envelope.
    pub allowed_cap_type: CapType,
    /// Maximum rights that may be requested by any activated resource.
    pub allowed_rights: CapRights,
    /// Required resolver version.
    pub resolver_version: u32,
    /// Current policy epoch.
    pub policy_epoch: u64,
    /// Current provider epoch.
    pub provider_epoch: u64,
    /// Current acquisition graph epoch.
    pub graph_epoch: u64,
    /// Maximum delegation depth for any activated resource.
    pub max_delegation_depth: u8,
    /// Graph-wide total privileged effect budget.
    pub max_effects: u32,
    /// Graph-wide total data budget.
    pub max_data_bytes: u64,
    /// Graph-wide total child-resource budget.
    pub max_children: u32,
    /// Maximum accepted age of provider evidence in milliseconds.
    pub max_evidence_age_ms: u64,
    /// Time after which this envelope may no longer be used.
    pub expires_at_ms: u64,
}

/// Monotonic graph-wide activation state.
///
/// Keeping aggregate budgets in one ledger prevents a caller from splitting one
/// oversized request into many individually valid acquisitions. A durable host
/// integration must persist this state atomically across crashes and retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationLedger {
    remaining_effects: u32,
    remaining_data_bytes: u64,
    remaining_children: u32,
    last_sequence: u64,
    policy_epoch: u64,
    provider_epoch: u64,
    graph_epoch: u64,
}

impl ActivationLedger {
    /// Create an empty activation ledger bound to an envelope's aggregate limits.
    #[must_use]
    pub const fn new(envelope: &ActivationEnvelope) -> Self {
        Self {
            remaining_effects: envelope.max_effects,
            remaining_data_bytes: envelope.max_data_bytes,
            remaining_children: envelope.max_children,
            last_sequence: 0,
            policy_epoch: envelope.policy_epoch,
            provider_epoch: envelope.provider_epoch,
            graph_epoch: envelope.graph_epoch,
        }
    }

    /// Remaining privileged effect budget.
    #[must_use]
    pub const fn remaining_effects(&self) -> u32 {
        self.remaining_effects
    }

    /// Remaining data budget in bytes.
    #[must_use]
    pub const fn remaining_data_bytes(&self) -> u64 {
        self.remaining_data_bytes
    }

    /// Remaining child-resource budget.
    #[must_use]
    pub const fn remaining_children(&self) -> u32 {
        self.remaining_children
    }

    /// Last successfully consumed activation sequence number.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

/// Trusted adapter that authenticates provider evidence.
///
/// Implementations must validate evidence independently of model-provided text.
/// A verifier that simply echoes model output defeats the security boundary.
pub trait ProviderEvidenceVerifier {
    /// Return the resolver version this verifier is prepared to authenticate.
    fn resolver_version(&self) -> u32;

    /// Authenticate the manifest against provider evidence held by the host.
    fn verify(&self, manifest: &ResolvedResourceManifest) -> bool;
}

/// An externally acquired resource that is not yet eligible for RVM authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantinedResource {
    manifest: ResolvedResourceManifest,
}

impl QuarantinedResource {
    /// Place a resolved provider manifest in quarantine.
    #[must_use]
    pub const fn new(manifest: ResolvedResourceManifest) -> Self {
        Self { manifest }
    }

    /// Inspect the quarantined manifest without activating it.
    #[must_use]
    pub const fn manifest(&self) -> &ResolvedResourceManifest {
        &self.manifest
    }

    /// Attempt to produce an evidence-only activation receipt.
    ///
    /// Every check is completed before the shared ledger is mutated, so a
    /// rejected activation cannot consume or otherwise change aggregate budget.
    pub fn activate<V: ProviderEvidenceVerifier>(
        &self,
        sequence: u64,
        now_ms: u64,
        envelope: &ActivationEnvelope,
        ledger: &mut ActivationLedger,
        verifier: &V,
    ) -> Result<ActivationReceipt, ActivationError> {
        let manifest = &self.manifest;

        if !verifier.verify(manifest) {
            return Err(ActivationError::EvidenceRejected);
        }
        if manifest.resolver_version != verifier.resolver_version()
            || manifest.resolver_version != envelope.resolver_version
        {
            return Err(ActivationError::ResolverVersionMismatch);
        }
        if manifest.policy_epoch != envelope.policy_epoch
            || ledger.policy_epoch != envelope.policy_epoch
        {
            return Err(ActivationError::PolicyEpochMismatch);
        }
        if manifest.provider_epoch != envelope.provider_epoch
            || ledger.provider_epoch != envelope.provider_epoch
        {
            return Err(ActivationError::ProviderEpochMismatch);
        }
        if manifest.graph_epoch != envelope.graph_epoch || ledger.graph_epoch != envelope.graph_epoch {
            return Err(ActivationError::GraphEpochMismatch);
        }
        if manifest.principal_digest != envelope.principal_digest {
            return Err(ActivationError::PrincipalMismatch);
        }
        if manifest.purpose_digest != envelope.purpose_digest {
            return Err(ActivationError::PurposeMismatch);
        }
        if manifest.provider_digest != envelope.provider_digest {
            return Err(ActivationError::ProviderMismatch);
        }
        if manifest.kind != envelope.allowed_kind {
            return Err(ActivationError::ResourceKindMismatch);
        }
        if manifest.requested_cap_type != envelope.allowed_cap_type {
            return Err(ActivationError::CapabilityTypeMismatch);
        }
        if !envelope.allowed_rights.contains(manifest.requested_rights) {
            return Err(ActivationError::RightsAmplification);
        }
        if manifest.delegation_depth > envelope.max_delegation_depth {
            return Err(ActivationError::DelegationExpansion);
        }
        if now_ms > envelope.expires_at_ms {
            return Err(ActivationError::EnvelopeExpired);
        }
        if manifest.resolved_at_ms > now_ms {
            return Err(ActivationError::EvidenceFromFuture);
        }
        if now_ms.saturating_sub(manifest.resolved_at_ms) > envelope.max_evidence_age_ms {
            return Err(ActivationError::EvidenceStale);
        }
        if sequence == 0 || sequence <= ledger.last_sequence {
            return Err(ActivationError::ReplaySequence);
        }

        let remaining_effects = ledger
            .remaining_effects
            .checked_sub(manifest.effect_budget)
            .ok_or(ActivationError::EffectBudgetExceeded)?;
        let remaining_data_bytes = ledger
            .remaining_data_bytes
            .checked_sub(manifest.data_budget_bytes)
            .ok_or(ActivationError::DataBudgetExceeded)?;
        let remaining_children = ledger
            .remaining_children
            .checked_sub(manifest.child_budget)
            .ok_or(ActivationError::ChildBudgetExceeded)?;

        ledger.remaining_effects = remaining_effects;
        ledger.remaining_data_bytes = remaining_data_bytes;
        ledger.remaining_children = remaining_children;
        ledger.last_sequence = sequence;

        Ok(ActivationReceipt {
            resource_id: manifest.resource_id,
            kind: manifest.kind,
            cap_type: manifest.requested_cap_type,
            rights: manifest.requested_rights,
            provider_digest: manifest.provider_digest,
            evidence_digest: manifest.evidence_digest,
            policy_epoch: manifest.policy_epoch,
            provider_epoch: manifest.provider_epoch,
            graph_epoch: manifest.graph_epoch,
            sequence,
        })
    }
}

/// Evidence that an acquired resource passed the quarantine activation checks.
///
/// A receipt never grants an RVM capability. Its sole purpose is to let a later
/// independently-authorized capability issuance bind to the exact checked
/// acquisition evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationReceipt {
    resource_id: u64,
    kind: AcquiredResourceKind,
    cap_type: CapType,
    rights: CapRights,
    provider_digest: Digest32,
    evidence_digest: Digest32,
    policy_epoch: u64,
    provider_epoch: u64,
    graph_epoch: u64,
    sequence: u64,
}

impl ActivationReceipt {
    /// Activated provider resource identifier.
    #[must_use]
    pub const fn resource_id(&self) -> u64 {
        self.resource_id
    }

    /// Activated resource class.
    #[must_use]
    pub const fn kind(&self) -> AcquiredResourceKind {
        self.kind
    }

    /// Requested RVM capability type checked by the activation boundary.
    #[must_use]
    pub const fn cap_type(&self) -> CapType {
        self.cap_type
    }

    /// Requested RVM rights checked by the activation boundary.
    #[must_use]
    pub const fn rights(&self) -> CapRights {
        self.rights
    }

    /// Authenticated provider identity bound to the receipt.
    #[must_use]
    pub const fn provider_digest(&self) -> Digest32 {
        self.provider_digest
    }

    /// Provider evidence digest bound to the receipt.
    #[must_use]
    pub const fn evidence_digest(&self) -> Digest32 {
        self.evidence_digest
    }

    /// Policy epoch checked during activation.
    #[must_use]
    pub const fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    /// Provider epoch checked during activation.
    #[must_use]
    pub const fn provider_epoch(&self) -> u64 {
        self.provider_epoch
    }

    /// Acquisition graph epoch checked during activation.
    #[must_use]
    pub const fn graph_epoch(&self) -> u64 {
        self.graph_epoch
    }

    /// Monotonic activation sequence consumed by this receipt.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Whether this receipt itself grants RVM authority.
    ///
    /// This is intentionally always false. Authority requires a separate live
    /// RVM capability decision.
    #[must_use]
    pub const fn grants_authority(&self) -> bool {
        false
    }
}

/// Reasons an acquired resource cannot leave quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    /// Provider evidence failed authentication.
    EvidenceRejected,
    /// Manifest, verifier, and envelope resolver versions disagree.
    ResolverVersionMismatch,
    /// Policy epoch is stale or substituted.
    PolicyEpochMismatch,
    /// Provider lifecycle epoch is stale or substituted.
    ProviderEpochMismatch,
    /// Acquisition graph epoch is stale or substituted.
    GraphEpochMismatch,
    /// Principal differs from the host-controlled envelope.
    PrincipalMismatch,
    /// Purpose differs from the host-controlled envelope.
    PurposeMismatch,
    /// Provider identity differs from the host-controlled envelope.
    ProviderMismatch,
    /// Resource class differs from the allowed class.
    ResourceKindMismatch,
    /// Requested RVM capability type differs from the allowed type.
    CapabilityTypeMismatch,
    /// Requested RVM rights exceed the envelope.
    RightsAmplification,
    /// Requested delegation depth exceeds the envelope.
    DelegationExpansion,
    /// The activation envelope has expired.
    EnvelopeExpired,
    /// Provider evidence is timestamped after the activation check.
    EvidenceFromFuture,
    /// Provider evidence is older than the allowed freshness window.
    EvidenceStale,
    /// Activation sequence is zero, repeated, or out of order.
    ReplaySequence,
    /// Requested effects exceed the remaining graph-wide budget.
    EffectBudgetExceeded,
    /// Requested data exceeds the remaining graph-wide budget.
    DataBudgetExceeded,
    /// Requested child resources exceed the remaining graph-wide budget.
    ChildBudgetExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINCIPAL: Digest32 = [1; 32];
    const PURPOSE: Digest32 = [2; 32];
    const PROVIDER: Digest32 = [3; 32];
    const EVIDENCE: Digest32 = [4; 32];

    struct TestVerifier {
        version: u32,
        accept: bool,
    }

    impl ProviderEvidenceVerifier for TestVerifier {
        fn resolver_version(&self) -> u32 {
            self.version
        }

        fn verify(&self, _manifest: &ResolvedResourceManifest) -> bool {
            self.accept
        }
    }

    fn envelope() -> ActivationEnvelope {
        ActivationEnvelope {
            principal_digest: PRINCIPAL,
            purpose_digest: PURPOSE,
            provider_digest: PROVIDER,
            allowed_kind: AcquiredResourceKind::Service,
            allowed_cap_type: CapType::Context,
            allowed_rights: CapRights::READ | CapRights::EXECUTE,
            resolver_version: 7,
            policy_epoch: 11,
            provider_epoch: 13,
            graph_epoch: 17,
            max_delegation_depth: 1,
            max_effects: 4,
            max_data_bytes: 1_024,
            max_children: 2,
            max_evidence_age_ms: 1_000,
            expires_at_ms: 20_000,
        }
    }

    fn manifest() -> ResolvedResourceManifest {
        ResolvedResourceManifest {
            resource_id: 42,
            kind: AcquiredResourceKind::Service,
            requested_cap_type: CapType::Context,
            requested_rights: CapRights::READ,
            principal_digest: PRINCIPAL,
            purpose_digest: PURPOSE,
            provider_digest: PROVIDER,
            evidence_digest: EVIDENCE,
            resolver_version: 7,
            policy_epoch: 11,
            provider_epoch: 13,
            graph_epoch: 17,
            delegation_depth: 1,
            effect_budget: 2,
            data_budget_bytes: 256,
            child_budget: 1,
            resolved_at_ms: 10_000,
        }
    }

    #[test]
    fn clean_acquisition_produces_evidence_only_receipt() {
        let env = envelope();
        let mut ledger = ActivationLedger::new(&env);
        let resource = QuarantinedResource::new(manifest());
        let receipt = resource
            .activate(
                1,
                10_500,
                &env,
                &mut ledger,
                &TestVerifier {
                    version: 7,
                    accept: true,
                },
            )
            .expect("clean resource should leave quarantine");

        assert_eq!(receipt.resource_id(), 42);
        assert_eq!(receipt.rights(), CapRights::READ);
        assert!(!receipt.grants_authority());
        assert_eq!(ledger.remaining_effects(), 2);
        assert_eq!(ledger.remaining_data_bytes(), 768);
        assert_eq!(ledger.remaining_children(), 1);
        assert_eq!(ledger.last_sequence(), 1);
    }

    #[test]
    fn rejected_evidence_fails_closed_without_mutating_ledger() {
        let env = envelope();
        let mut ledger = ActivationLedger::new(&env);
        let before = ledger;
        let result = QuarantinedResource::new(manifest()).activate(
            1,
            10_500,
            &env,
            &mut ledger,
            &TestVerifier {
                version: 7,
                accept: false,
            },
        );

        assert_eq!(result, Err(ActivationError::EvidenceRejected));
        assert_eq!(ledger, before);
    }

    #[test]
    fn rights_amplification_is_rejected() {
        let env = envelope();
        let mut hostile = manifest();
        hostile.requested_rights = CapRights::READ | CapRights::WRITE;
        let mut ledger = ActivationLedger::new(&env);
        let result = QuarantinedResource::new(hostile).activate(
            1,
            10_500,
            &env,
            &mut ledger,
            &TestVerifier {
                version: 7,
                accept: true,
            },
        );

        assert_eq!(result, Err(ActivationError::RightsAmplification));
    }

    #[test]
    fn stale_epochs_are_rejected() {
        let env = envelope();
        let mut stale = manifest();
        stale.graph_epoch -= 1;
        let mut ledger = ActivationLedger::new(&env);
        let result = QuarantinedResource::new(stale).activate(
            1,
            10_500,
            &env,
            &mut ledger,
            &TestVerifier {
                version: 7,
                accept: true,
            },
        );

        assert_eq!(result, Err(ActivationError::GraphEpochMismatch));
    }

    #[test]
    fn replay_sequence_is_rejected() {
        let env = envelope();
        let resource = QuarantinedResource::new(manifest());
        let verifier = TestVerifier {
            version: 7,
            accept: true,
        };
        let mut ledger = ActivationLedger::new(&env);
        resource
            .activate(1, 10_500, &env, &mut ledger, &verifier)
            .expect("first activation should succeed");
        let result = resource.activate(1, 10_500, &env, &mut ledger, &verifier);

        assert_eq!(result, Err(ActivationError::ReplaySequence));
    }

    #[test]
    fn split_acquisition_cannot_evade_graph_budget() {
        let env = envelope();
        let verifier = TestVerifier {
            version: 7,
            accept: true,
        };
        let first = QuarantinedResource::new(manifest());
        let mut second_manifest = manifest();
        second_manifest.resource_id = 43;
        second_manifest.effect_budget = 3;
        let second = QuarantinedResource::new(second_manifest);
        let mut ledger = ActivationLedger::new(&env);

        first
            .activate(1, 10_500, &env, &mut ledger, &verifier)
            .expect("first resource should fit budget");
        let before = ledger;
        let result = second.activate(2, 10_500, &env, &mut ledger, &verifier);

        assert_eq!(result, Err(ActivationError::EffectBudgetExceeded));
        assert_eq!(ledger, before);
    }

    #[test]
    fn stale_evidence_is_rejected() {
        let env = envelope();
        let mut ledger = ActivationLedger::new(&env);
        let result = QuarantinedResource::new(manifest()).activate(
            1,
            11_001,
            &env,
            &mut ledger,
            &TestVerifier {
                version: 7,
                accept: true,
            },
        );

        assert_eq!(result, Err(ActivationError::EvidenceStale));
    }

    #[test]
    fn provider_substitution_is_rejected() {
        let env = envelope();
        let mut substituted = manifest();
        substituted.provider_digest = [9; 32];
        let mut ledger = ActivationLedger::new(&env);
        let result = QuarantinedResource::new(substituted).activate(
            1,
            10_500,
            &env,
            &mut ledger,
            &TestVerifier {
                version: 7,
                accept: true,
            },
        );

        assert_eq!(result, Err(ActivationError::ProviderMismatch));
    }

    #[test]
    fn future_evidence_is_rejected() {
        let env = envelope();
        let mut future = manifest();
        future.resolved_at_ms = 11_000;
        let mut ledger = ActivationLedger::new(&env);
        let result = QuarantinedResource::new(future).activate(
            1,
            10_500,
            &env,
            &mut ledger,
            &TestVerifier {
                version: 7,
                accept: true,
            },
        );

        assert_eq!(result, Err(ActivationError::EvidenceFromFuture));
    }
}