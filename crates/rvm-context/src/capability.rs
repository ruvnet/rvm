//! Live capability binding and authorization for `ruv://` operations.
//!
//! A URI is never authority. This module resolves an opaque capability handle
//! against a live [`CapabilityManager`], then verifies its generation, epoch,
//! rights, type, owner, and trusted namespace binding before any resolver is
//! called. Raw [`rvm_types::CapToken`] values are intentionally not accepted.

use crate::error::{ContextError, ContextResult};
use crate::uri::{Authority, Collection, PathSegment, ProgressiveView, RuvUri, Subject, TenantId};
use alloc::string::ToString;
use alloc::vec::Vec;
use rvm_cap::{CapManagerConfig, CapabilityManager};
use rvm_types::{ActionKind, CapRights, CapType, PartitionId, WitnessRecord};
use rvm_witness::WitnessLog;
use sha2::{Digest, Sha256};

/// Maximum number of entries returned by one governed search.
pub const MAX_SEARCH_RESULTS: usize = 64;

/// An index and generation pair into the live RVM capability table.
///
/// Handles are safe to accept from an untrusted caller because authorization
/// always resolves them through the manager and rejects stale generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilityHandle {
    index: u32,
    generation: u32,
}

impl CapabilityHandle {
    /// Construct a handle received from an RVM partition boundary.
    #[must_use]
    pub const fn new(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

    /// Return the capability-table index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Return the generation used for stale-handle detection.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// A governed operation over the context namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ContextOperation {
    /// Resolve an immutable revision or versionless alias.
    Resolve = 0,
    /// List direct children below a context path.
    List = 1,
    /// Traverse context containment below a path.
    Tree = 2,
    /// Read context bytes or a derived representation.
    Read = 3,
    /// Enumerate semantically relevant context candidates.
    Search = 4,
    /// Inspect prior immutable revisions of an alias.
    History = 5,
    /// Verify a revision and produce proof material.
    Verify = 6,
    /// Register a new immutable whole-RVF revision.
    Put = 7,
    /// Advance a versionless alias with compare-and-swap.
    CompareAndSwapAlias = 8,
    /// Advance an alias to a tombstone revision.
    Forget = 9,
    /// Authorize execution without granting readable bytes.
    Execute = 10,
    /// Delegate a narrower context capability.
    Grant = 11,
    /// Revoke a context capability lineage.
    Revoke = 12,
    /// Seal witnessed decisions into an external receipt.
    SealReceipt = 13,
}

impl ContextOperation {
    /// Return the exact RVM rights required for this operation.
    #[must_use]
    pub const fn required_rights(self) -> CapRights {
        match self {
            Self::Resolve | Self::List | Self::Tree | Self::Read | Self::Search | Self::History => {
                CapRights::READ
            }
            Self::Verify => CapRights::READ.union(CapRights::PROVE),
            Self::Put | Self::CompareAndSwapAlias | Self::Forget => CapRights::WRITE,
            Self::Execute => CapRights::EXECUTE,
            Self::Grant => CapRights::GRANT,
            Self::Revoke => CapRights::REVOKE,
            Self::SealReceipt => CapRights::PROVE,
        }
    }

    /// Return the witness action emitted after a successful operation.
    #[must_use]
    pub const fn action_kind(self) -> ActionKind {
        match self {
            Self::Resolve | Self::List | Self::Tree | Self::History | Self::Verify => {
                ActionKind::ContextResolve
            }
            Self::Read => ActionKind::ContextRead,
            Self::Search => ActionKind::ContextSearch,
            Self::Put => ActionKind::ContextPut,
            Self::CompareAndSwapAlias => ActionKind::ContextAliasUpdate,
            Self::Forget => ActionKind::ContextForget,
            Self::Execute => ActionKind::ContextExecute,
            Self::Grant => ActionKind::CapabilityGrant,
            Self::Revoke => ActionKind::CapabilityRevoke,
            Self::SealReceipt => ActionKind::ContextEpochSeal,
        }
    }

    fn required_view_bit(self, explicit: Option<ProgressiveView>) -> u8 {
        if let Some(view) = explicit {
            return view_bit(view);
        }
        match self {
            Self::Resolve | Self::List | Self::Tree | Self::History | Self::Verify => {
                ContextViewMask::MANIFEST.0
            }
            Self::Read => ContextViewMask::CONTENT.0,
            Self::Search => ContextViewMask::OVERVIEW.0,
            Self::Put
            | Self::CompareAndSwapAlias
            | Self::Forget
            | Self::Execute
            | Self::Grant
            | Self::Revoke
            | Self::SealReceipt => 0,
        }
    }

    fn target_shape_is_valid(self, target: &RuvUri) -> bool {
        match self {
            Self::Put | Self::Verify | Self::SealReceipt => {
                target.is_pinned() && target.view().is_none()
            }
            Self::Execute => {
                target.is_pinned()
                    && target.view().is_none()
                    && target.collection() == Collection::Skills
            }
            Self::List | Self::Tree | Self::History | Self::CompareAndSwapAlias | Self::Forget => {
                !target.is_pinned() && target.view().is_none()
            }
            Self::Grant | Self::Revoke => target.view().is_none(),
            Self::Resolve | Self::Read | Self::Search => true,
        }
    }
}

/// Bit mask of progressive representations a context grant may disclose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextViewMask(u8);

impl ContextViewMask {
    /// Permit manifest metadata.
    pub const MANIFEST: Self = Self(0x01);
    /// Permit the compact abstract representation.
    pub const ABSTRACT: Self = Self(0x02);
    /// Permit the navigational overview representation.
    pub const OVERVIEW: Self = Self(0x04);
    /// Permit full L2 content bytes.
    pub const CONTENT: Self = Self(0x08);
    /// Backward-compatible spelling for full L2 content bytes.
    pub const RAW: Self = Self::CONTENT;
    /// Permit every v1 representation.
    pub const ALL: Self = Self(0x0f);

    /// Construct a mask from known bits, rejecting reserved bits.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits != 0 && bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the underlying stable bit representation.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Combine two view masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether this mask permits a representation.
    #[must_use]
    pub const fn allows(self, view: ProgressiveView) -> bool {
        let bit = view_bit(view);
        self.0 & bit == bit
    }

    /// Whether `other` is equal to or narrower than this mask.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

const fn view_bit(view: ProgressiveView) -> u8 {
    match view {
        ProgressiveView::Abstract => ContextViewMask::ABSTRACT.0,
        ProgressiveView::Overview => ContextViewMask::OVERVIEW.0,
        ProgressiveView::Content => ContextViewMask::CONTENT.0,
    }
}

/// A trusted namespace and path-prefix binding for one capability lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextScope {
    authority: Authority,
    tenant: TenantId,
    subject: Subject,
    collection: Collection,
    path_prefix: Vec<PathSegment>,
    views: ContextViewMask,
}

impl ContextScope {
    /// Bind a scope to the typed identity and segment prefix of `root`.
    ///
    /// A revision and view on `root` do not become part of the authority;
    /// revision immutability and requested views are checked independently.
    #[must_use]
    pub fn from_uri(root: &RuvUri, views: ContextViewMask) -> Self {
        Self {
            authority: root.authority().clone(),
            tenant: root.tenant().clone(),
            subject: root.subject().clone(),
            collection: root.collection(),
            path_prefix: root.path().to_vec(),
            views,
        }
    }

    /// Return the bound authority.
    #[must_use]
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Return the bound tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Return the bound subject.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Return the bound collection.
    #[must_use]
    pub const fn collection(&self) -> Collection {
        self.collection
    }

    /// Return the path-segment prefix.
    #[must_use]
    pub fn path_prefix(&self) -> &[PathSegment] {
        &self.path_prefix
    }

    /// Return the permitted progressive representations.
    #[must_use]
    pub const fn views(&self) -> ContextViewMask {
        self.views
    }

    /// Whether `child` is equal to or narrower than this trusted scope.
    #[must_use]
    pub fn contains_scope(&self, child: &Self) -> bool {
        self.authority == child.authority
            && self.tenant == child.tenant
            && self.subject == child.subject
            && self.collection == child.collection
            && path_has_prefix(&child.path_prefix, &self.path_prefix)
            && self.views.contains(child.views)
    }

    fn allows(&self, target: &RuvUri, operation: ContextOperation) -> bool {
        if &self.authority != target.authority()
            || &self.tenant != target.tenant()
            || &self.subject != target.subject()
            || self.collection != target.collection()
            || !path_has_prefix(target.path(), &self.path_prefix)
        {
            return false;
        }
        let required_view = operation.required_view_bit(target.view());
        self.views.bits() & required_view == required_view
    }

    fn fingerprint(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(b"RUV-CONTEXT-SCOPE-V1");
        // `Display` for each of these is exactly `f.write_str(self.as_str())`,
        // so `as_str` hashes byte-identical input to the `to_string` this
        // replaces -- without allocating a String per component to read it.
        // `fingerprint_is_unchanged_by_the_as_str_rewrite` pins that.
        hasher.update(self.authority.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.tenant.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.subject.kind().as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.subject.id().as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.collection.as_str().as_bytes());
        for segment in &self.path_prefix {
            hasher.update([0xff]);
            hasher.update(segment.as_str().as_bytes());
        }
        hasher.update([self.views.bits()]);
        let digest = hasher.finalize();
        let mut first = [0u8; 8];
        first.copy_from_slice(&digest[..8]);
        u64::from_le_bytes(first)
    }
}

fn path_has_prefix(path: &[PathSegment], prefix: &[PathSegment]) -> bool {
    path.len() >= prefix.len() && &path[..prefix.len()] == prefix
}

/// One request presented to the governed runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRequest {
    capability: CapabilityHandle,
    operation: ContextOperation,
    target: RuvUri,
}

impl ContextRequest {
    /// Construct an untrusted request. Authorization occurs later.
    #[must_use]
    pub fn new(capability: CapabilityHandle, operation: ContextOperation, target: RuvUri) -> Self {
        Self {
            capability,
            operation,
            target,
        }
    }

    /// Return the opaque capability handle.
    #[must_use]
    pub const fn capability(&self) -> CapabilityHandle {
        self.capability
    }

    /// Return the requested operation.
    #[must_use]
    pub const fn operation(&self) -> ContextOperation {
        self.operation
    }

    /// Return the canonical target.
    #[must_use]
    pub const fn target(&self) -> &RuvUri {
        &self.target
    }
}

/// A request proven against the live capability and trusted scope tables.
///
/// Fields and construction are private. Resolver implementations receive this
/// type only after the runtime has appended a P1 allow witness record.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedRequest {
    actor: PartitionId,
    operation: ContextOperation,
    target: RuvUri,
    capability_hash: u32,
    witness_sequence: u64,
    timestamp_ns: u64,
}

impl AuthorizedRequest {
    /// Return the authorized actor.
    #[must_use]
    pub const fn actor(&self) -> PartitionId {
        self.actor
    }

    /// Return the one authorized operation.
    #[must_use]
    pub const fn operation(&self) -> ContextOperation {
        self.operation
    }

    /// Return the exact authorized target.
    #[must_use]
    pub const fn target(&self) -> &RuvUri {
        &self.target
    }

    /// Return the non-secret truncated capability identifier.
    #[must_use]
    pub const fn capability_hash(&self) -> u32 {
        self.capability_hash
    }

    /// Return the allow witness sequence emitted before resolver access.
    #[must_use]
    pub const fn witness_sequence(&self) -> u64 {
        self.witness_sequence
    }
}

/// Trusted scope binding for one live capability token identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextGrant {
    token_id: u64,
    scope: ContextScope,
}

impl ContextGrant {
    /// Return the live capability token identifier this binding protects.
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token_id
    }

    /// Return the trusted scope.
    #[must_use]
    pub const fn scope(&self) -> &ContextScope {
        &self.scope
    }
}

/// A const-bounded trusted binding table.
///
/// The table is keyed by live token identifier rather than `CapSlot.badge`:
/// badges may change during ordinary capability delegation and are therefore
/// not a safe authority binding.
#[derive(Debug)]
pub struct ContextGrantTable<const N: usize> {
    grants: Vec<ContextGrant>,
}

impl<const N: usize> ContextGrantTable<N> {
    /// Create an empty binding table.
    #[must_use]
    pub const fn new() -> Self {
        Self { grants: Vec::new() }
    }

    /// Return the number of trusted bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether no capability has a trusted binding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Return the compile-time capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Look up a binding by live token identifier.
    #[must_use]
    pub fn get(&self, token_id: u64) -> Option<&ContextGrant> {
        self.grants.iter().find(|grant| grant.token_id == token_id)
    }

    fn bind(&mut self, token_id: u64, scope: ContextScope) -> ContextResult<()> {
        if let Some(existing) = self.get(token_id) {
            return if existing.scope == scope {
                Ok(())
            } else {
                Err(ContextError::GrantAlreadyBound)
            };
        }
        if self.grants.len() >= N {
            return Err(ContextError::GrantTableFull);
        }
        self.grants.push(ContextGrant { token_id, scope });
        Ok(())
    }

    fn retain_live<const C: usize>(&mut self, manager: &CapabilityManager<C>) {
        self.grants.retain(|grant| {
            manager
                .table()
                .iter()
                .any(|(_, slot)| slot.token.id() == grant.token_id)
        });
    }

    fn clear(&mut self) {
        self.grants.clear();
    }
}

impl<const N: usize> Default for ContextGrantTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Owner of live context capabilities and their trusted scope bindings.
///
/// Keeping the capability manager inside this authority prevents callers from
/// minting an unbound `Context` capability through a parallel mutable path.
pub struct ContextAuthority<const C: usize, const G: usize> {
    manager: CapabilityManager<C>,
    grants: ContextGrantTable<G>,
}

impl<const C: usize, const G: usize> ContextAuthority<C, G> {
    /// Wrap a capability manager and begin with no trusted context bindings.
    #[must_use]
    pub const fn new(manager: CapabilityManager<C>) -> Self {
        Self {
            manager,
            grants: ContextGrantTable::new(),
        }
    }

    /// Create an authority with the default RVM capability configuration.
    #[must_use]
    pub const fn with_defaults() -> Self {
        Self::new(CapabilityManager::new(CapManagerConfig::new()))
    }

    /// Return read-only access to the live capability manager.
    #[must_use]
    pub const fn capability_manager(&self) -> &CapabilityManager<C> {
        &self.manager
    }

    /// Return read-only access to trusted bindings.
    #[must_use]
    pub const fn grants(&self) -> &ContextGrantTable<G> {
        &self.grants
    }

    /// Issue and bind a root context capability.
    ///
    /// # Errors
    ///
    /// Only the hypervisor may issue a root. Capability-table and grant-table
    /// capacity errors are returned without leaving an unbound live grant.
    pub fn issue_root(
        &mut self,
        scope: ContextScope,
        rights: CapRights,
        owner: PartitionId,
        caller: PartitionId,
    ) -> ContextResult<CapabilityHandle> {
        let badge = scope.fingerprint();
        let (index, generation) = self.manager.create_root_capability_checked(
            CapType::Context,
            rights,
            badge,
            owner,
            caller,
        )?;
        let handle = CapabilityHandle::new(index, generation);
        let token_id = self.manager.table().lookup(index, generation)?.token.id();
        if let Err(error) = self.grants.bind(token_id, scope) {
            let _ = self.manager.revoke(index, generation);
            return Err(error);
        }
        Ok(handle)
    }

    /// Bind an existing live context capability supplied by trusted kernel code.
    ///
    /// # Errors
    ///
    /// Refuses stale handles and every capability type except
    /// [`CapType::Context`]. This is an administrative integration path, not a
    /// partition-facing request API.
    pub fn bind_existing(
        &mut self,
        handle: CapabilityHandle,
        scope: ContextScope,
    ) -> ContextResult<()> {
        self.manager
            .verify_p1(handle.index, handle.generation, CapRights::empty())
            .map_err(|_| ContextError::AccessDenied)?;
        let slot = self
            .manager
            .table()
            .lookup(handle.index, handle.generation)
            .map_err(|_| ContextError::AccessDenied)?;
        if slot.token.cap_type() != CapType::Context {
            return Err(ContextError::AccessDenied);
        }
        self.grants.bind(slot.token.id(), scope)
    }

    /// Delegate a capability to an equal or narrower trusted context scope.
    ///
    /// # Errors
    ///
    /// Refuses scope or view widening, missing `GRANT`, ownership mismatch,
    /// rights escalation, stale handles, and capacity exhaustion.
    pub fn delegate(
        &mut self,
        source: CapabilityHandle,
        child_scope: ContextScope,
        requested_rights: CapRights,
        target_owner: PartitionId,
        caller: PartitionId,
    ) -> ContextResult<CapabilityHandle> {
        self.manager
            .verify_p1(source.index, source.generation, CapRights::GRANT)
            .map_err(|_| ContextError::AccessDenied)?;
        let source_slot = *self
            .manager
            .table()
            .lookup(source.index, source.generation)
            .map_err(|_| ContextError::AccessDenied)?;
        if source_slot.token.cap_type() != CapType::Context || source_slot.owner != caller {
            return Err(ContextError::AccessDenied);
        }
        let parent = self
            .grants
            .get(source_slot.token.id())
            .ok_or(ContextError::AccessDenied)?;
        if !parent.scope.contains_scope(&child_scope) {
            return Err(ContextError::ScopeEscalation);
        }

        let badge = child_scope.fingerprint();
        let (index, generation) = self.manager.grant_checked(
            source.index,
            source.generation,
            requested_rights,
            badge,
            target_owner,
            caller,
        )?;
        let handle = CapabilityHandle::new(index, generation);
        let token_id = self.manager.table().lookup(index, generation)?.token.id();
        if let Err(error) = self.grants.bind(token_id, child_scope) {
            let _ = self.manager.revoke(index, generation);
            return Err(error);
        }
        Ok(handle)
    }

    /// Revoke a capability and all descendants, then prune stale bindings.
    ///
    /// # Errors
    ///
    /// Returns the capability manager's error for an invalid or stale handle.
    pub fn revoke(&mut self, handle: CapabilityHandle) -> ContextResult<usize> {
        let result = self.manager.revoke(handle.index, handle.generation)?;
        self.grants.retain_live(&self.manager);
        Ok(result.revoked_count)
    }

    /// Rotate the capability epoch, immediately invalidating prior handles.
    pub fn increment_epoch(&mut self) {
        self.manager.increment_epoch();
        self.grants.clear();
    }

    pub(crate) fn authorize<const W: usize>(
        &self,
        actor: PartitionId,
        timestamp_ns: u64,
        request: &ContextRequest,
        expected_operation: ContextOperation,
        witness: &WitnessLog<W>,
    ) -> ContextResult<AuthorizedRequest> {
        let record_denial = |capability_hash| {
            Self::emit_denied(actor, timestamp_ns, request, witness, capability_hash);
        };
        if request.operation != expected_operation
            || !expected_operation.target_shape_is_valid(&request.target)
        {
            record_denial(handle_fingerprint(request.capability));
            return Err(if request.operation != expected_operation {
                ContextError::OperationMismatch
            } else if matches!(
                expected_operation,
                ContextOperation::Put
                    | ContextOperation::Verify
                    | ContextOperation::Execute
                    | ContextOperation::SealReceipt
            ) && !request.target.is_pinned()
            {
                ContextError::PinnedUriRequired
            } else if matches!(
                expected_operation,
                ContextOperation::List
                    | ContextOperation::Tree
                    | ContextOperation::History
                    | ContextOperation::CompareAndSwapAlias
                    | ContextOperation::Forget
            ) && request.target.is_pinned()
            {
                ContextError::VersionlessUriRequired
            } else {
                ContextError::InvalidTarget
            });
        }

        let rights = expected_operation.required_rights();
        if self
            .manager
            .verify_p1(
                request.capability.index,
                request.capability.generation,
                rights,
            )
            .is_err()
        {
            record_denial(handle_fingerprint(request.capability));
            return Err(ContextError::AccessDenied);
        }
        let Ok(slot) = self
            .manager
            .table()
            .lookup(request.capability.index, request.capability.generation)
        else {
            record_denial(handle_fingerprint(request.capability));
            return Err(ContextError::AccessDenied);
        };
        let token = slot.token;
        if token.cap_type() != CapType::Context || slot.owner != actor {
            record_denial(token.truncated_hash());
            return Err(ContextError::AccessDenied);
        }
        let Some(grant) = self.grants.get(token.id()) else {
            record_denial(token.truncated_hash());
            return Err(ContextError::AccessDenied);
        };
        if !grant.scope.allows(&request.target, expected_operation) {
            record_denial(token.truncated_hash());
            return Err(ContextError::AccessDenied);
        }

        let sequence = emit_decision(
            witness,
            ActionKind::ProofVerifiedP1,
            actor,
            timestamp_ns,
            request,
            token.truncated_hash(),
        );
        Ok(AuthorizedRequest {
            actor,
            operation: expected_operation,
            target: request.target.clone(),
            capability_hash: token.truncated_hash(),
            witness_sequence: sequence,
            timestamp_ns,
        })
    }

    /// Record a completed resolver operation after validating its result.
    pub(crate) fn record_success<const W: usize>(
        request: &AuthorizedRequest,
        witness: &WitnessLog<W>,
    ) -> u64 {
        emit_authorized(witness, request.operation.action_kind(), request)
    }

    /// Record rejection of an invalid or out-of-scope resolver response.
    pub(crate) fn record_resolver_rejection<const W: usize>(
        request: &AuthorizedRequest,
        witness: &WitnessLog<W>,
    ) -> u64 {
        emit_authorized(witness, ActionKind::ProofRejected, request)
    }

    fn emit_denied<const W: usize>(
        actor: PartitionId,
        timestamp_ns: u64,
        request: &ContextRequest,
        witness: &WitnessLog<W>,
        capability_hash: u32,
    ) {
        let _ = emit_decision(
            witness,
            ActionKind::ProofRejected,
            actor,
            timestamp_ns,
            request,
            capability_hash,
        );
    }
}

fn emit_authorized<const W: usize>(
    witness: &WitnessLog<W>,
    action: ActionKind,
    request: &AuthorizedRequest,
) -> u64 {
    let digest = Sha256::digest(request.target.to_string().as_bytes());
    emit_record(
        witness,
        action,
        request.operation,
        request.actor,
        request.capability_hash,
        request.timestamp_ns,
        &digest,
    )
}

fn handle_fingerprint(handle: CapabilityHandle) -> u32 {
    handle.index ^ handle.generation.rotate_left(13)
}

fn emit_decision<const W: usize>(
    witness: &WitnessLog<W>,
    action: ActionKind,
    actor: PartitionId,
    timestamp_ns: u64,
    request: &ContextRequest,
    capability_hash: u32,
) -> u64 {
    let digest = Sha256::digest(request.target.to_string().as_bytes());
    emit_record(
        witness,
        action,
        request.operation,
        actor,
        capability_hash,
        timestamp_ns,
        &digest,
    )
}

fn emit_record<const W: usize>(
    witness: &WitnessLog<W>,
    action: ActionKind,
    operation: ContextOperation,
    actor: PartitionId,
    capability_hash: u32,
    timestamp_ns: u64,
    digest: &[u8],
) -> u64 {
    let mut target = [0u8; 8];
    target.copy_from_slice(&digest[..8]);
    let mut record = WitnessRecord::zeroed();
    record.action_kind = action as u8;
    record.proof_tier = 1;
    record.flags = operation as u8;
    record.actor_partition_id = actor.as_u32();
    record.target_object_id = u64::from_le_bytes(target);
    record.capability_hash = capability_hash;
    record.payload.copy_from_slice(&digest[8..16]);
    record.timestamp_ns = timestamp_ns;
    witness.append(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use core::str::FromStr;

    type AuthorityUnderTest = ContextAuthority<16, 16>;

    fn uri(path: &str, view: Option<&str>, pinned: bool) -> RuvUri {
        let revision = if pinned {
            format!("?rev=sha256:{}", "11".repeat(32))
        } else {
            alloc::string::String::new()
        };
        let view = view.map_or_else(alloc::string::String::new, |value| {
            if revision.is_empty() {
                format!("?view={value}")
            } else {
                format!("&view={value}")
            }
        });
        let suffix = if path.is_empty() {
            alloc::string::String::new()
        } else {
            format!("/{path}")
        };
        RuvUri::from_str(&format!(
            "ruv://example.com/acme/user/alice/memory{suffix}{revision}{view}"
        ))
        .unwrap()
    }

    fn issue(
        authority: &mut AuthorityUnderTest,
        root: &RuvUri,
        views: ContextViewMask,
        rights: CapRights,
        owner: PartitionId,
    ) -> CapabilityHandle {
        authority
            .issue_root(
                ContextScope::from_uri(root, views),
                rights,
                owner,
                PartitionId::HYPERVISOR,
            )
            .unwrap()
    }

    #[test]
    fn operation_rights_are_total_and_read_execute_are_separate() {
        assert_eq!(ContextOperation::Read.required_rights(), CapRights::READ);
        assert_eq!(
            ContextOperation::Execute.required_rights(),
            CapRights::EXECUTE
        );
        assert_eq!(
            ContextOperation::Verify.required_rights(),
            CapRights::READ | CapRights::PROVE
        );
        assert_eq!(
            ContextOperation::CompareAndSwapAlias.required_rights(),
            CapRights::WRITE
        );
    }

    #[test]
    fn live_generation_epoch_owner_rights_scope_and_view_are_enforced() {
        let owner = PartitionId::new(7);
        let root = uri("docs", None, false);
        let target = uri("docs/item", Some("overview"), false);
        let mut authority = AuthorityUnderTest::with_defaults();
        let handle = issue(
            &mut authority,
            &root,
            ContextViewMask::OVERVIEW,
            CapRights::READ,
            owner,
        );
        let log = WitnessLog::<32>::new();

        let allowed = ContextRequest::new(handle, ContextOperation::Read, target.clone());
        assert!(authority
            .authorize(owner, 1, &allowed, ContextOperation::Read, &log)
            .is_ok());

        let wrong_owner = ContextRequest::new(handle, ContextOperation::Read, target.clone());
        assert_eq!(
            authority.authorize(
                PartitionId::new(8),
                2,
                &wrong_owner,
                ContextOperation::Read,
                &log
            ),
            Err(ContextError::AccessDenied)
        );

        let sibling = ContextRequest::new(
            handle,
            ContextOperation::Read,
            uri("other/item", Some("overview"), false),
        );
        assert_eq!(
            authority.authorize(owner, 3, &sibling, ContextOperation::Read, &log),
            Err(ContextError::AccessDenied)
        );

        let raw = ContextRequest::new(
            handle,
            ContextOperation::Read,
            uri("docs/item", Some("content"), false),
        );
        assert_eq!(
            authority.authorize(owner, 4, &raw, ContextOperation::Read, &log),
            Err(ContextError::AccessDenied)
        );

        authority.increment_epoch();
        assert_eq!(
            authority.authorize(owner, 5, &allowed, ContextOperation::Read, &log),
            Err(ContextError::AccessDenied)
        );
        assert_eq!(log.total_emitted(), 5);
    }

    #[test]
    fn path_prefix_is_segment_aware() {
        let owner = PartitionId::new(7);
        let root = uri("foo", None, false);
        let mut authority = AuthorityUnderTest::with_defaults();
        let handle = issue(
            &mut authority,
            &root,
            ContextViewMask::OVERVIEW,
            CapRights::READ,
            owner,
        );
        let log = WitnessLog::<8>::new();
        let request = ContextRequest::new(
            handle,
            ContextOperation::Search,
            uri("foobar", Some("overview"), false),
        );
        assert_eq!(
            authority.authorize(owner, 1, &request, ContextOperation::Search, &log),
            Err(ContextError::AccessDenied)
        );
    }

    #[test]
    fn epoch_rotation_releases_stale_grant_capacity() {
        let owner = PartitionId::new(7);
        let root = uri("docs", None, false);
        let mut authority = ContextAuthority::<4, 1>::with_defaults();
        authority
            .issue_root(
                ContextScope::from_uri(&root, ContextViewMask::ALL),
                CapRights::READ,
                owner,
                PartitionId::HYPERVISOR,
            )
            .unwrap();
        assert_eq!(authority.grants().len(), 1);

        authority.increment_epoch();
        assert!(authority.grants().is_empty());
        assert!(authority
            .issue_root(
                ContextScope::from_uri(&root, ContextViewMask::ALL),
                CapRights::READ,
                owner,
                PartitionId::HYPERVISOR,
            )
            .is_ok());
    }

    #[test]
    fn read_capability_cannot_execute_and_execute_capability_cannot_read() {
        let owner = PartitionId::new(7);
        let root = uri("skills", None, false);
        let target = RuvUri::parse(&format!(
            "ruv://example.com/acme/user/alice/skills/tool?rev=sha256:{}",
            "11".repeat(32)
        ))
        .unwrap();
        let mut authority = AuthorityUnderTest::with_defaults();
        let read = issue(
            &mut authority,
            &root,
            ContextViewMask::ALL,
            CapRights::READ,
            owner,
        );
        let execute = issue(
            &mut authority,
            &root,
            ContextViewMask::MANIFEST,
            CapRights::EXECUTE,
            owner,
        );
        let log = WitnessLog::<8>::new();
        let execute_with_read =
            ContextRequest::new(read, ContextOperation::Execute, target.clone());
        assert_eq!(
            authority.authorize(
                owner,
                1,
                &execute_with_read,
                ContextOperation::Execute,
                &log
            ),
            Err(ContextError::AccessDenied)
        );
        let read_with_execute = ContextRequest::new(execute, ContextOperation::Read, target);
        assert_eq!(
            authority.authorize(owner, 2, &read_with_execute, ContextOperation::Read, &log),
            Err(ContextError::AccessDenied)
        );
    }

    #[test]
    fn delegation_cannot_widen_path_or_views() {
        let owner = PartitionId::new(7);
        let root = uri("docs", None, false);
        let mut authority = AuthorityUnderTest::with_defaults();
        let parent = issue(
            &mut authority,
            &root,
            ContextViewMask::OVERVIEW,
            CapRights::READ | CapRights::GRANT,
            owner,
        );
        let wider_path = ContextScope::from_uri(&uri("", None, false), ContextViewMask::OVERVIEW);
        assert_eq!(
            authority.delegate(parent, wider_path, CapRights::READ, owner, owner),
            Err(ContextError::ScopeEscalation)
        );
        let wider_view = ContextScope::from_uri(&root, ContextViewMask::ALL);
        assert_eq!(
            authority.delegate(parent, wider_view, CapRights::READ, owner, owner),
            Err(ContextError::ScopeEscalation)
        );
    }

    #[test]
    fn non_context_capability_cannot_be_bound() {
        let owner = PartitionId::new(7);
        let mut manager = CapabilityManager::<8>::with_defaults();
        let (index, generation) = manager
            .create_root_capability(CapType::Region, CapRights::READ, 0, owner)
            .unwrap();
        let mut authority = ContextAuthority::<8, 8>::new(manager);
        assert_eq!(
            authority.bind_existing(
                CapabilityHandle::new(index, generation),
                ContextScope::from_uri(&uri("docs", None, false), ContextViewMask::ALL),
            ),
            Err(ContextError::AccessDenied)
        );
    }
}

#[cfg(test)]
mod fingerprint_stability_tests {
    use super::*;
    use crate::uri::RuvUri;

    fn fp(uri: &str) -> u64 {
        let parsed = RuvUri::parse(uri).expect("parses");
        let mask = ContextViewMask::from_bits(0b0000_0111).expect("mask");
        ContextScope::from_uri(&parsed, mask).fingerprint()
    }

    /// A scope fingerprint becomes a capability badge, so its bytes are an
    /// identity, not an implementation detail. These values were captured
    /// before `fingerprint` moved from `to_string` to `as_str`; they must not
    /// move again without a deliberate, versioned change to the hash input.
    #[test]
    fn fingerprint_is_unchanged_by_the_as_str_rewrite() {
        assert_eq!(
            fp("ruv://context.example/acme/agent/researcher/memory"),
            0xded4_a8a4_26a1_881d,
            "bare-collection scope fingerprint changed"
        );
        assert_eq!(
            fp("ruv://context.example/acme/agent/researcher/resources/projects/orion/spec"),
            0x668d_962c_6040_c9ea,
            "path-prefixed scope fingerprint changed"
        );
    }
}
