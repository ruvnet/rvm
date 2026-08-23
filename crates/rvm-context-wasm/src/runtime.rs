//! A self-contained governed context runtime hosted inside the wasm module.
//!
//! # The wasm module is its own authority
//!
//! This runtime owns its capability table, its grant table, its witness ring,
//! and its logical clock. Every capability it issues is an index and a
//! generation into *its own* live table. A [`CapabilityHandle`] is therefore
//! not a bearer token: it is not signed, not serializable, and not meaningful
//! to any other process. A handle minted by a Rust-side service is just two
//! integers that would index a different table here.
//!
//! A decision this runtime renders binds only to the scope table the host
//! provisioned into it. It is a faithful, deterministic policy simulator,
//! correct for shadow-mode evaluation, and it is **not** evidence about a
//! separate Rust-side authority unless that authority provisioned the same
//! scopes. Anyone promoting this to enforcement must provision the grant table
//! from the same authority that issues real capabilities.

use crate::error::{argument_error, chain_error, context_error};
use crate::receipt::{signer_from_key, SignedReceipt};
use crate::rights::Rights;
use crate::scope::ContextScope;
use crate::uri::RuvUri;
use rvm_context::capability::{
    CapabilityHandle as CoreHandle, ContextAuthority, ContextOperation, ContextRequest,
};
use rvm_context::resolver::{
    AliasSnapshot as CoreAlias, ContextHit as CoreHit, MemoryResolver,
    ResolvedContext as CoreResolved,
};
use rvm_context::runtime::{ContextRuntime as CoreRuntime, ExecutionPermit as CorePermit};
use rvm_context::uri::Revision;
use rvm_types::{PartitionId, WitnessRecord};
use wasm_bindgen::prelude::*;

/// Capability table slots this module provisions.
pub const CAPABILITY_SLOTS: usize = 64;
/// Scope grant bindings this module provisions.
pub const GRANT_SLOTS: usize = 64;
/// Witness ring records this module retains.
///
/// The core default is `rvm_witness::DEFAULT_RING_CAPACITY` (262,144), which
/// as an inline `[WitnessRecord; N]` would reserve roughly 16 MiB inside the
/// module. A wasm module cannot spend that, so the ring is sized down here and
/// the capacity is part of this binding's published contract.
pub const WITNESS_SLOTS: usize = 1024;
/// Immutable objects the in-module resolver retains.
pub const OBJECT_SLOTS: usize = 64;
/// Aliases the in-module resolver retains.
pub const ALIAS_SLOTS: usize = 64;

type Resolver = MemoryResolver<OBJECT_SLOTS, ALIAS_SLOTS>;
type Inner = CoreRuntime<Resolver, CAPABILITY_SLOTS, GRANT_SLOTS, WITNESS_SLOTS>;

/// An index and generation into this module's live capability table.
///
/// Not a bearer token. Not portable across a process boundary.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct CapabilityHandle {
    inner: CoreHandle,
}

#[wasm_bindgen]
impl CapabilityHandle {
    /// The table slot index.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn index(&self) -> u32 {
        self.inner.index()
    }

    /// The slot generation, which invalidates stale handles after revocation.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.inner.generation()
    }
}

/// A revision resolved through the governed runtime.
#[wasm_bindgen]
pub struct ResolvedContext {
    inner: CoreResolved,
    witness_sequence: u64,
}

#[wasm_bindgen]
impl ResolvedContext {
    /// The pinned URI naming the immutable revision.
    #[wasm_bindgen(getter, js_name = pinnedUri)]
    #[must_use]
    pub fn pinned_uri(&self) -> String {
        self.inner.pinned_uri().to_string()
    }

    /// The immutable revision.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn revision(&self) -> String {
        self.inner.revision().to_string()
    }

    /// The stored RVF length in bytes.
    #[wasm_bindgen(getter, js_name = rvfLength)]
    #[must_use]
    pub fn rvf_length(&self) -> usize {
        self.inner.rvf_len()
    }

    /// The alias snapshot this resolution passed through, when it had one.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn alias(&self) -> Option<AliasSnapshot> {
        self.inner.alias().map(|alias| AliasSnapshot {
            inner: alias.clone(),
        })
    }

    /// The witness sequence at the moment this decision was recorded.
    #[wasm_bindgen(getter, js_name = witnessSequence)]
    #[must_use]
    pub fn witness_sequence(&self) -> u64 {
        self.witness_sequence
    }
}

/// A mutable alias observed at one generation.
#[wasm_bindgen]
pub struct AliasSnapshot {
    inner: CoreAlias,
}

#[wasm_bindgen]
impl AliasSnapshot {
    /// The versionless alias URI.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn alias(&self) -> String {
        self.inner.alias().to_string()
    }

    /// The revision the alias points at.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn revision(&self) -> String {
        self.inner.revision().to_string()
    }

    /// The alias generation counter, used for compare-and-swap.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.generation().get()
    }

    /// Whether the alias has been tombstoned.
    #[wasm_bindgen(getter, js_name = isTombstone)]
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.inner.is_tombstone()
    }
}

/// One search candidate.
#[wasm_bindgen]
pub struct ContextHit {
    inner: CoreHit,
}

#[wasm_bindgen]
impl ContextHit {
    /// The pinned URI of the candidate.
    #[wasm_bindgen(getter, js_name = pinnedUri)]
    #[must_use]
    pub fn pinned_uri(&self) -> String {
        self.inner.pinned_uri().to_string()
    }

    /// The candidate revision.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn revision(&self) -> String {
        self.inner.revision().to_string()
    }

    /// The relevance score.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn score(&self) -> u32 {
        self.inner.score()
    }

    /// The alias generation, when the hit came through an alias.
    #[wasm_bindgen(getter, js_name = aliasGeneration)]
    #[must_use]
    pub fn alias_generation(&self) -> Option<u64> {
        self.inner
            .alias_generation()
            .map(rvm_context::resolver::AliasGeneration::get)
    }
}

/// Permission to execute a skill, carrying no readable bytes.
#[wasm_bindgen]
pub struct ExecutionPermit {
    inner: CorePermit,
}

#[wasm_bindgen]
impl ExecutionPermit {
    /// The authenticated actor the permit was issued to.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn actor(&self) -> u32 {
        self.inner.actor().as_u32()
    }

    /// The pinned URI the permit authorizes.
    #[wasm_bindgen(getter, js_name = pinnedUri)]
    #[must_use]
    pub fn pinned_uri(&self) -> String {
        self.inner.pinned_uri().to_string()
    }

    /// The immutable revision the permit authorizes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn revision(&self) -> String {
        self.inner.revision().to_string()
    }

    /// The hash of the capability that produced the permit.
    #[wasm_bindgen(getter, js_name = capabilityHash)]
    #[must_use]
    pub fn capability_hash(&self) -> u32 {
        self.inner.capability_hash()
    }

    /// The witness sequence of the allow record.
    #[wasm_bindgen(getter, js_name = witnessSequence)]
    #[must_use]
    pub fn witness_sequence(&self) -> u64 {
        self.inner.witness_sequence()
    }
}

/// A resolved revision together with its content bytes.
#[wasm_bindgen]
pub struct ReadResult {
    context: ResolvedContext,
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl ReadResult {
    /// The resolved revision.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn context(self) -> ResolvedContext {
        self.context
    }

    /// The content bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

fn parse_revision(text: &str) -> Result<Revision, JsValue> {
    text.parse::<Revision>().map_err(crate::error::uri_error)
}

/// The four 32-byte roots a host binds into a sealed epoch.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct EpochCommitments {
    namespace_root: [u8; 32],
    rvf_identity: [u8; 32],
    policy_hash: [u8; 32],
    detail_root: [u8; 32],
}

#[wasm_bindgen]
impl EpochCommitments {
    /// Collects the four commitments, each exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Throws `ContextArgumentError` with code `InvalidDigestLength` naming
    /// the field that was not 32 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(
        namespace_root: &[u8],
        rvf_identity: &[u8],
        policy_hash: &[u8],
        detail_root: &[u8],
    ) -> Result<EpochCommitments, JsValue> {
        Ok(Self {
            namespace_root: digest32(namespace_root, "namespaceRoot")?,
            rvf_identity: digest32(rvf_identity, "rvfIdentity")?,
            policy_hash: digest32(policy_hash, "policyHash")?,
            detail_root: digest32(detail_root, "detailRoot")?,
        })
    }
}

/// A governed `ruv://` context runtime, entirely contained in this module.
///
/// See the module documentation: this runtime is its own authority, and the
/// handles it issues are not portable.
#[wasm_bindgen]
pub struct ContextRuntime {
    inner: Inner,
}

#[wasm_bindgen]
impl ContextRuntime {
    /// Creates a runtime bound to `actor`, with an empty authority and store.
    ///
    /// The clock is the deterministic `LogicalContextClock`, which counts from
    /// zero. No host time source is consulted, so identical call sequences
    /// produce identical witness timestamps.
    ///
    /// # Errors
    ///
    /// Throws `ContextArgumentError` when `actor` exceeds the logical
    /// partition maximum.
    #[wasm_bindgen(constructor)]
    pub fn new(actor: u32) -> Result<ContextRuntime, JsValue> {
        let actor = partition(actor)?;
        Ok(Self {
            inner: CoreRuntime::new(
                actor,
                ContextAuthority::with_defaults(),
                MemoryResolver::new(),
            ),
        })
    }

    /// The authenticated actor bound at construction.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn actor(&self) -> u32 {
        self.inner.actor().as_u32()
    }

    /// The sequence the next witness record will take.
    #[wasm_bindgen(getter, js_name = witnessSequence)]
    #[must_use]
    pub fn witness_sequence(&self) -> u64 {
        self.inner.witness_log().checkpoint().next_sequence()
    }

    /// The witness chain hash immediately before the next record.
    #[wasm_bindgen(getter, js_name = witnessChainHash)]
    #[must_use]
    pub fn witness_chain_hash(&self) -> u64 {
        self.inner.witness_log().checkpoint().chain_hash()
    }

    /// The capacities this module was compiled with.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn capacities() -> Vec<u32> {
        [
            CAPABILITY_SLOTS,
            GRANT_SLOTS,
            WITNESS_SLOTS,
            OBJECT_SLOTS,
            ALIAS_SLOTS,
        ]
        .iter()
        .map(|slots| u32::try_from(*slots).unwrap_or(u32::MAX))
        .collect()
    }

    /// Provisions a root capability over `scope` with `rights`.
    ///
    /// # This is a privileged host step, not a partition-facing request
    ///
    /// The core crate refuses root creation unless the caller is
    /// `PartitionId::HYPERVISOR`; in a real RVM only the kernel may mint a
    /// root. This module performs it *as* the hypervisor, which is the
    /// concrete form of "the wasm module is its own authority". The runtime's
    /// own `actor` is deliberately not used as the caller here, because a
    /// partition promoting itself to hypervisor is exactly the escalation the
    /// core check exists to stop.
    ///
    /// Treat this as the provisioning API the host calls during setup. Every
    /// capability below it is then subject to the ordinary governed checks.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` when the capability or grant table is full.
    #[wasm_bindgen(js_name = issueRoot)]
    pub fn issue_root(
        &mut self,
        scope: &ContextScope,
        rights: &Rights,
        owner: u32,
    ) -> Result<CapabilityHandle, JsValue> {
        let owner = partition(owner)?;
        self.inner
            .authority_mut()
            .issue_root(
                scope.inner().clone(),
                rights.inner(),
                owner,
                PartitionId::HYPERVISOR,
            )
            .map(|inner| CapabilityHandle { inner })
            .map_err(context_error)
    }

    /// Delegates a narrower capability from `source`.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` with code `ScopeEscalation` when the child scope
    /// or rights would widen the parent.
    pub fn delegate(
        &mut self,
        source: &CapabilityHandle,
        child_scope: &ContextScope,
        rights: &Rights,
        target_owner: u32,
    ) -> Result<CapabilityHandle, JsValue> {
        let target_owner = partition(target_owner)?;
        let caller = self.inner.actor();
        self.inner
            .authority_mut()
            .delegate(
                source.inner,
                child_scope.inner().clone(),
                rights.inner(),
                target_owner,
                caller,
            )
            .map(|inner| CapabilityHandle { inner })
            .map_err(context_error)
    }

    /// Revokes a capability lineage, returning how many capabilities fell.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` when the handle is stale or not a context
    /// capability.
    pub fn revoke(&mut self, handle: &CapabilityHandle) -> Result<usize, JsValue> {
        self.inner
            .authority_mut()
            .revoke(handle.inner)
            .map_err(context_error)
    }

    /// Advances the capability epoch.
    #[wasm_bindgen(js_name = incrementEpoch)]
    pub fn increment_epoch(&mut self) {
        self.inner.authority_mut().increment_epoch();
    }

    /// Resolves a name to an immutable revision.
    ///
    /// # Errors
    ///
    /// Throws `ContextError`; authorization failures collapse to
    /// `AccessDenied` by design.
    pub fn resolve(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
    ) -> Result<ResolvedContext, JsValue> {
        let request = request(*handle, ContextOperation::Resolve, target);
        let resolved = self.inner.resolve(&request).map_err(context_error)?;
        Ok(self.wrap(resolved))
    }

    /// Verifies a revision and produces proof material.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal.
    pub fn verify(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
    ) -> Result<ResolvedContext, JsValue> {
        let request = request(*handle, ContextOperation::Verify, target);
        let resolved = self.inner.verify(&request).map_err(context_error)?;
        Ok(self.wrap(resolved))
    }

    /// Reads context bytes.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal.
    pub fn read(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
    ) -> Result<ReadResult, JsValue> {
        let request = request(*handle, ContextOperation::Read, target);
        let (resolved, bytes) = self.inner.read(&request).map_err(context_error)?;
        Ok(ReadResult {
            context: self.wrap(resolved),
            bytes,
        })
    }

    /// Registers a new immutable whole-RVF revision.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` when the bytes do not hash to the pinned
    /// revision, or on refusal.
    pub fn put(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        rvf: &[u8],
    ) -> Result<ResolvedContext, JsValue> {
        let request = request(*handle, ContextOperation::Put, target);
        let resolved = self.inner.put(&request, rvf).map_err(context_error)?;
        Ok(self.wrap(resolved))
    }

    /// Lists direct children below a path.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal or an invalid limit.
    pub fn list(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        limit: usize,
    ) -> Result<Vec<ResolvedContext>, JsValue> {
        let request = request(*handle, ContextOperation::List, target);
        let found = self.inner.list(&request, limit).map_err(context_error)?;
        Ok(self.wrap_all(found))
    }

    /// Traverses containment below a path.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal or an invalid limit.
    pub fn tree(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        limit: usize,
    ) -> Result<Vec<ResolvedContext>, JsValue> {
        let request = request(*handle, ContextOperation::Tree, target);
        let found = self.inner.tree(&request, limit).map_err(context_error)?;
        Ok(self.wrap_all(found))
    }

    /// Inspects prior revisions of an alias.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal or an invalid limit.
    pub fn history(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        limit: usize,
    ) -> Result<Vec<ResolvedContext>, JsValue> {
        let request = request(*handle, ContextOperation::History, target);
        let found = self.inner.history(&request, limit).map_err(context_error)?;
        Ok(self.wrap_all(found))
    }

    /// Enumerates semantically relevant candidates.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal, an empty query, or an invalid limit.
    pub fn search(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        query: &[u8],
        limit: usize,
    ) -> Result<Vec<ContextHit>, JsValue> {
        let request = request(*handle, ContextOperation::Search, target);
        let hits = self
            .inner
            .search(&request, query, limit)
            .map_err(context_error)?;
        Ok(hits.into_iter().map(|inner| ContextHit { inner }).collect())
    }

    /// Advances an alias with compare-and-swap.
    ///
    /// Pass `expected` as undefined to require that the alias does not exist.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` with code `AliasConflict` when the observed
    /// snapshot differs.
    #[wasm_bindgen(js_name = compareAndSwapAlias)]
    pub fn compare_and_swap_alias(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        expected: Option<AliasSnapshot>,
        next_revision: &str,
    ) -> Result<AliasSnapshot, JsValue> {
        let revision = parse_revision(next_revision)?;
        let request = request(*handle, ContextOperation::CompareAndSwapAlias, target);
        let expected = expected.map(|snapshot| snapshot.inner);
        self.inner
            .compare_and_swap_alias(&request, expected.as_ref(), revision)
            .map(|inner| AliasSnapshot { inner })
            .map_err(context_error)
    }

    /// Advances an alias to a tombstone.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal or a snapshot conflict.
    pub fn forget(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        expected: &AliasSnapshot,
    ) -> Result<AliasSnapshot, JsValue> {
        let request = request(*handle, ContextOperation::Forget, target);
        self.inner
            .forget(&request, &expected.inner)
            .map(|inner| AliasSnapshot { inner })
            .map_err(context_error)
    }

    /// Authorizes execution of a skill without disclosing its bytes.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal.
    #[wasm_bindgen(js_name = authorizeExecute)]
    pub fn authorize_execute(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
    ) -> Result<ExecutionPermit, JsValue> {
        let request = request(*handle, ContextOperation::Execute, target);
        self.inner
            .authorize_execute(&request)
            .map(|inner| ExecutionPermit { inner })
            .map_err(context_error)
    }

    /// Delegates through the governed path, emitting a witness record.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal or scope escalation.
    pub fn grant(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        child_scope: &ContextScope,
        rights: &Rights,
        target_owner: u32,
    ) -> Result<CapabilityHandle, JsValue> {
        let target_owner = partition(target_owner)?;
        let request = request(*handle, ContextOperation::Grant, target);
        self.inner
            .grant(
                &request,
                child_scope.inner().clone(),
                rights.inner(),
                target_owner,
            )
            .map(|inner| CapabilityHandle { inner })
            .map_err(context_error)
    }

    /// Revokes through the governed path, emitting a witness record.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` on refusal.
    #[wasm_bindgen(js_name = revokeGoverned)]
    pub fn revoke_governed(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
    ) -> Result<usize, JsValue> {
        let request = request(*handle, ContextOperation::Revoke, target);
        self.inner.revoke(&request).map_err(context_error)
    }

    /// Seals the witnessed decisions since the last epoch into a receipt.
    ///
    /// `key` is the 32-byte HMAC key the host provisions; this module has no
    /// default key and will not invent one. The four roots are the commitments
    /// the host binds into the epoch, each 32 bytes.
    ///
    /// # Errors
    ///
    /// Throws `ContextError` when the request is refused or the epoch cannot
    /// be sealed, and `ContextArgumentError` when `key` or a root is not 32
    /// bytes.
    #[wasm_bindgen(js_name = sealEpoch)]
    pub fn seal_epoch(
        &mut self,
        handle: &CapabilityHandle,
        target: &RuvUri,
        key: &[u8],
        commitments: &EpochCommitments,
    ) -> Result<SignedReceipt, JsValue> {
        let signer = signer_from_key(key)?;
        let EpochCommitments {
            namespace_root,
            rvf_identity,
            policy_hash,
            detail_root,
        } = *commitments;
        let request = request(*handle, ContextOperation::SealReceipt, target);
        let mut scratch = vec![WitnessRecord::zeroed(); WITNESS_SLOTS];
        let (sealed, _checkpoint) = self
            .inner
            .seal_epoch(
                &request,
                &mut scratch,
                namespace_root,
                rvf_identity,
                policy_hash,
                detail_root,
                &signer,
            )
            .map_err(context_error)?;
        Ok(SignedReceipt::from_inner(sealed))
    }

    /// Verifies the integrity of this module's own witness chain.
    ///
    /// This check is keyless: it recomputes the hash chain over the retained
    /// records. It proves the log has not been reordered or truncated in
    /// memory. It says nothing about any other process's log.
    ///
    /// # Errors
    ///
    /// Throws `WitnessChainError` on a chain break, a corrupted record, or an
    /// empty log.
    #[wasm_bindgen(js_name = verifyWitnessChain)]
    pub fn verify_witness_chain(&self) -> Result<usize, JsValue> {
        let records = self.snapshot_records();
        rvm_witness::verify_chain(&records).map_err(chain_error)
    }

    /// The SHA-256 digest of every retained witness record, in order.
    ///
    /// `record_to_digest` is a pure, keyless function of the record bytes, so
    /// these digests are the anchor for cross-implementation determinism.
    #[wasm_bindgen(js_name = witnessDigests)]
    #[must_use]
    pub fn witness_digests(&self) -> Vec<u8> {
        let records = self.snapshot_records();
        let mut out = Vec::with_capacity(records.len() * 32);
        for record in &records {
            out.extend_from_slice(&rvm_witness::record_to_digest(record));
        }
        out
    }

    /// How many witness records are currently retained.
    #[wasm_bindgen(getter, js_name = witnessRecordCount)]
    #[must_use]
    pub fn witness_record_count(&self) -> usize {
        self.snapshot_records().len()
    }
}

fn request(
    handle: CapabilityHandle,
    operation: ContextOperation,
    target: &RuvUri,
) -> ContextRequest {
    ContextRequest::new(handle.inner, operation, target.inner().clone())
}

impl ContextRuntime {
    fn wrap(&self, inner: CoreResolved) -> ResolvedContext {
        ResolvedContext {
            inner,
            witness_sequence: self.witness_sequence(),
        }
    }

    fn wrap_all(&self, found: Vec<CoreResolved>) -> Vec<ResolvedContext> {
        let sequence = self.witness_sequence();
        found
            .into_iter()
            .map(|inner| ResolvedContext {
                inner,
                witness_sequence: sequence,
            })
            .collect()
    }

    fn snapshot_records(&self) -> Vec<WitnessRecord> {
        let mut buffer = vec![WitnessRecord::zeroed(); WITNESS_SLOTS];
        let count = self.inner.witness_log().snapshot(&mut buffer);
        buffer.truncate(count);
        buffer
    }
}

fn digest32(bytes: &[u8], field: &str) -> Result<[u8; 32], JsValue> {
    bytes.try_into().map_err(|_| {
        argument_error(
            "InvalidDigestLength",
            &format!("{field} must be exactly 32 bytes"),
        )
    })
}

fn partition(id: u32) -> Result<PartitionId, JsValue> {
    if id >= PartitionId::MAX_LOGICAL {
        return Err(argument_error(
            "InvalidPartitionId",
            &format!(
                "partition id {id} is at or beyond the logical maximum {}",
                PartitionId::MAX_LOGICAL
            ),
        ));
    }
    Ok(PartitionId::new(id))
}
