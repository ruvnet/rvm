# ADR 170: Quarantined Acquired Resource Activation

**Status**: Proposed  
**Date**: 2026-09-23  
**Tracks**: ruvnet/rvm#77  
**Motivation**: AcquireBound, arXiv:2609.14744

## Context

An autonomous agent can acquire a resource through a transaction that is perfectly valid while the returned resource is still unsafe to activate as authority. Examples include compute, credentials, external accounts, services, devices, and delegated agents. Payment success, an MCP response, a provider object identifier, a signed artifact, or a model decision does not establish that the returned resource may become usable RVM authority.

RVM already provides unforgeable capabilities, monotonic attenuation, bounded delegation, epoch revocation, proof checks, and witness evidence. The missing boundary is earlier: acquisition output needs to remain quarantined until current host policy resolves what it actually is and whether it fits a bounded authority envelope.

## Decision

Add an additive acquisition primitive to `rvm-cap`.

`ResolvedResourceManifest` records authenticated provider evidence after resolution into an RVM-facing resource class, capability type, requested rights, principal, purpose, provider identity, evidence digest, resolver version, epochs, delegation depth, aggregate resource budgets, and evidence time.

`ActivationEnvelope` is host-controlled policy. It fixes principal, purpose, provider, resource class, capability type, maximum rights, resolver version, current epochs, delegation depth, aggregate effects, data, child-resource budgets, evidence freshness, and expiry.

`ActivationLedger` is monotonic graph-wide state. Every successful activation consumes aggregate effect, data, and child-resource budgets before another acquisition can activate. This blocks simple split acquisition where many individually valid resources exceed the graph-wide ceiling in aggregate.

`QuarantinedResource::activate` validates provider evidence through a host-supplied `ProviderEvidenceVerifier`, binds resolver version and all current epochs, checks identity and purpose, enforces rights attenuation, validates freshness, rejects replayed sequence numbers, and checks aggregate budgets before mutating the ledger.

`ActivationReceipt` is evidence only. It never mints a `CapToken` and `grants_authority()` is structurally false. Capability issuance remains a separate RVM decision under current policy.

## Invariants

1. Provider success is not authority.
2. Model output is not provider evidence.
3. A manifest cannot widen the host envelope.
4. Rights are downward closed: requested rights must be a subset of allowed rights.
5. Resource class and target capability type match exactly.
6. Principal, purpose, and provider identity match exactly.
7. Resolver, policy, provider, and graph epochs match current host state.
8. Evidence outside the freshness window or from the future is rejected.
9. Activation sequence numbers are monotonic and nonzero.
10. Failed activation is atomic with respect to aggregate ledger state.
11. Multiple acquisitions share one aggregate ledger and cannot independently reset budgets.
12. An activation receipt never grants RVM execution authority.

## Threat model and contradiction tests

The implementation must be tested against provider substitution, principal substitution, purpose substitution, resource-type substitution, capability-type substitution, rights amplification, stale epochs, stale evidence, future evidence, resolver downgrade, replay, split-budget evasion, malformed evidence, resource exhaustion, and failure atomicity.

The key residual risk is host substitution. A compromised host can give the verifier stale or fabricated provider reality. This primitive therefore cannot prove its own evidence source. Production adapters must authenticate provider state independently and bind that evidence to an RVM witness or equivalent trusted receipt.

Crash consistency is also outside the in-memory primitive. A production service must persist `ActivationLedger` and the final activation receipt in one atomic transaction or use a replay-safe external ledger. Recreating a fresh ledger after a crash would defeat graph-wide limits.

## Benchmark contract

The structural benchmark uses 10,000 deterministic cases over five seeds. Half are clean. Half preserve provider success while violating one of five activation conditions: rights, graph epoch, provider identity, evidence freshness, or aggregate effect budget.

Baseline: provider evidence only.  
Candidate: quarantine plus activation envelope and aggregate ledger.

Report case count, seeds, accepted and rejected cases, false accepts, false denials, baseline total time, candidate total time, candidate mean decision latency, p95 latency for batches of 100, batch variance, throughput, relative runtime, local model cost, energy status, Rust version, OS, and dependency tree.

Structural acceptance requires zero unsafe activation, zero clean false denial, zero replay acceptance, zero aggregate budget evasion, and p95 local validation below 100 microseconds per decision on documented CI hardware. Task-level value is a separate MetaHarness experiment.

## Cross-stack integration

RVM owns activation and final effect authorization. RVF may carry manifest and receipt digests. RVForge may package only provider adapters that have passed independent reproduction. RuFlo may request acquisitions and schedule work but cannot self-activate the returned resource. Core Memory stores evidence and activation history without becoming an authority source. RuVector and RuVector WASM may retrieve manifests but similarity cannot imply permission. MetaHarness owns independent reproduction. Autogenous and Dream Machine may propose acquisition plans but cannot alter activation envelopes or acceptance tests. MidStream carries lifecycle events. RuView and RuField may reuse the pattern for acquired sensors and devices. WorldGraph may represent the acquired resource as data before activation. LatentMesh transports evidence as untrusted input. Cognitum can expose a tenant-auditable acquisition boundary. MCP tool success never implies activation.

## Migration and rollback

The API is additive. No existing capability or acquisition path changes automatically. Initial rollout is shadow mode only. Integrations may compare the receipt decision with existing behavior without changing execution.

Rollback is removal of the shadow integration and this additive API. No persistent data migration is required during the experiment phase.

## Governance

No autonomous merge, deployment, credential escalation, policy weakening, or irreversible migration is authorized. Promotion requires exact-head CI, security and dependency review, independent MetaHarness reproduction, and explicit human approval. Existing dependency security issue ruvnet/rvm#74 remains a blocker and must not be suppressed.
