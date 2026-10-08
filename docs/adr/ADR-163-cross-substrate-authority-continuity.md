# ADR 163: Strict Cross Substrate Authority Continuity

Status: proposed

Date: 2026-09-09

Issues: #67, #68, #69, #70

MetaHarness: ruvnet/metaharness#301

## Context

RVM already provides default deny capabilities, attenuation, revocation epochs, policy validation, provenance work, and effect boundary controls. A remaining composition risk appears when decision relevant authorization state lives outside the planner visible workspace or memory and is dropped, rebound, widened, or reinterpreted while an operation crosses components.

`Beyond Agent Harnesses: Cross-Substrate Authority for Multi-Agent Systems` (arXiv:2609.08472, submitted 2026-09-08) provides new originating team evidence for this failure class. In its controlled evidence ablation, authority blind candidate evidence reaches 0 of 32 final semantic successes while raw receipts and a typed authority relation each reach 32 of 32. Typed packaging does not improve planning accuracy over the same raw authority fact. Planning remains unreliable even with visibility, while a deterministic execution guard prevents all six replayed unsafe intents from becoming effects and permits all 12 valid authorized publish intents.

These are external results and are not RuV benchmark claims until independently reproduced.

## Decision

Add a dependency free strict continuity verifier to `rvm-cap`.

The first version binds eight decision relevant security fields across a component transition:

1. authenticated principal
2. task scope
3. provenance root
4. capability scope
5. active policy state
6. canonical action
7. permitted effect boundary
8. capability epoch

All eight must remain identical. Planner visible input and output context may change and are recorded separately as transition evidence.

The verifier returns a typed receipt with `authority = None`. It never consults a capability table, grants a capability, refreshes an epoch, or approves the external effect. Callers must separately validate the underlying RVM capability or permit before mutation.

## Why strict first

Issue #67 allows either monotonic continuity or an explicitly authorized release. Implementing a generic release bit in the first version would create a new authority surface before an authenticated release protocol exists. The safer first primitive therefore accepts no caller controlled exception.

A later ADR may define authorized security context changes only after the release authority, replay behavior, delegation semantics, revocation behavior, and witness format are independently specified and tested.

## Receipt semantics

The receipt is evidence, not a standalone cryptographic proof. Durable or remote use must seal the receipt through the existing RVM or RVF witness path.

A matching digest establishes equality of the bound representation. It does not establish semantic truth, capture completeness, authorization, or policy correctness by itself.

## Security invariants

1. No authoritative field may change silently.
2. A changed capability epoch always fails strict continuity.
3. Input or output model context cannot grant authority.
4. A continuity receipt cannot create or widen rights.
5. The verifier contains no bypass flag and no release token.
6. Root grants and source context must be authenticated independently.
7. Unknown security context fields remain a host integration risk and must be covered by the boundary inventory.
8. The implementation remains `no_std`, allocation free, dependency free, and `unsafe` free.

## Benchmark

MetaHarness #301 Track A owns independent reproduction.

Freeze at least 32 transition fault classes across:

1. MCP to RVM
2. Ruflo delegation to RVM
3. Core Memory retrieval to RVM
4. one lifecycle hook or equivalent host boundary

Faults must include principal substitution, task rebound, provenance discontinuity, capability scope widening, policy change, action reinterpretation, effect boundary mismatch, stale or advanced epoch, missing mapping, replay, malformed external evidence, partial failure, and resource exhaustion.

For every arm report baseline, candidate, workload, commits, environment, versions, seeds, sample size, harmful effects, benign completion, escalation, p50 and p95 verifier latency, CPU, receipt size, failures, variance where applicable, and reproduction commands.

Promotion requires zero harmful external effects across the frozen fault corpus, benign completion within 2 absolute points of the stronger baseline, every authority context change failing closed or escalating before effect, p95 local verification below 1 millisecond, no capability expansion, and all repository CI and security gates green.

## Falsification

Reject or narrow this primitive if one of these occurs:

1. Existing RVM boundary checks already detect every frozen cross substrate fault with equal or lower cost.
2. Strict equality causes more than 2 absolute points of benign task loss and a simpler authenticated mapping solves the same problem.
3. Host integrations cannot produce independently trustworthy context identities.
4. The receipt is treated operationally as authority rather than evidence.

## Performance

The implementation compares seven fixed 32 byte digests and one `u64` epoch. It allocates no memory and performs no hashing, I/O, model call, network operation, or capability lookup. The explicit target is below 1 millisecond p95 in integration; micro level local cost should be substantially lower but must be measured rather than assumed.

## Migration

Additive only. Existing capability checks, policies, launch behavior, and host integrations remain unchanged until a caller explicitly adopts the strict verifier before a mutation boundary.

## Rollback

Remove `transition.rs`, its public export, and integration call sites. No persisted state migration is required. Existing sealed receipts remain inert audit evidence.

## Governance

Draft PR, independent MetaHarness reproduction, security review, dependency review, and human approval are required. No autonomous merge, deployment, credential escalation, policy weakening, or irreversible migration.