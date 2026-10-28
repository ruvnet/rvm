# ADR 162: Capability Bound Lifecycle Hook Updates

Status: Proposed
Date: 2026-09-04
Tracks: ruvnet/rvm#64

## Context

Lifecycle hooks can execute host-side commands outside the model decision path. HookPry, arXiv:2609.03884, submitted 2026-09-03, demonstrates a supply-chain threat in which a previously benign plugin later changes hook configuration while retaining the same plugin identity. The originating team reports 1,000 runs across 25 harness and backend combinations, with all seven evaluated harnesses compromised. RuV has not independently reproduced those results.

Prompt filtering cannot protect a control-plane action the model never observes. A stable plugin name, marketplace identity, signature, popularity, prior benign behavior, or model approval is insufficient evidence that a later hook update should inherit execution authority.

## Decision

RVM treats each lifecycle-hook update as a fresh privileged authorization event.

`rvm-cap` exposes an allocation-free `HookUpdateGrant` and `validate_hook_update` contract. The grant binds the plugin identity digest, exact previously approved manifest digest, allowed lifecycle events, maximum effective capability rights, capability epoch, and expiry tick. The request additionally binds the next manifest digest and exact command digest.

Validation fails closed when plugin identity changes, continuity from the previous approved manifest is missing, the event class is outside the grant, requested rights exceed the ceiling, the capability epoch changes, or the grant expires.

The resulting `HookBinding` is evidence that the request stayed inside the grant envelope. It is not evidence that the grant itself was legitimately issued. The caller must bind grant issuance to an independently authenticated RVM capability.

## Security invariants

1. Hook updates never widen rights beyond the independently issued grant.
2. New lifecycle event bindings require explicit inclusion in the grant.
3. Manifest continuity is exact. A stale reviewed manifest cannot authorize an unrelated update.
4. Epoch mismatch and expiry fail closed.
5. Model text, tool metadata, peer consensus, plugin signatures, and prior benign behavior never mint authority.
6. Successful validation authorizes only the declared hook binding.
7. A later integration must emit a witness receipt linking the prior manifest, next manifest, command digest, event, grant identity, epoch, and allow or deny decision.

## Alternatives rejected

Static malware scanning is insufficient because the upstream study reports large miss rates and because static classification cannot represent user-specific capability scope. Prompt-level defenses are structurally irrelevant to host-side execution that occurs outside the model loop. Blanket disabling of hooks removes legitimate extensibility and would be a poor default without workload evidence.

## Benchmark

MetaHarness issue 281 freezes benign and malicious synthetic update sequences before candidate outcomes are visible. It compares current admission behavior with the new deterministic gate and records unauthorized bindings, rights widening, legitimate acceptance, p50 and p95 validation latency, CPU cost, malformed input behavior, replay behavior, and exact software versions.

Promotion requires zero unauthorized bindings on the frozen attack set, zero rights widening, legitimate update acceptance within one absolute percentage point of baseline, and deterministic local validation below 100 microseconds p95.

## Rollback

The primitive is additive and changes no existing hook or plugin admission path by default. Removing the module and export returns `rvm-cap` to its previous behavior. No state migration is required.
