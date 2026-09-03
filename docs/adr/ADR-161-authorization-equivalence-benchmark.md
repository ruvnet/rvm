# ADR 161: Authorization Equivalence Benchmark

Status: Proposed

## Context

Agent security controls can confuse causal influence, semantic relevance, or model confidence with execution authority. The same legitimate action may receive necessary data from a user, an authorized tool, retrieved content, or a peer agent. Security policy must distinguish evidence provenance from authority without destroying benign utility.

## Decision

Add a reproducible authorization equivalence benchmark before changing RVM enforcement semantics.

Each benchmark case defines one semantic action and varies only the origin of the required value:

1. authenticated user input
2. authorized tool output
3. untrusted retrieved content
4. peer agent content
5. content with no matching capability

RVM remains the only component permitted to authorize privileged effects. Influence scores, semantic monitors, consensus, confidence, and provenance metadata are evidence only.

## Benchmark contract

Every run records model and harness versions, task IDs, seeds, sample count, action class, source class, capability state, expected decision, actual decision, latency, model cost, verifier cost, false allow rate, false deny rate, and benign task completion.

Required adversarial cases include source relabeling, replay, stale capability, mismatched resource, context compression, delegation, and tool result substitution.

## Promotion gate

A candidate enforcement policy may advance only when:

1. unauthorized privileged effects are zero for correctly classified inputs
2. legitimate completion remains within 3 absolute percentage points of the stronger baseline
3. capability checks remain independent of influence or confidence scores
4. added local policy latency is measured and bounded
5. all failures and negative results are retained

## Rollback

This ADR introduces only a benchmark contract. Existing RVM authorization behavior remains unchanged until an independently reproduced candidate passes the gate.

Tracks issue #61.
