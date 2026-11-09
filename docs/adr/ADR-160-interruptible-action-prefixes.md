# ADR 160: Interruptible Action Prefixes

Status: Proposed

Date: 2026-09-17

Issue: #72

## Context

World models and agent planners often emit more than one action from a single observation. Executing a long sequence without checking the environment again can reduce latency and planning cost, but it also allows stale predictions to compound after the world changes.

WAVE Go, arXiv:2609.18193, submitted 2026-09-16, reports an embodied version of this tradeoff. Its executor selects a bounded command prefix from a predicted sequence, interrupts pending commands when updated observations invalidate execution, and uses an estimated cumulative failure budget to balance progress against replanning. The originating team reports 74.1 percent in distribution success and 63.3 percent dynamic out of distribution success, with fewer collisions than the strongest comparison. Against fixed four command execution, adaptive interruption raises success by 4.0 points while reducing replanning frequency by 51.2 percent. These are external originating team results and are not RuV benchmark claims.

RVM already controls authorization and capability scope. Issue #62 covers invocation scoped execution leases that bind a protected call to an executing workload. Neither primitive expresses how many already authorized actions may be executed from one observation before fresh evidence is required.

## Decision

Add an additive, no_std prefix selector to `rvm-cap`.

The selector consumes a host owned `InterruptiblePrefixPolicy`, one `PrefixAssessment`, the trusted current tick, and the trusted current capability epoch. It returns the maximal leading sequence that remains inside the declared observation age, step count, individual risk, cumulative risk, precondition, and reversibility boundaries.

The policy binds the evaluator and policy digests. An assessment created under a different evaluator or policy fails closed. A stale capability epoch fails closed. Invalid digests or out of range risks fail closed.

Every action selected by this primitive still requires the normal RVM authorization gate. `dispatch_steps` is a scheduling bound, not a capability.

## Why the primitive is narrow

RVM does not estimate risk, predict the world, or decide whether a semantic precondition is true. Those are evidence producing functions owned by a qualified host component. RVM only checks that the evidence is bound to the expected evaluator and policy and then applies deterministic ceilings.

This avoids importing an embodied world model into the authorization layer and makes the primitive reusable for digital tool macros, remote operations, spatial navigation, RF sensing control, and browser automation.

## Invariants

1. Prefix selection never grants execution authority.
2. Each dispatched action still passes the ordinary capability and policy gate.
3. A prefix is scoped to one observation and one capability epoch.
4. An irreversible action is never batched by this first version.
5. A failed precondition stops before that action.
6. Individual and cumulative risk ceilings are both enforced.
7. Policy and evaluator substitution fail closed.
8. Missing or malformed digests fail closed.
9. Hosts reobserve before selecting another prefix.
10. Risk estimates, model confidence, signatures, and world model output remain evidence and never become authority.

## Cross stack mapping

RuView and RuField can bind sensor driven action batches to fresh observations.

WorldGraph can use the selector for navigation and scene update sequences without moving world model logic into RVM.

RuFlo can use the same contract for reversible tool macros and remote desktop sequences.

MetaHarness owns independent comparisons against fixed one step, fixed four step, and adaptive oracle controls.

RVF can carry the policy, evaluator, observation, and action digests as evidence.

RVForge can package only reviewed prefix policies and adapters.

Autogenous and Dream Machine may propose action sequences but cannot alter the host policy or capability epoch.

MidStream can trigger refresh when new live evidence invalidates a queued prefix.

LatentMesh may transport assessment evidence but cannot grant capability.

Cognitum can use the primitive for low latency remote operations where stale action batches create operational risk.

MCP tool calls remain individually authorized even when a planner groups them into one prefix.

## Security analysis

The largest failure mode is dishonest risk evidence. A compromised evaluator can label a dangerous step as low risk and precondition satisfied. Digest binding only identifies the evaluator; it does not prove the evaluator is correct. Production use therefore requires independently configured evaluator identity, held out MetaHarness qualification, and ordinary RVM authorization for every effect.

A second failure mode is assuming reversibility from model text. The `reversible` field must come from host owned tool or actuator metadata. A model supplied reversibility claim is untrusted evidence and must not reach the selector as an authenticated assessment.

A third failure mode is batching externally irreversible effects such as purchases, credential changes, destructive file operations, or physical actuation without a proven inverse. Version one stops before every action marked irreversible.

## Benchmark contract

The structural benchmark uses five fixed seeds and at least 10,000 prefixes. It includes clean sequences, stale observations, capability epoch mismatch, policy substitution, evaluator substitution, failed preconditions, irreversible actions, individual risk violations, cumulative risk exhaustion, and malformed evidence.

Report exact source commit, Rust toolchain, operating system, architecture, seeds, sample size, baseline and candidate false allow and false deny counts, stop reason coverage, p50 and p95 latency, throughput, absolute and relative overhead, failures, and reproduction command. Dollar cost is zero for the local deterministic benchmark. Energy is unmeasured unless a future runner supplies instrumentation.

The later task level benchmark must use matched capabilities and budgets across fixed one step, fixed four step, bounded prefix, and adaptive oracle controls on at least one digital and one spatial workload.

## Promotion gates

Structural promotion requires zero unsafe prefix extension on the frozen corpus, zero clean false denial, deterministic decisions, no allocation requirement inside the selector, no unsafe code, and local p95 below 100 microseconds.

Task level promotion requires at least one of the following against the stronger fixed baseline: at least 10 percent lower end to end latency at matched success, at least 20 percent fewer replans at matched success, or at least 3 absolute points higher task success at matched latency. No capability expansion or increase in irreversible effect errors is allowed.

## Migration and rollback

The change is additive and does not alter existing capability records, wire formats, durable state, or execution semantics until a caller opts in. Rollback removes the module, export, documentation, and callers. Existing authorization paths remain unchanged.

## Governance

The implementation remains on an isolated branch and draft pull request. MetaHarness reproduction and human review are required before integration. No autonomous merge, deployment, credential escalation, policy weakening, or irreversible migration is authorized.