# ADR 159: Monotonic Instruction Provenance Ceiling

Status: Proposed

Date: 2026-08-28

## Context

Modern model APIs expose instruction levels such as system, developer, user, and tool or data content. Agent harnesses rebuild model facing context when they delegate to subagents, summarize history, resume persistent goals, retrieve memory, or execute scheduled work.

The security boundary fails if content originally classified as data is reintroduced at a higher instruction level. A tool result forwarded to a subagent as a user message is no longer merely the same text in a different container. The harness has changed the model facing authority of that text.

The paper `When Context Gets Root: Privilege Escalation in LLM Harnesses`, arXiv:2608.27299, submitted 2026-08-27, demonstrates this failure across six coding agent harnesses and thirteen attack objectives. The reported attacks also reproduce through persistent goals and scheduled tasks. The study is an originating team report and has not yet been independently reproduced inside RVM.

RVM already separates names, evidence, and capabilities. The missing primitive is an explicit rule for model facing instruction authority during context reconstruction.

## Decision

Add `InstructionProvenance` to `rvm-context` with a monotonic authority ceiling.

A context fragment is classified once at a trusted boundary with:

1. original source category
2. original instruction level
3. current maximum instruction level
4. exact content digest
5. deterministic lineage digest
6. transformation depth

Ordinary transformations may preserve or reduce the ceiling. They may never increase it.

A downgrade is intentionally irreversible through the transformation API. Reclassification at a higher level is only possible by returning to an external trusted host boundary and creating a new root provenance record.

## Instruction levels

From least to greatest model facing authority:

1. Data
2. Agent
3. User
4. Developer
5. System

The ordering is a portable RVM abstraction. Provider specific adapters remain responsible for mapping it onto each model API without increasing authority.

## Source rules

Trusted constructors exist for system policy, developer policy, authenticated human user input, and peer agent messages. Content with missing provenance defaults to Data regardless of whether it came from a tool, retrieval system, stored artifact, or scheduler.

Persistent and scheduled state must preserve its prior provenance envelope. If that envelope is missing, the content is data, not a user instruction.

## Security invariant

For every parent fragment `p` and derived fragment `c`:

`c.ceiling <= p.ceiling`

For every presentation at model facing level `l`:

`l <= fragment.ceiling`

No model generated text, peer consensus, retrieved content, digest, or provenance record grants RVM execution authority. Privileged side effects still require an independently validated RVM capability.

## Digest semantics

The content digest detects byte changes. The lineage digest commits to the prior lineage, transform type, new ceiling, depth, and current content digest.

These hashes are evidence identity only. They are not signatures. A malicious host can fabricate provenance records if it already controls the classification boundary. This ADR therefore protects against unsafe harness composition and accidental or induced privilege elevation inside a conforming host. It does not replace host integrity, signatures, capabilities, or RVM policy enforcement.

## Integration

MetaHarness should attach provenance to every context fragment and reject illegal role promotion before invoking a model.

Ruflo and Autogenous should preserve the envelope across delegation and peer communication.

MCP tool output and retrieved content enter as Data.

Core Memory should retain the envelope when persistent goals or scheduled state are stored.

The WASM binding should expose the same validation logic after the Rust primitive is benchmarked and reviewed.

## Migration

The change is additive. Existing callers are unaffected.

Adapters can roll out in shadow mode by constructing provenance records and logging would reject events before enforcing them.

Rollback removes adapter enforcement while leaving the evidence records harmless.

## Validation plan

Unit tests must cover tool to user escalation, retrieval to developer escalation, peer agent to user escalation, persistent state without provenance, irreversible downgrade, content mutation, deterministic lineage, and transformation depth exhaustion.

A MetaHarness reproduction should replay the thirteen published attack objectives where licensing and harness access allow, plus RVM specific cases for retrieval, subagent forwarding, persistent goals, scheduled tasks, and MCP tool results.

Promotion requires zero successful authority increases through conforming RVM adapters, no legitimate task regression above three absolute percentage points, and measured context construction overhead below one percent of model invocation latency.

## Consequences

The architecture gains a portable checkable invariant across agent runtimes. The tradeoff is metadata propagation through every context transformation and provider adapter. The cost should be negligible relative to model inference, but the integration surface is broad and must be staged.

The largest residual risk is false trust at the root classification boundary. The fix is to bind trusted root classification to authenticated principals and RVM capabilities rather than accepting caller supplied role labels.
