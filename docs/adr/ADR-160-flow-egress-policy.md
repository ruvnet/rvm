# ADR-160: Monotonic Context Flow Labels and Explicit Egress Budgets

Status: Proposed
Date: 2026-08-31
Owners: RVM context and security maintainers
Related: #53, #54, ADR-159

## Context

RVM already provides capability-scoped authorization for governed `ruv://` operations. That answers whether an actor may perform an action. It does not by itself answer whether data derived from sensitive runtime context may cross a later sink boundary through a sequence of individually authorized operations.

Two recent results sharpen this gap.

* ContextLeak, arXiv:2608.27800, submitted 2026-08-28, demonstrates malicious tool metadata that induces an agent both to select the tool and to pass runtime context as tool arguments. The originating team reports transfer to Claude Code backed by Claude Sonnet 4.6: 22 malicious selections in 100 trials, with near-complete extraction conditional on selection. PromptGuard, DataSentinel, PromptArmor, and Ant MCPScan show 0.97 to 1.00 false-negative rates against the evaluated malicious metadata.
* ToolMinimize, arXiv:2608.24957, accepted at PST 2026, measures ordinary privacy oversharing even without a malicious tool. Across GPT-4o, Claude 3.5 Sonnet, and Llama-3.3-70B, 81 to 88 percent of default tool calls contain unnecessary privacy-sensitive data. The paper reports schema-aware argument rewriting reducing privacy cost by 81.2 to 92.0 percent at 100 percent argument-level validity, with 1.77 ms median middleware latency.

These results suggest that tool trust screening and prompt hardening are necessary but insufficient. The runtime needs an authoritative boundary that constrains what classes of context may leave a task through a sink, independently of what the model or tool metadata requests.

## Decision

Add a small, no-std flow policy primitive to `rvm-context` with three rules.

1. Every model-facing value that can reach an external sink may carry a `FlowLabel` containing a task scope, sensitivity class set, and deterministic lineage hash.
2. Ordinary transformations are monotonic. Derivation preserves every class. Multi-source composition unions every parent class. Version 1 deliberately exposes no declassification API.
3. Before disclosure, trusted policy supplies an `EgressBudget` for one sink and one task scope. Disclosure is allowed only when the label scope exactly matches and every carried class is explicitly permitted.

The initial classes are `PUBLIC`, `TASK_INPUT`, `RUNTIME_CONTEXT`, `PERSISTENT_MEMORY`, `TOOL_METADATA`, and `SECRET`.

A flow label or hash is evidence, not authority. It never grants `READ`, `WRITE`, `EXECUTE`, `GRANT`, `REVOKE`, or network authority. A caller still requires the relevant live RVM capability. Tool metadata, model output, memory, peer messages, consensus, and confidence are never allowed to create or widen an egress budget.

## Why this primitive is intentionally small

A full information-flow language is already tracked in issue #53. The first production primitive should be independently useful, easily reviewable, and reversible. It establishes the invariant needed by MCP, Ruflo, Core Memory, LatentMesh, and agent runtimes without committing RVM to a particular policy DSL or privacy classifier.

It also separates two problems that should not be conflated.

* Classification decides what a value contains or derives from.
* Authorization decides whether that class may cross a sink boundary.

Future argument minimization can reduce a label before the sink only through an explicit, separately reviewed release mechanism that proves the sensitive source material is no longer represented. Version 1 has no such mechanism.

## Security invariants

1. Unknown class bits are rejected.
2. Source labels require non-empty classes and a non-zero task scope.
3. Derivation cannot remove sensitivity.
4. Joining values unions all sensitivity and rejects cross-task composition.
5. Egress budgets are sink specific and task specific.
6. A deny-all budget is representable.
7. Flow lineage cannot be interpreted as an execution capability.
8. Model-controlled content cannot mutate the budget.
9. Parent count and transformation tag length are bounded to limit resource exhaustion.
10. Missing flow labels at an enforced boundary must be treated as unknown and denied by the integration layer. This crate does not silently invent a permissive label.

## Interfaces

```rust
let context = FlowLabel::source(
    FlowClasses::RUNTIME_CONTEXT,
    task_scope,
    b"conversation:turn:42",
)?;

let summarized = context.derive(b"summary:v1")?;

let budget = EgressBudget::new(
    weather_tool_sink,
    task_scope,
    FlowClasses::PUBLIC.union(FlowClasses::TASK_INPUT),
)?;

let receipt = budget.check(&summarized);
assert!(!receipt.decision().is_allowed());
```

## Cross-stack integration

* RVM: enforce the final egress decision next to the existing capability check.
* MCP: bind server and tool identity to the sink identifier; never derive the budget from tool descriptions.
* Core Memory: label retrieved memory before rendering it into model context.
* Ruflo and Autogenous: preserve labels in delegation and tool-call receipts.
* LatentMesh: propagate labels alongside compressed or latent payloads; compression cannot remove classes.
* RVF: sign portable artifacts and future controlled-release decisions.
* MetaHarness: independently reproduce malicious and benign context-passing cases.
* MidStream: observe denied flows and anomaly patterns without gaining authority to override the decision.

## Migration

The feature is additive. Existing context APIs remain unchanged. Integrations opt into enforcement one sink boundary at a time. No stored RVF or `ruv://` data migration is required.

Recommended rollout:

1. Shadow mode records flow decisions without blocking.
2. Enforce `SECRET` and `RUNTIME_CONTEXT` for untrusted third-party sinks.
3. Add Core Memory and MCP label propagation.
4. Expand to agent delegation and LatentMesh only after zero-loss propagation tests pass.
5. Consider controlled release or schema-aware argument minimization only after independent benchmark evidence.

## Benchmark protocol

The benchmark must compare current RVM behavior, metadata/tool scanning plus prompt hardening, flow-label enforcement, and flow-label enforcement plus any later argument minimizer.

Workload:

* ContextLeak-style user prompt, conversation history, tool list, persistent-memory, and mixed-context cases.
* Benign tools that legitimately require task input.
* Third-party and first-party sinks.
* At least two backend model families.
* At least 100 trials per attack class and matched benign class where model cost permits.

Required reporting:

* exact repository commit and branch
* Rust toolchain and target
* model/provider/version
* MCP/tool schemas and sink trust class
* seeds and sample size
* malicious tool selection rate
* unauthorized context disclosure rate
* benign tool task completion
* false block rate
* bytes and sensitivity classes transmitted
* p50 and p95 policy latency
* CPU and memory overhead
* token and provider cost
* malformed-input failures
* missing-label behavior
* cross-task attempts
* long-lineage and parent-limit cases
* ablations with task scope removed and class union removed
* reproduction commands and raw receipts

Primary acceptance gate:

* zero unauthorized disclosure for policy-visible labeled flows
* benign task success within 3 absolute percentage points of the stronger baseline
* median local flow-check overhead below 1 ms and below 1 percent of end-to-end tool-call latency
* zero class loss through summary, memory, MCP, and one agent-delegation transformation
* no capability expansion

ContextLeak attack-success numbers are originating-team measurements and must not be treated as RuV validation until independently reproduced.

## Dependency and runtime impact

The implementation reuses the existing `sha2` dependency already present in `rvm-context`. It introduces no new dependency, network surface, unsafe code, allocator requirement beyond the crate's existing `alloc` use, or persistent storage format.

## Rollback

Remove flow enforcement from sink adapters and retain existing action-scoped capability checks. Because the API is additive and no persistent data migration is introduced, rollback does not require rewriting stored context or RVF artifacts. Flow receipts may remain as historical evidence.

## Rejected alternatives

### Prompt-only privacy instructions

Rejected as an authority boundary. ContextLeak and ToolMinimize both report large residual leakage under instruction-level defenses.

### Tool metadata screening only

Rejected as a complete defense. ContextLeak reports false-negative rates of 0.97 to 1.00 for evaluated metadata detectors.

### Block every tool carrying sensitive input

Rejected as the target architecture because it destroys legitimate utility. RVM needs explicit per-sink budgets and, later, controlled minimization rather than universal blocking.

### Full policy DSL in this change

Deferred. Issue #53 remains the broader flow-policy program. A minimal invariant is easier to verify and gives the stack an immediate reusable boundary.

## Consequences

Positive:

* runtime context cannot be disclosed solely because a model or malicious tool asks for it
* the same primitive spans MCP, memory, agent delegation, latent transport, and external network sinks
* no model-specific defense is required
* the fast path is deterministic and local
* rollout and rollback are incremental

Negative:

* labels are only as correct as the trusted classification boundary that creates them
* coarse classes can over-block without a later minimization or controlled-release mechanism
* cross-stack integrations must preserve labels exactly
* a hash proves lineage identity, not semantic absence of sensitive information

The dominant unresolved risk is source misclassification. The fix path is to bind source-label creation to authenticated principals and schema/data classifiers, then test false-negative classification separately from egress authorization.
