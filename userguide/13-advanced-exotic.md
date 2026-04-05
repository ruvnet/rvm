# Advanced and Exotic: Novel Capabilities

RVM contains six capabilities with no prior art in existing hypervisors or
operating systems. Each emerged from the intersection of coherence theory,
capability security, and bare-metal systems engineering. This chapter explains
what each capability is, why it matters, and where to find the implementation
in the codebase.

For the foundational concepts behind these capabilities, start with [Core
Concepts](02-core-concepts.md). For the API surface, see [Crate
Reference](04-crate-reference.md).

---

## 1. Kernel-Level Graph Control Loop

**No other operating system uses spectral graph coherence as a first-class
scheduling signal.**

Traditional hypervisors schedule partitions by deadline, priority, or fair
share. RVM adds a second signal: *cut pressure*, derived from the coherence
graph. The coherence engine computes how tightly coupled each partition is to
its neighbors, and the scheduler uses that signal to prioritize partitions
that are part of an active communication cluster.

### How it works

1. The `CoherenceGraph` (in `rvm-coherence`) maintains a weighted adjacency
   structure where nodes are partitions and edges represent communication
   channels (`CommEdge`). Edge weights are updated as IPC traffic flows.

2. The scoring module (`rvm_coherence::scoring`) computes a `CoherenceScore`
   for each partition as the ratio of internal weight (self-loops) to total
   weight (all incident edges). Higher scores mean the partition is more
   self-contained; lower scores mean it is heavily coupled to neighbors.

3. The `EmaFilter` (in `rvm-coherence`) smooths raw scores using fixed-point
   exponential moving averages. This prevents scheduling jitter from noisy
   measurements.

4. The pressure module (`rvm_coherence::pressure`) derives a `CutPressure`
   signal from the graph structure. High cut pressure means the partition
   sits on a weak cut boundary -- it might benefit from migration or splitting.

5. The `AdaptiveCoherenceEngine` throttles recomputation frequency based on
   CPU load: every epoch below 60% load, every 2nd epoch at 60-80%, every
   4th epoch above 80%.

6. The scheduler (`rvm-sched`) combines two signals into a single priority:

   ```text
   priority = deadline_urgency + cut_pressure_boost
   ```

   Partitions with high cut pressure receive a scheduling boost, ensuring
   that coupled workloads run in close temporal proximity.

### Where to look

| Component | Crate | Module |
|---|---|---|
| Graph structure | rvm-coherence | `graph` |
| Score computation | rvm-coherence | `scoring` |
| Cut pressure | rvm-coherence | `pressure` |
| MinCut | rvm-coherence | `mincut` |
| Adaptive throttle | rvm-coherence | `adaptive` |
| EMA filter | rvm-coherence | root (`EmaFilter`) |
| 2-signal priority | rvm-sched | `priority` |

---

## 2. Reconstructable Memory (Time Travel)

**Unlike demand paging, RVM can reconstruct any historical memory state from
a checkpoint plus the witness trail.**

Traditional hypervisors page memory in and out of physical frames. When a
page is evicted, its contents are written to swap. When it is needed again,
the swap image is loaded. There is no concept of *historical* state -- you
can only access the current version.

RVM's dormant memory tier (Tier 2) stores state differently. Instead of a
raw swap image, a dormant region consists of:

1. A `CompressedCheckpoint` -- a snapshot of the region at a known-good point.
2. A sequence of `WitnessDelta` records -- every mutation since the checkpoint.

To restore a dormant region, the `ReconstructionPipeline` (in `rvm-memory`)
replays the deltas on top of the checkpoint:

```text
Load checkpoint --> Decompress --> Apply deltas in order --> Validate hash
```

Because the witness trail records *every* mutation with timestamps, you can
reconstruct the state of any region at any point in time, not just the latest
version. This enables forensic queries like "what was the state of region X
between 14:00 and 14:05?"

### Key types

| Type | Crate | Purpose |
|---|---|---|
| `CompressedCheckpoint` | rvm-memory | Snapshot with compression metadata |
| `WitnessDelta` | rvm-memory | Single mutation record with offset, length, data hash |
| `ReconstructionPipeline` | rvm-memory | Replay engine |
| `ReconstructionResult` | rvm-memory | Outcome with integrity verification |
| `CheckpointId` | rvm-memory | Unique checkpoint reference |

### Design constraints

- No heap allocation: all reconstruction works on caller-provided buffers.
- Delta integrity: each delta carries an FNV-1a hash of its data payload.
- The final reconstructed state is validated against an expected hash.

See [Memory Model](08-memory-model.md) for the four-tier architecture and
tier transition rules.

---

## 3. Proof-Gated Infrastructure

**Every mutation in RVM requires a valid proof. This is not authorization --
it is mathematical verification.**

In a traditional OS, access control asks "does this process have permission?"
RVM goes further: it asks "can this process *prove* that this state transition
is valid?" The proof must be submitted alongside the mutation request, and
the proof engine verifies it before the mutation proceeds.

The three proof tiers are:

| Tier | Name | Verification | Cost | Use Case |
|---|---|---|---|---|
| P1 | Capability Check | Rights bitmap lookup | < 1 ns | Every operation |
| P2 | Policy Validation | Hash preimage + witness | ~996 ns | State mutations |
| P3 | Deep Proof | Zero-knowledge (TEE) | Deferred | Privacy-preserving ops |

The `SecurityGate` (in `rvm-security`) enforces the three-stage pipeline:

1. **Capability check** -- Does the caller hold the right `CapToken` with
   the required `CapRights`?
2. **Proof verification** -- Does the submitted `Proof` satisfy its
   `WitnessHash` commitment?
3. **Witness logging** -- The decision (allow or deny) is recorded in the
   witness trail before the mutation executes.

This pipeline is wired at the kernel level. There is no way to bypass it --
not through a syscall, not through a hypercall, not through a device access.

See [Capabilities and Proofs](05-capabilities-proofs.md) for the full proof
system API and [Security](10-security.md) for the gate pipeline.

---

## 4. Witness-Native OS

**The audit trail is a first-class kernel object, not bolted-on logging.**

Most operating systems add audit logging as an afterthought -- a daemon that
watches system calls, a kernel tracepoint that can be disabled, or a log file
that can be deleted. In RVM, the witness trail is part of the kernel's
fundamental architecture. It cannot be disabled, deleted, or bypassed.

Every witness record is exactly 64 bytes (one cache line) and is emitted at
~17 ns per record. The record format is:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `sequence` (monotonic counter) |
| 8 | 8 | `timestamp_ns` |
| 16 | 1 | `action_kind` |
| 17 | 1 | `proof_tier` |
| 18 | 2 | `flags` |
| 20 | 4 | `actor_partition_id` |
| 24 | 4 | `target_object_id` |
| 28 | 4 | `capability_hash` |
| 32 | 8 | `payload` |
| 40 | 8 | `prev_hash` (FNV-1a chain) |
| 48 | 8 | `record_hash` |
| 56 | 8 | `aux` (signature or extension) |

The `prev_hash` and `record_hash` fields form a hash chain. Each record's
`prev_hash` equals the preceding record's `record_hash`. Breaking any link
is detectable by `verify_chain()`.

The witness is not just an audit log -- it is the *recovery mechanism*. The
`ReconstructionPipeline` uses witness deltas to rebuild dormant memory. The
fault rollback system uses witness records to determine the point of failure.

See [Witness and Audit](06-witness-audit.md) for the full witness system.

---

## 5. Live Partition Split and Merge

**No other hypervisor can dynamically re-isolate workloads along graph-
theoretic cut boundaries.**

Traditional VM migration moves an entire VM from one host to another. RVM
can split a single partition into two partitions, or merge two partitions
into one, while the system is running.

### Split

The `scored_region_assignment()` function (in `rvm-partition`) assigns each
memory region to the "left" or "right" child partition based on coherence
affinity:

```rust
pub fn scored_region_assignment(
    region_coherence: CoherenceScore,
    left_coherence: CoherenceScore,
    right_coherence: CoherenceScore,
) -> u16  // 0..10000: higher = prefer left
```

Regions are placed with the partition whose coherence profile is closest. The
MinCut algorithm identifies the optimal split boundary -- the point where
cutting the graph severs the fewest (weakest) communication edges.

### Merge

The `merge_preconditions_full()` function validates that two partitions can
be safely merged:

```rust
pub fn merge_preconditions_full(
    coherence_a: CoherenceScore,
    coherence_b: CoherenceScore,
    are_adjacent: bool,
    combined_cap_count: usize,
    max_caps_per_partition: usize,
) -> Result<(), MergePreconditionError>
```

Three preconditions must hold:

1. Both partitions must exceed the merge coherence threshold (7000 basis
   points by default).
2. The partitions must be adjacent in the coherence graph (they share a
   `CommEdge`).
3. The combined capability count must fit within the per-partition limit.

### Why this matters

Split and merge enable dynamic right-sizing of isolation domains. A partition
that has grown too large and contains loosely coupled workloads can be split
to improve isolation. Two small partitions that are tightly coupled can be
merged to reduce IPC overhead.

See [Partitions and Scheduling](07-partitions-scheduling.md) for the
partition lifecycle and state machine.

---

## 6. Edge Security on 64 KB RAM (Seed Profile)

**Full capability + proof + witness security on microcontroller-class hardware.**

The Seed hardware profile runs RVM on devices with as little as 64 KB of RAM.
At this scale, most systems run bare C with no memory protection, no process
isolation, and no audit trail. RVM provides:

- **Capability isolation.** Each partition has a scoped capability table.
  Code in partition A cannot access partition B's memory or devices without a
  valid `CapToken`.
- **Proof-gated mutations.** Even on a 64 KB device, every state change
  requires a proof (at minimum, a P1 capability check).
- **Witness trail.** A 64-record ring buffer (4 KB) records every privileged
  action. The hash chain ensures tamper evidence.
- **Measured boot.** The attestation digest proves exactly which code is
  running.

What makes this possible is the `no_std`, zero-heap, const-generic
architecture. The entire security stack compiles down to a few kilobytes of
code with fully predictable memory usage.

See [Bare-Metal Deployment](12-bare-metal.md) for build instructions and
[Security](10-security.md) for the security model.

---

## 7. Fault Rollback Classes

RVM defines four failure classes with escalating severity and recovery
strategies. Each escalation is recorded in the witness trail.

| Class | Name | Recovery Strategy | Scope |
|---|---|---|---|
| F1 | Transient | Agent restart | Single WASM agent within a partition |
| F2 | Recoverable | Partition reconstruct | Single partition from checkpoint + deltas |
| F3 | Permanent | Memory rollback | Partition destroyed, memory reclaimed |
| F4 | Catastrophic | Kernel reboot | System-wide measured re-attestation |

The `FailureClass` enum (in `rvm-types`) maps directly to these levels:

```rust
pub enum FailureClass {
    Transient = 0,    // F1
    Recoverable = 1,  // F2
    Permanent = 2,    // F3
    Catastrophic = 3, // F4
}
```

### Witnessed escalation

When an F1 recovery fails (agent restart does not resolve the issue), the
system escalates to F2 and records the escalation in the witness trail. If
F2 fails (checkpoint is corrupted or deltas are inconsistent), escalation
continues to F3 and then F4.

Every escalation emits a witness record with the old and new failure class,
the partition involved, and the reason for escalation. This creates an
auditable chain from initial fault to final resolution.

### Recovery checkpoint

The `RecoveryCheckpoint` type captures the state needed to restore a
partition:

```rust
pub struct RecoveryCheckpoint {
    pub partition: PartitionId,
    pub witness_sequence: u64,
    pub timestamp_ns: u64,
    pub epoch: u32,
}
```

The `ReconstructionReceipt` pairs a checkpoint with metadata about whether
the partition was hibernated or destroyed, guiding the reconstruction
pipeline.

---

## 8. Deterministic Edge Orchestration

RVM's three scheduling modes enable coexistence of safety-critical and
best-effort workloads on the same hardware.

| Mode | Behavior | Use Case |
|---|---|---|
| **Reflex** | Hard real-time. Bounded local execution only. No cross-partition IPC. | Safety-critical control loops |
| **Flow** | Normal execution with coherence-aware placement. | General workloads |
| **Recovery** | Stabilization. Replay, rollback, split operations. | Post-fault recovery |

### Reflex mode

In Reflex mode, the scheduler guarantees bounded latency by disabling all
cross-partition traffic. A partition running a safety-critical control loop
(e.g., motor controller, braking system) executes with deterministic timing.
This is enforced at the scheduler level -- no coherence recomputation, no
MinCut, no IPC message delivery.

### Coexistence

On an automotive ECU, a typical deployment might have:

- Partition 1 (Reflex): ADAS control loop -- 1 ms deadline, hard real-time
- Partition 2 (Flow): Infotainment UI -- best-effort, coherence-scheduled
- Partition 3 (Flow): Telemetry agent -- periodic data upload
- Partition 4 (Recovery): OTA update staging area

Each partition is isolated by capabilities. The Reflex partition cannot be
preempted by Flow partitions. If the infotainment partition crashes, it is
contained -- it cannot affect the ADAS control loop.

See [Partitions and Scheduling](07-partitions-scheduling.md) for the
scheduler modes and priority computation.

---

## 9. RuVector Integration

RVM's coherence engine can optionally use the RuVector library for advanced
graph computations. The integration is behind the `ruvector` feature flag in
`rvm-coherence`.

| RuVector Module | RVM Use |
|---|---|
| `ruvector-mincut` | Production-grade minimum cut algorithms |
| `ruvector-sparsifier` | Graph sparsification for large partition counts |
| `ruvector-solver` | Spectral solvers for coherence eigenvalue analysis |
| `ruvector-coherence` | IIT-inspired Phi computation pipelines |

When the `ruvector` feature is disabled (default), RVM uses its built-in
`MinCutBridge` (a budgeted Stoer-Wagner heuristic) and the simple
internal/total weight ratio for scoring. These built-in implementations are
sufficient for deployments with up to ~16 partitions.

For larger deployments (tens or hundreds of partitions), the RuVector backends
provide better algorithmic complexity and accuracy. The `RuVectorCoherenceEngine`
type (in `rvm_coherence::engine`) implements the `CoherenceBackend` trait and
can be substituted at compile time.

---

## Further Reading

- [Core Concepts](02-core-concepts.md) -- foundational theory behind coherence and capabilities
- [Capabilities and Proofs](05-capabilities-proofs.md) -- the three-tier proof system
- [Witness and Audit](06-witness-audit.md) -- witness record format and chain integrity
- [Partitions and Scheduling](07-partitions-scheduling.md) -- split, merge, and scheduling modes
- [Memory Model](08-memory-model.md) -- four-tier architecture and reconstruction
- [Security](10-security.md) -- security gate pipeline and TEE integration
- [Performance](11-performance.md) -- benchmark results for all subsystems
- [Bare-Metal Deployment](12-bare-metal.md) -- Seed and Appliance hardware profiles
- [Glossary](15-glossary.md) -- definitions for all terms used in this chapter
- [Cross-Reference Index](cross-reference.md) -- find every mention of a concept
