# Core Concepts: How RVM Thinks

This chapter explains the ideas behind RVM in plain language. No code, no API details -- just the mental model you need before diving into any of the technical chapters.

---

## Partitions, Not VMs

A traditional VM emulates a complete computer: CPU, memory controller, network card, disk, BIOS. That abstraction was designed for running Linux or Windows inside a box. AI agents do not need any of that. They need fast isolation, dynamic boundaries, and dense communication.

RVM replaces VMs with **partitions**. A partition is a coherence domain -- a lightweight container that holds:

- A capability table (what this partition is allowed to do)
- Communication edges to other partitions (who it talks to)
- Coherence and cut-pressure metrics (how tightly coupled it is)
- CPU affinity and a VMID assignment (where it runs)

A partition has no emulated hardware, no guest BIOS, and no virtual device model. It is the unit of **scheduling**, **isolation**, **migration**, and **fault containment**.

```
Traditional VM:
  +--------------------------+
  | Guest OS                 |
  | Virtual NIC, Disk, GPU   |
  | Emulated BIOS            |
  +--------------------------+
  | Hypervisor (KVM, Xen)    |
  +--------------------------+

RVM Partition:
  +--------------------------+
  | Capability table         |
  | CommEdges (graph links)  |
  | Coherence score          |
  +--------------------------+
  | RVM Kernel (bare Rust)   |
  +--------------------------+
```

The key difference: partition boundaries are **dynamic**. When agents inside two partitions start talking heavily, RVM can merge them or migrate one agent closer. When trust drops or coupling weakens, RVM can split a partition along the graph's natural cut boundary. No existing hypervisor can do this.

> **See also:** [Partitions and Scheduling](07-partitions-scheduling.md) for lifecycle states, split/merge semantics, and the 256-partition VMID limit.

---

## Capabilities: Unforgeable Keys

In most operating systems, access control is based on identity: "user X is allowed to read file Y." RVM uses a different model called **capability-based security**. Instead of asking "who are you?", RVM asks "what key do you hold?"

A **capability** is an unforgeable kernel-resident token. It has three parts:

1. **Target** -- the object it grants access to (a partition, memory region, device, etc.)
2. **Rights** -- a bitmask of what operations are allowed
3. **Lineage** -- who created this capability and how deep the delegation chain goes

### The 7 Rights

| Right | Meaning |
|-------|---------|
| `READ` | Inspect the target object's state |
| `WRITE` | Mutate the target object's state |
| `GRANT` | Delegate this capability to another partition (transitive) |
| `REVOKE` | Revoke a previously granted capability |
| `EXECUTE` | Invoke the target (run code, send IPC) |
| `PROVE` | Use the target in a proof context |
| `GRANT_ONCE` | Delegate exactly once (non-transitive) |

### Monotonic Attenuation

When you delegate a capability, you can only give away rights you already hold, and you can remove rights but never add them. This is called **monotonic attenuation** -- capabilities can only get weaker as they flow through the system, never stronger.

```
Root capability: READ + WRITE + GRANT + EXECUTE
        |
        +---> Delegated: READ + WRITE + EXECUTE   (GRANT removed)
                    |
                    +---> Delegated: READ          (WRITE + EXECUTE removed)
```

### Delegation Depth

To prevent unbounded chains, delegation depth is capped at **8 levels** (DC-3). This means the longest chain from a root capability to a leaf is at most 8 hops.

### Epoch-Based Revocation

Capabilities carry an **epoch counter**. When the kernel increments the epoch (for example, during a security event), all capabilities from the old epoch become stale. This provides a fast, global invalidation mechanism without walking every capability tree.

> **See also:** [Capabilities and Proofs](05-capabilities-proofs.md) for the derivation tree API, P1/P2/P3 verification, and nonce ring details.

---

## Witness Trail: Every Action Recorded

RVM follows a simple rule: **no witness, no mutation**. Every privileged action -- creating a partition, granting a capability, remapping memory, switching context -- emits a witness record *before* the mutation commits. If the witness cannot be written, the mutation does not happen.

### What a Witness Record Looks Like

Each record is exactly **64 bytes**, designed to fit in a single cache line:

```
+-------+-------+--------+-------+--------+--------+---------+---------+----------+----------+-----+
| seq   | time  | action | proof | flags  | actor  | target  | cap     | payload  | prev     | rec  | aux |
| (u64) | (u64) | (u8)   | (u8)  | (u16)  | (u32)  | (u32)   | (u32)  | (u64)    | hash     | hash | (u64)|
|       |       |        |       |        |        |         |        |          | (u64)    | (u64)|     |
+-------+-------+--------+-------+--------+--------+---------+---------+----------+----------+-----+
  8B      8B      1B       1B      2B       4B       4B        4B       8B         8B         8B    8B
                                                                                          = 64 bytes
```

### Hash Chain

Every record includes the hash of the **previous** record in its `prev_hash` field. This creates a tamper-evident chain: if anyone modifies a past record, all subsequent hashes break. The chain uses SHA-256 (with FNV-1a as a lightweight fallback for constrained hardware).

### Performance

Emitting a witness record takes approximately **17 nanoseconds** -- far below the ADR target of 500 ns. The witness log uses a ring buffer that holds 262,144 records (16 MB at 64 bytes each).

### Why It Matters

The witness trail enables three things no other hypervisor provides:

1. **Deterministic replay** -- given a checkpoint and the witness log, you can reconstruct exactly what happened
2. **Memory time travel** -- dormant memory is rebuilt from witness + checkpoint, not stored as raw bytes
3. **Forensic queries** -- "which partition mutated this region between 14:00 and 14:05?"

> **See also:** [Witness and Audit](06-witness-audit.md) for the emitter API, HMAC signing, replay queries, and `StrictSigner`.

---

## Proof Gates: Trust but Verify

Every state mutation in RVM must pass through a **proof gate**. This means you cannot remap memory, split a partition, grant a capability, or perform any other privileged operation without presenting a valid proof token.

The proof system has **three tiers**, each trading speed for assurance depth:

### Tier 1: Capability Check (P1)

| Property | Value |
|----------|-------|
| Budget | < 1 us |
| Measured | < 1 ns |
| What it checks | Does the caller hold a valid capability with the required rights? |
| When to use | Every routine operation (IPC send, memory read, context switch) |

P1 is a constant-time bitmask comparison. It is the hot path -- it runs on every hypercall.

### Tier 2: Policy Validation (P2)

| Property | Value |
|----------|-------|
| Budget | < 100 us |
| Measured | ~996 ns |
| What it checks | 6 policy rules (resource limits, partition state, epoch freshness, etc.) |
| When to use | Cross-partition operations, grants, device leases |

P2 runs a set of policy rules in constant time. It is more expensive than P1 but still sub-microsecond.

### Tier 3: Deep Proof (P3)

| Property | Value |
|----------|-------|
| Budget | < 10 ms |
| What it checks | Full derivation chain walk to root, ancestor integrity, epoch monotonicity |
| When to use | High-assurance operations, deferred zero-knowledge proofs |

P3 walks the entire capability derivation tree from leaf to root. It is the most expensive tier but provides the strongest guarantee.

```
Hypercall arrives
       |
       v
  +--------+     fail     +--------+
  |  P1    |------------->| DENY   |
  | (caps) |              +--------+
  +---+----+
      | pass
      v
  +--------+     fail     +--------+
  |  P2    |------------->| DENY   |
  |(policy)|              +--------+
  +---+----+
      | pass
      v
  +--------+
  | COMMIT | ---> emit witness ---> apply mutation
  +--------+
```

> **See also:** [Capabilities and Proofs](05-capabilities-proofs.md) for the proof engine API, TEE pipeline, and cryptographic signers (Ed25519, HMAC-SHA256).

---

## The Coherence Graph

RVM models agent communication as a **weighted graph**. Each partition is a node. Each communication channel between partitions is a **CommEdge** -- a weighted edge whose weight reflects how much traffic flows between the two endpoints.

```
  Partition A -----(w=150)------- Partition B
       |                              |
    (w=20)                        (w=200)
       |                              |
  Partition C -----(w=5)-------- Partition D
```

### Coherence Score

Every partition has a **coherence score** in the range [0.0, 1.0], stored as fixed-point basis points (0..10000). The score measures how much of the partition's communication is *internal* versus *external*:

```
coherence = internal_weight / total_weight
```

A score near 1.0 means the partition is well-isolated -- its agents mostly talk to each other. A score near 0.0 means its agents are heavily entangled with other partitions.

### Cut Pressure

When a partition's coherence drops below a threshold, RVM computes **cut pressure** -- a signal that the partition should be split. The coherence engine uses a budgeted Stoer-Wagner mincut algorithm (DC-2: < 50 us per epoch, measured at ~331 ns) to find the optimal cut boundary.

### Split and Merge

- **Split**: when cut pressure exceeds the split threshold, RVM divides the partition along the mincut boundary. Capabilities follow their owning objects (DC-8). Memory regions are assigned using weighted scoring (DC-9).
- **Merge**: when two adjacent partitions have high mutual coherence and sufficient resources, they can merge into one. Merges require 7 preconditions to be satisfied (DC-11).

### Why a Graph?

The graph is what makes RVM *coherence-native*. Traditional hypervisors treat communication as a side effect. RVM treats it as the primary signal for resource allocation. The scheduler reads coherence scores. The memory tier manager reads them. The split/merge engine reads them. The graph is the source of truth.

> **See also:** [Architecture](03-architecture.md) for where the coherence engine sits in the crate stack, [Partitions and Scheduling](07-partitions-scheduling.md) for split/merge details.

---

## Memory Time Travel

RVM does not use demand paging. Memory is not silently swapped to disk and fetched back on fault. Instead, RVM organizes memory into **four explicit tiers**:

| Tier | Name | Description |
|------|------|-------------|
| 0 | **Hot** | Per-core SRAM or L1-adjacent. Always resident during execution. |
| 1 | **Warm** | Shared DRAM. Resident if the residency rule is met. |
| 2 | **Dormant** | Compressed checkpoint + delta. Not directly accessible. |
| 3 | **Cold** | Persistent archival. Accessed only during recovery. |

### Tier Transitions Are Explicit

When the coherence score for a partition drops, its memory regions may be demoted:

```
Hot ---(coherence drops)---> Warm ---(idle too long)---> Dormant ---(archived)---> Cold
```

When the memory is needed again, it is **reconstructed**, not demand-paged:

```
Cold ---> Dormant ---> decompress checkpoint + replay witness deltas ---> Warm ---> Hot
```

### Why This Matters

Because dormant memory is stored as `checkpoint + witness deltas` rather than raw bytes, RVM can reconstruct **any historical state**. If you have the witness log and the checkpoint, you can answer questions like:

- What was partition 7's memory state at timestamp T?
- Which agent wrote to address 0x8000 between two specific witness records?
- What would have happened if we skipped mutation #4,219?

This is what the README calls "memory time travel." No other hypervisor provides this capability.

> **See also:** [Memory Model](08-memory-model.md) for the buddy allocator, tier thresholds, compression, and the reconstruction pipeline API.

---

## The Scheduler's Two Signals

RVM's scheduler combines two signals into a single priority number:

```
priority = deadline_urgency + cut_pressure_boost
```

### Signal 1: Deadline Urgency

How close is this partition to missing its deadline? Higher urgency means the partition runs sooner. This is the traditional real-time scheduling signal.

### Signal 2: Cut Pressure Boost

How much structural tension does this partition have in the coherence graph? A partition under high cut pressure needs CPU time to complete its migration or split. The coherence engine feeds this signal directly to the scheduler.

### Three Scheduling Modes

| Mode | Behavior | When Used |
|------|----------|-----------|
| **Reflex** | Hard real-time. Bounded local execution only. No cross-partition traffic. | Safety-critical paths (sensor fusion, PLC control) |
| **Flow** | Normal execution with coherence-aware placement. | Default mode for most agents |
| **Recovery** | Stabilization. Replay, rollback, split. | After a fault (F1-F3) |

### Degraded Mode

If the coherence engine is unavailable (DC-1 / DC-6), the scheduler falls back to **degraded mode**: it zeros out `cut_pressure_boost` and uses `deadline_urgency` alone. The system still works -- it just loses the ability to make graph-aware placement decisions.

> **See also:** [Partitions and Scheduling](07-partitions-scheduling.md) for the scheduler API, SMP coordination, and per-CPU runqueues.

---

## Design Constraints

RVM's behavior is governed by 15 design constraints (DC-1 through DC-15), defined in ADRs 132-140. These are not guidelines -- they are hard rules enforced by the implementation.

| ID | Constraint | Status |
|----|-----------|--------|
| DC-1 | Coherence engine is optional; system degrades gracefully | Implemented |
| DC-2 | MinCut budget: < 50 us per epoch | Implemented (~331 ns) |
| DC-3 | Capabilities are unforgeable, monotonically attenuated | Implemented |
| DC-4 | 2-signal priority: `deadline_urgency + cut_pressure_boost` | Implemented |
| DC-5 | Three systems cleanly separated (kernel + coherence + agents) | Enforced via features |
| DC-6 | Degraded mode when coherence unavailable | Implemented |
| DC-7 | Migration timeout enforcement (100 ms) | Implemented |
| DC-8 | Capabilities follow objects during partition split | Implemented |
| DC-9 | Coherence score range [0.0, 1.0] as fixed-point (u16 basis points) | Implemented |
| DC-10 | Epoch-based witness batching (no per-switch records) | Implemented |
| DC-11 | Merge requires coherence above threshold + adjacency + resources | Implemented |
| DC-12 | Max 256 physical VMIDs, multiplexed for >256 partitions | Implemented |
| DC-13 | WASM is optional; native bare partitions are first class | Enforced |
| DC-14 | Failure classes: transient (F1), recoverable (F2), permanent (F3), catastrophic (F4) | Implemented |
| DC-15 | All types are `no_std`, `forbid(unsafe_code)`, `deny(missing_docs)` | Enforced |

> **See also:** [Architecture](03-architecture.md) for how these constraints map to crate boundaries, [Security](10-security.md) for failure class escalation, [Glossary](15-glossary.md) for precise definitions.

---

## Cross-References

- [Architecture](03-architecture.md) -- how the crates implement these concepts
- [Capabilities and Proofs](05-capabilities-proofs.md) -- deep dive into the 3-tier proof system
- [Witness and Audit](06-witness-audit.md) -- witness record format, hash chain, signing
- [Partitions and Scheduling](07-partitions-scheduling.md) -- partition lifecycle, split/merge, scheduler modes
- [Memory Model](08-memory-model.md) -- four-tier memory, buddy allocator, reconstruction
- [Security](10-security.md) -- security gate, attestation, failure classes
- [Glossary](15-glossary.md) -- precise definitions for all RVM-specific terms
