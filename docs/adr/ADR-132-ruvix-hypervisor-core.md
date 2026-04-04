# ADR-132: RVM Hypervisor Core — Standalone Coherence-Native Microhypervisor

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-014 (Coherence Engine), ADR-124 (Dynamic Partition Cache), ADR-131 (Consciousness Metrics Crate)

---

## Context

Current virtualization technology centers on the VM as the fundamental unit of isolation and scheduling. KVM provides the dominant Linux virtualization API, Firecracker builds a minimalist microVM on top of KVM, and seL4 offers a formally verified microkernel with capability-based security. All of these treat a virtual machine (or process) as the primary abstraction boundary.

RVM changes this. Instead of VMs, the primary abstraction is **coherence domains** — dynamically partitioned graph regions where placement, isolation, and migration decisions are driven by graph-theoretic cut pressure and locality scoring. Every privileged mutation is proof-gated (capability-based authority) and every privileged action emits a compact witness record for full auditability.

RVM is NOT a KVM VMM. It boots bare-metal and owns the hardware directly.

### Problem Statement

1. **VM-centric virtualization wastes coherence**: Traditional hypervisors allocate resources per-VM without understanding the coupling structure of the workloads inside. Cross-VM communication pays full exit cost regardless of locality.
2. **No coherence-native hypervisor exists**: No existing system uses graph partitioning (mincut) as a first-class scheduling and isolation primitive.
3. **Agent workloads need finer-grained isolation**: Multi-agent edge deployments require partitions that are smaller, faster to switch, and cheaper to migrate than full VMs.
4. **Audit trails are bolted on, not native**: Existing hypervisors treat logging as an afterthought. Witness-native operation requires audit records as a core kernel object.
5. **Rust proves viable for bare-metal kernels**: RustyHermit, Theseus, RedLeaf, and Tock demonstrate that Rust can own hardware directly, eliminating classes of memory safety bugs that plague C-based kernels.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| KVM | Dominant Linux virtualization API | Baseline comparison; RVM deliberately avoids this dependency |
| Firecracker (AWS) | Minimalist KVM-based microVM, ~125ms boot | Performance target; RVM targets <250ms cold boot without KVM |
| seL4 | Formally verified capability-based microkernel | Capability model inspiration; RVM defers formal verification to post-v1 |
| Rust in Linux (6.1+) | Memory safety in kernel modules | Validates Rust for systems programming; RVM goes further with 95-99% Rust |
| RustyHermit | Bare-metal Rust unikernel | Proves bare-metal Rust boot viability |
| Theseus OS | Intralingual OS design in Rust | Demonstrates Rust ownership for OS resource management |
| RedLeaf | Rust language-based OS with cross-domain isolation | Informs partition isolation model |
| Tock | Embedded Rust OS with capability-based security | Informs capability + device lease model for constrained hardware |
| RuVector mincut crate | Graph-theoretic minimum cut computation | Direct dependency for partition placement and isolation decisions |

---

## Decision

Build RVM as a standalone bare-metal Rust hypervisor with the following core properties:

1. **No KVM/Linux dependency** — boots directly on hardware via QEMU virt, ARM, RISC-V
2. **Coherence domains** as the primary abstraction (not VMs)
3. **Dynamic mincut** (using RuVector's `mincut` crate) for placement, isolation, and migration
4. **Proof-gated mutation** — three-layer proof system (see below); no privileged action without valid authority
5. **Witness-native** — every privileged action emits a compact, immutable audit record
6. **Rust-first** — 95-99% Rust; assembly only for reset vector, trap entry, and context switch stubs
7. **Reconstructable memory** — 4-tier model (hot/warm/dormant/cold) with cut-pressure-driven eviction
8. **Agent-optimized** — WASM partition adapter for multi-agent edge workloads
9. **Coherence engine is optional** — kernel MUST boot and run without the graph/mincut/solver subsystem
10. **Graceful degradation** — if coherence engine fails or exceeds budget, system falls back to locality-based scheduling

---

## Design Constraints (Critical)

These constraints exist to prevent scope collapse. Every contributor and reviewer must enforce them.

### DC-1: Coherence Engine is Optional

The kernel (Layer 1) MUST boot, schedule, isolate, and emit witnesses **without Layer 2** (coherence engine). Layer 2 is an optimization, not a dependency. If the coherence engine panics, is absent, or exceeds its time budget, the kernel degrades to locality-based scheduling using static partition affinity.

**Contract**: `Layer 1 depends on Layer 0 only. Layer 2 depends on Layer 1. Never the reverse.`

### DC-2: Mincut Never Blocks Scheduling

Dynamic mincut MUST operate within a hard time budget per scheduler epoch:

```
max_mincut_time_per_epoch = 50 microseconds (configurable)
if exceeded:
    use last_known_cut
    set degraded_flag = true
    log witness(MINCUT_BUDGET_EXCEEDED)
```

Mincut runs asynchronously between epochs when possible. The scheduler always has a valid (possibly stale) cut to use. **Mincut must NEVER block a scheduling decision.**

### DC-3: Three-Layer Proof System

The proof system is NOT one thing. It is three distinct layers with different latency budgets:

| Layer | Name | Budget | What It Does |
|-------|------|--------|-------------|
| **P1** | Capability check | < 1 us | Validates unforgeable token exists and carries required rights. Bitmap comparison. Fast path. |
| **P2** | Policy validation | < 100 us | Validates structural invariants (ownership chains, region bounds, lease expiry, delegation depth). |
| **P3** | Deep proof | < 10 ms | Optional cryptographic or semantic verification (hash chains, attestation, cross-partition proofs). Only invoked for high-stakes mutations (migration, merge, device lease). |

**v1 ships P1 + P2 only.** P3 is Phase 2+. Conflating these three systems is a design error.

### DC-4: Scheduler Starts Simple

v1 scheduler uses **two signals only**:

```
priority = deadline_urgency + cut_pressure_boost
```

Novelty scoring and structural risk are deferred to post-v1. Ship a working scheduler first, then add intelligence. Four interacting signals in the hot path is a bottleneck waiting to happen.

### DC-5: Three Systems, Cleanly Separated

RVM is simultaneously a hypervisor, a graph engine, and an agent runtime. These MUST be separable:

| System | Can Run Alone? | Degrades Without |
|--------|---------------|-----------------|
| Kernel (hypervisor) | YES — this is the foundation | Nothing — it is the root |
| Coherence engine | NO — needs kernel | Kernel runs with static placement |
| Agent runtime (WASM) | NO — needs kernel | Kernel runs bare partitions only |

**Failure mode to prevent**: everything depends on everything. Each system must have a clear degradation story.

### DC-6: Degraded Mode is Explicit

When the coherence engine is unavailable or over-budget, the kernel enters **degraded mode**:

```
if coherence_engine_unavailable OR coherence_engine_over_budget:
    disable split/merge operations
    use static partition affinity (locality-based)
    scheduler uses deadline_urgency only (cut_pressure = 0)
    memory tiers use static thresholds for promotion/demotion
    emit witness(DEGRADED_MODE_ENTERED)
```

This is the **guaranteed baseline**. The system is always usable without intelligence.

### DC-7: Migration Has a Time Budget

Partition migration (serialize → transfer → rebuild) MUST complete within a hard bound:

```
max_migration_time = 100 milliseconds (configurable per partition size class)
if exceeded:
    abort migration
    restore source partition to Running
    emit witness(MIGRATION_TIMEOUT, partition_id, elapsed_ms)
    mark partition as migration_ineligible for cooldown_period
```

Unbounded migration is a liveness hazard. Partial migration is not permitted — it either completes or aborts cleanly.

### DC-8: Capabilities Follow Ownership on Split

During partition split, capabilities MUST NOT blindly duplicate. Capabilities follow the objects they reference:

```
for each capability in splitting_partition:
    if capability.target_object is on side_A:
        assign capability to partition_A only
    elif capability.target_object is on side_B:
        assign capability to partition_B only
    elif capability.target_object is shared:
        attenuate to READ_ONLY in both
        emit witness(CAPABILITY_ATTENUATED_ON_SPLIT)
```

Blind duplication leaks authority across partition boundaries. This is a security invariant, not an optimization.

### DC-9: Region Assignment Uses Scored Placement

During partition split, region assignment uses a **weighted score**, not naive majority-accessor:

```
region_score(side) = alpha * local_access_fraction
                   + beta  * remote_access_cost_avoided
                   + gamma * size_penalty
```

With `alpha=0.5, beta=0.3, gamma=0.2` as starting weights. Assign region to the side with higher score. This prevents oscillation from hotspots with cross-cut access patterns (shared model weights, graph state).

### DC-10: Partition Switch is Not Individually Witnessed (With Epoch Summary)

Individual partition switches are NOT witnessed (they must be < 10μs). Instead:

```
every scheduler_epoch (e.g., every 1ms):
    emit witness(EPOCH_SUMMARY, {
        switch_count,
        partition_ids_active,
        total_switch_time_us,
        degraded_flag
    })

if debug_mode:
    sample 1 in N switches with full witness
```

This preserves auditability without adding latency to the hot path.

### DC-11: Merge Requires Strong Preconditions

Partition merge requires more than shared edge + coherence threshold:

```
merge_preconditions:
    1. shared CommEdge exists                    (structural)
    2. coherence_score > merge_threshold         (graph signal)
    3. no conflicting device leases              (resource)
    4. no overlapping mutable memory regions     (safety)
    5. capability intersection is valid          (authority)
    6. both partitions in Running or Suspended   (lifecycle)
    7. proof P2 validates merge authority         (security)
```

Missing any precondition = merge rejected + witness emitted. Weak merge preconditions lead to authority leaks and resource conflicts.

### DC-12: Logical Partitions Exceed Physical Slots

Hardware VMID space is bounded (e.g., 256 on ARM). Agent workloads can exceed this.

```
logical_partition_count <= MAX_LOGICAL (configurable, e.g., 4096)
physical_partition_slots = hardware VMID limit (e.g., 256)

if logical > physical:
    multiplex: least-recently-scheduled logical partitions yield physical slots
    on reschedule: flush TLB, reassign VMID, restore stage-2 mappings
    emit witness(VMID_RECLAIM, old_partition, new_partition)
```

This separates the scheduling abstraction from hardware limits. Physical slots are a cache, not a ceiling.

### DC-13: WASM is Optional — Native Partitions Are First Class

v1 supports **native bare partitions** as the primary execution mode. WASM is an optional safety/portability layer, not a hard dependency:

```
partition_types:
    bare:   native code runs directly in partition (v1 primary)
    wasm:   WASM module runs inside partition via wasmtime (v1 optional, Phase 4)
```

This enables early validation without WASM overhead, and allows performance-critical workloads to run native. WASM becomes a **portability and sandboxing layer**, not an execution requirement.

### DC-14: Failure Classification (F1-F4)

Every failure must be classified and escalated predictably:

| Class | Scope | Response |
|-------|-------|----------|
| F1 | Agent failure (single WASM/native) | Restart within partition |
| F2 | Partition failure | Terminate + reconstruct from checkpoint |
| F3 | Memory corruption | Rollback affected region, Recovery mode |
| F4 | Kernel failure | Full reboot from A/B image |

**Escalation**: F1 → F2 after 3 restart failures. F2 → F3 if reconstruction fails. F3 → F4 if rollback fails. Each escalation is witnessed. "Recover without reboot" means F1-F3, not F4.

### DC-15: Control Partition Required on Appliance

Every Appliance deployment includes a **control partition** — the operator's interface to the system:

- Witness log queries
- Partition inspection and management
- Health monitoring and anomaly detection
- Debug console (serial or network)

The control partition is the first user partition created at boot. It has elevated capabilities but is still subject to proof-gated mutation — it cannot bypass the security model.

---

## Architecture

### Layer Model

```
Layer 4: Persistent State
         witness log | compressed dormant memory | RVF checkpoints
         ─────────────────────────────────────────────────────────
Layer 3: Execution Adapters
         bare partition | WASM partition | service adapter
         ─────────────────────────────────────────────────────────
Layer 2: Coherence Engine
         graph state | mincut | pressure scoring | migration
         ─────────────────────────────────────────────────────────
Layer 1: RVM Core (Rust, no_std)
         partitions | capabilities | scheduler | witnesses
         ─────────────────────────────────────────────────────────
Layer 0: Machine Entry (assembly)
         reset vector | trap handlers | context switch
```

**Layer 0 — Machine Entry** (assembly, <500 LoC total):
Minimal assembly for hardware reset, exception/interrupt trap entry, and register-level context switch. Everything else is Rust.

**Layer 1 — RVM Core** (Rust, `#![no_std]`):
Partition lifecycle, capability creation/verification/revocation, witness emission, scheduler tick, memory region management. This layer owns all hardware resources and enforces the capability discipline.

**Layer 2 — Coherence Engine** (Rust, **optional** — see DC-1):
Maintains the runtime coherence graph — partitions as nodes, communication channels as weighted edges. Runs the mincut algorithm to compute cut pressure (within hard time budget — see DC-2), derives placement and migration decisions, and triggers partition splits or merges when pressure thresholds are crossed. **If absent or failed, kernel falls back to locality-based static placement.**

**Layer 3 — Execution Adapters** (Rust):
Provides runtime environments within partitions. The bare partition adapter runs native code directly. The WASM partition adapter hosts WebAssembly modules for agent workloads. The service adapter exposes inter-partition RPC.

**Layer 4 — Persistent State**:
Witness log (append-only, tamper-evident), compressed dormant memory (tier 3 of the memory model), and RVF-backed checkpoints for full state recovery.

### First-Class Objects

| Object | Description |
|--------|-------------|
| **Partition** | Coherence domain container; unit of scheduling, isolation, and migration |
| **Capability** | Unforgeable authority token; grants specific rights over specific objects |
| **Witness** | Compact audit record emitted by every privileged action |
| **MemoryRegion** | Typed, tiered, owned memory range with explicit lifetime |
| **CommEdge** | Inter-partition communication channel; weighted edge in the coherence graph |
| **DeviceLease** | Time-bounded, revocable access grant to a hardware device |
| **CoherenceScore** | Locality and coupling metric derived from the coherence graph |
| **CutPressure** | Graph-derived isolation signal; high pressure triggers migration or split |
| **RecoveryCheckpoint** | State snapshot for rollback and reconstruction |

### Scheduling Modes

| Mode | Behavior |
|------|----------|
| **Reflex** | Hard real-time. Bounded local execution only. No cross-partition traffic. Deterministic worst-case latency. |
| **Flow** | Normal execution. v1 priority = `deadline_urgency + cut_pressure_boost` (DC-4). Coherence-aware placement when engine available; locality-based otherwise. |
| **Recovery** | Stabilization mode. Replay witness log, rollback to checkpoint, split partitions, rebuild memory from dormant tier. |

### Memory Model

The memory model is a key differentiator. Pages are not simply resident or swapped — they occupy one of four tiers, and promotion/demotion is driven by cut-value and recency, not just access frequency.

| Tier | Location | Contents | Residency Rule |
|------|----------|----------|----------------|
| **Hot** | Tile/core-local | Active execution state | Always resident during partition execution |
| **Warm** | Shared fast memory within cluster | Recently-used shared state | Resident if cut-value justifies cross-partition sharing |
| **Dormant** | Compressed storage | Proof objects, embeddings, suspended state | Compressed; restored on demand or at recovery |
| **Cold** | RVF-backed archival | Checkpoints, historical state | Restore points; accessed only during recovery |

Pages stay resident only if `cut_value + recency_score > eviction_threshold`. The coherence engine continuously recomputes these scores as the graph evolves.

### RuVector Crate Integration

RVM leverages existing RuVector crates rather than reimplementing graph primitives:

| Crate | Usage in RVM |
|-------|---------------|
| `mincut` | Partition placement decisions, isolation boundary computation, migration triggers |
| `sparsifier` | Efficient sparse graph representation for the coherence graph |
| `solver` | Coherence score computation, spectral analysis for pressure detection |
| `ruvector-cnn` | (Potential) Neural scheduling heuristics for workload prediction |

---

## Target Platforms

| Platform | Profile | Characteristics |
|----------|---------|----------------|
| **Seed** | Tiny, persistent, event-driven | Hardware-constrained, single or few partitions, deep sleep, witness-only audit |
| **Appliance** | Edge hub, deterministic orchestration | Bounded multi-agent workloads, real-time scheduling, full coherence engine |
| **Chip** | Future Cognitum silicon | Tile-local memory, hardware-assisted partition switch, native coherence scoring |

---

## Success Criteria (v1)

| # | Criterion | Target |
|---|-----------|--------|
| 1 | Cold boot to first witness | < 250ms on Appliance hardware |
| 2 | Hot partition switch latency | < 10 microseconds |
| 3 | Remote memory traffic reduction | >= 20% vs naive (non-coherence-aware) placement |
| 4 | Tail latency reduction | >= 20% under mixed partition pressure |
| 5 | Witness completeness | Full trail for every migration, remap, and device lease |
| 6 | Fault recovery | Recover from injected fault without global reboot |

---

## Non-Goals (v1)

- Full Linux ABI compatibility
- Large device model surface (USB, GPU, network card diversity)
- Desktop or workstation use
- Full formal verification (deferred to post-v1; seL4-style proofs are multi-year efforts)
- Cloud VM replacement (strongest advantage is edge/appliance coherence)

---

## Consequences

### Positive

- **Category-defining**: Coherence-native, not VM-native. No existing hypervisor operates on graph-partitioned coherence domains as a first-class primitive.
- **Agent-optimized**: Partitions fit agent workloads (small, fast-switching, WASM-compatible) better than full VMs.
- **Memory-safe by construction**: Rust eliminates use-after-free, buffer overflow, and data race classes that account for ~70% of kernel CVEs in C-based systems.
- **Auditable by default**: Witness-native operation means the audit trail is not a separate subsystem but a core kernel object.
- **Leverages existing work**: Direct integration with RuVector's `mincut`, `sparsifier`, and `solver` crates avoids reimplementing graph algorithms.
- **Minimal attack surface**: No Linux dependency, no KVM ioctl surface, no legacy device models.

### Negative

- **Higher conceptual complexity**: Coherence domains, cut pressure, and graph-driven scheduling are less familiar than VM/process abstractions. Documentation and developer onboarding require extra investment.
- **Algorithmic cost of dynamic mincut**: Mincut at the wrong granularity or frequency can become a scheduling bottleneck. Hard budget (DC-2) and stale-cut fallback are mandatory. Mincut must NEVER block scheduling.
- **Three-system coupling risk**: RVM is simultaneously hypervisor + graph engine + agent runtime. Without strict layering discipline (DC-5), everything depends on everything and debugging becomes impossible.
- **No commodity ecosystem**: Cannot run unmodified Linux binaries. No free compatibility with existing container or VM tooling.
- **No formal verification posture initially**: The capability model provides safety properties, but machine-checked proofs are deferred. This limits adoption in safety-critical domains until post-v1 verification work completes.

---

## Rejected Alternatives

| Alternative | Reason for Rejection |
|-------------|---------------------|
| **KVM-based VMM (Firecracker model)** | Does not create a new abstraction. Still Linux-dependent. Cannot achieve sub-10-microsecond partition switch through KVM exit path. |
| **seL4 clone** | Over-constrains v1 delivery speed. Formal verification adds years to timeline. seL4's abstraction is still process/thread-centric, not coherence-centric. |
| **C implementation** | Wrong language for a proof/witness/ownership-heavy design. Rust's type system enforces capability discipline at compile time. C would require runtime checks for properties Rust guarantees statically. |
| **Cloud-first target** | RVM's strongest advantage is edge/appliance coherence where workloads are bounded and latency-sensitive. Cloud VMs are well-served by existing solutions. |

---

## Implementation Milestones

### Critical Path Phases

The milestones are grouped into four phases with strict dependencies. **Phase 1 must succeed or nothing else matters.**

#### Phase 1: Foundation (M0-M1) — "Can it boot and isolate?"

| Milestone | Deliverable | Gate |
|-----------|-------------|------|
| **M0** | Bare-metal Rust boot on QEMU (no KVM). Reset vector, EL2 entry, serial output, basic trap handling, MMU. | Serial output from Rust code |
| **M1** | Partition + capability object model (P1 + P2 proof layers). Create, destroy, switch partitions with capability checks. Simple deadline-based scheduler. | Two isolated partitions, capability-enforced |

#### Phase 2: Differentiation (M2-M3) — "Can it prove and witness?"

| Milestone | Deliverable | Gate |
|-----------|-------------|------|
| **M2** | Witness logging + proof verifier. Every privileged action emits a 64-byte chained witness. Replay and audit. | Full witness chain from boot to shutdown |
| **M3** | Scheduler with 2-signal priority (deadline + cut_pressure, per DC-4). Flow and Reflex modes. Basic IPC with zero-copy. | Partition switch < 10us |

#### Phase 3: Innovation (M4-M5) — "Can it think about coherence?"

| Milestone | Deliverable | Gate |
|-----------|-------------|------|
| **M4** | Dynamic mincut integration (with DC-2 budget enforcement). Live coherence graph, cut pressure, migration triggers. Stale-cut fallback. | One mincut-guided placement decision with witness proof |
| **M5** | Memory tier management. Hot/warm/dormant/cold tiers with cut-pressure-driven promotion and eviction. Reconstruction from dormant state. | 20% remote memory traffic reduction vs naive baseline |

#### Phase 4: Expansion (M6-M7) — "Can agents run on it?"

| Milestone | Deliverable | Gate |
|-----------|-------------|------|
| **M6** | WASM agent runtime adapter. Host WebAssembly modules inside partitions. Agent lifecycle (spawn, migrate, hibernate, reconstruct). | Agent spawns, communicates, migrates between partitions |
| **M7** | Seed/Appliance hardware bring-up. Boot on real hardware targets, validate all success criteria end-to-end. | All 6 success criteria met on hardware |

### 4-6 Week Acceptance Test

RVM is on track if within 4-6 weeks (end of Phase 1 + early Phase 2) it can demonstrate:

1. Boot on QEMU AArch64 virt (no KVM, bare-metal EL2)
2. Create two isolated partitions
3. Enforce capability-based isolation between them
4. Emit witness records for every privileged action
5. Switch partitions in under 10 microseconds

**Before mincut. Before WASM. Before anything fancy.**

---

## Follow-On ADRs

| ADR | Topic |
|-----|-------|
| ADR-133 | Partition Object Model |
| ADR-134 | Witness Schema and Log Format |
| ADR-135 | Proof Verifier Design |
| ADR-136 | Memory Hierarchy and Reconstruction |
| ADR-137 | Bare-Metal Boot Sequence |
| ADR-138 | Seed Hardware Bring-Up |
| ADR-139 | Appliance Deployment Model |
| ADR-140 | Agent Runtime Adapter |

---

## References

- Barham, P., et al. "Xen and the Art of Virtualization." SOSP 2003.
- Klein, G., et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009.
- Agache, A., et al. "Firecracker: Lightweight Virtualization for Serverless Applications." NSDI 2020.
- Narayanan, V., et al. "RedLeaf: Isolation and Communication in a Safe Operating System." OSDI 2020.
- Boos, K., et al. "Theseus: an Experiment in Operating System Structure and State Management." OSDI 2020.
- Levy, A., et al. "The Case for Writing a Kernel in Rust." APSys 2017.
- RuVector mincut crate: `crates/mincut/`
- RuVector sparsifier crate: `crates/sparsifier/`
- RuVector solver crate: `crates/solver/`
