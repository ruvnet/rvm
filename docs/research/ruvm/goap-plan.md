# RVM Hypervisor Core -- GOAP Plan

> Goal-Oriented Action Planning for the RVM Coherence-Native Microhypervisor

| Field | Value |
|-------|-------|
| Status | Draft |
| Date | 2026-04-04 |
| Scope | Research + Architecture + Implementation roadmap |
| Relates to | ADR-087 (RVM Cognition Kernel), ADR-106 (Kernel/RVF Integration), ADR-117 (Canonical MinCut) |

---

## 0. Executive Summary

This document defines the GOAP (Goal-Oriented Action Planning) strategy for **RVM Hypervisor Core** -- a Rust-first, coherence-native microhypervisor that replaces the VM abstraction with **coherence domains**: graph-partitioned isolation units managed by dynamic min-cut, governed by proof-gated capabilities, and optimized for multi-agent edge computing.

RVM Hypervisor Core is NOT a KVM VMM. It is NOT a Linux module. It is a standalone hypervisor that boots bare metal, manages hardware directly, and uses coherence domains as its primary scheduling and isolation primitive. Traditional VMs are subsumed as a degenerate case (a coherence domain with a single opaque partition and no graph structure).

### Current State Assessment

The RuVector project already has significant infrastructure in place:

- **ruvix kernel workspace** -- 22 sub-crates, ~101K lines of Rust, 760 tests passing (Phase A complete)
- **ruvix-cap** -- seL4-inspired capability system with derivation trees
- **ruvix-proof** -- 3-tier proof engine (Reflex <100ns, Standard <100us, Deep <10ms)
- **ruvix-sched** -- Coherence-aware scheduler with novelty boosting
- **ruvix-hal** -- HAL traits for AArch64, RISC-V, x86 (trait definitions)
- **ruvix-aarch64** -- AArch64 boot, MMU stubs
- **ruvix-physmem** -- Physical memory allocator
- **ruvix-boot** -- 5-stage RVF boot with ML-DSA-65 signatures
- **ruvix-nucleus** -- 12 syscalls, checkpoint/replay
- **ruvector-mincut** -- Subpolynomial dynamic min-cut (the crown jewel)
- **ruvector-sparsifier** -- Dynamic spectral graph sparsification
- **ruvector-solver** -- Sublinear-time sparse solvers
- **ruvector-coherence** -- Coherence scoring with spectral support
- **ruvector-raft** -- Distributed consensus
- **ruvector-verified** -- Formal verification with lean-agentic dependent types
- **cognitum-gate-kernel** -- 256-tile coherence gate fabric (WASM)
- **qemu-swarm** -- QEMU cluster simulation

### Goal State

A running microhypervisor that:

1. Boots bare metal on QEMU virt (AArch64) to first witness in <250ms
2. Manages coherence domains (not VMs) as the primary isolation unit
3. Uses dynamic min-cut to partition, migrate, and reclaim partitions
4. Gates every privileged mutation with capability proofs
5. Emits a complete witness trail for every state change
6. Achieves hot partition switch in <10us
7. Reduces remote memory traffic by 20% via coherence-aware placement
8. Runs WASM agent partitions with zero-copy IPC
9. Recovers from faults without global reboot

---

## 1. Research Phase Goals

### 1.1 Bare-Metal Rust Hypervisors and Microkernels

**Goal state:** Deep understanding of existing Rust bare-metal systems to inform what to adopt, adapt, and discard.

| Project | Why Study It | Key Takeaway for RVM |
|---------|-------------|----------------------|
| **RustyHermit / Hermit** | Unikernel in Rust; uhyve hypervisor boots directly. No Linux dependency. | Boot sequence patterns, QEMU integration, minimal device model |
| **Theseus OS** | Rust OS with live code swapping, cell-based memory. No address spaces. | Intralingual design, state spill prevention, namespace-based isolation |
| **RedLeaf** | Rust OS with language-level isolation, no hardware protection needed for safety. | Ownership-based isolation as alternative to page tables for trusted partitions |
| **Tock OS** | Embedded Rust OS with grant regions, capsule isolation. | Grant-based memory model maps to RVM region policies |
| **Hubris** | Oxide Computer's embedded Rust RTOS with static task allocation. | Panic isolation, supervisor/task fault model |
| **Firecracker** | KVM VMM in Rust. Anti-pattern for architecture (depends on KVM), but study for device model. | Minimal device model pattern, virtio implementation |

**Actions:**
- [ ] A1.1.1: Read Theseus OS OSDI 2020 paper -- extract cell/namespace isolation patterns
- [ ] A1.1.2: Read RedLeaf OSDI 2020 paper -- extract ownership-based isolation model
- [ ] A1.1.3: Study Hubris source for panic-isolated task model
- [ ] A1.1.4: Study RustyHermit uhyve for bare-metal boot without KVM

**Preconditions:** None
**Effects:** Design vocabulary for coherence domains established; isolation model decision data gathered

### 1.2 Capability-Based OS Designs

**Goal state:** Identify which capability model to adopt for proof-gated coherence domains.

| System | Why Study It | Key Takeaway |
|--------|-------------|-------------|
| **seL4** | Formally verified microkernel with capability-based access control. Gold standard. | Derivation trees, CNode design, retype mechanism. Already partially adopted in ruvix-cap. |
| **CHERI** | Hardware capability extensions (Arm Morello). Capabilities in registers. | Hardware-enforced bounds on pointers; could replace page table boundaries for fine-grained isolation |
| **Barrelfish** | Multikernel OS with capability system and message-passing IPC. | Per-core kernel model; capability transfer across cores maps to coherence domain migration |
| **Fuchsia/Zircon** | Capability-based microkernel from Google. Handles as capabilities. | Practical capability system at scale; job/process/thread hierarchy |

**Actions:**
- [ ] A1.2.1: Map seL4 CNode/Untyped/Retype to ruvix-cap derivation trees -- identify gaps
- [ ] A1.2.2: Study CHERI Morello ISA for hardware-backed capability enforcement
- [ ] A1.2.3: Study Barrelfish multikernel design for cross-core capability transfer
- [ ] A1.2.4: Evaluate Fuchsia handle table design for runtime performance characteristics

**Preconditions:** A1.1 partially complete (understand isolation context)
**Effects:** Capability model finalized; hardware vs. software enforcement decision made

### 1.3 Graph-Partitioned Scheduling

**Goal state:** Algorithm for coherence-pressure-driven scheduling that leverages ruvector-mincut.

| Topic | Reference | Relevance |
|-------|-----------|-----------|
| **Graph-based task scheduling** | Kwok & Ahmad survey (1999); modern DAG schedulers | Task dependency graphs as scheduling input |
| **Spectral graph partitioning** | Fiedler vectors, Normalized Cuts (Shi & Malik 2000) | Coherence domain boundary identification |
| **Dynamic min-cut for placement** | ruvector-mincut (our own subpolynomial algorithm) | Core algorithm for partition placement |
| **Network flow scheduling** | Coffman-Graham, Hu's algorithm | Precedence-constrained scheduling with graph structure |
| **NUMA-aware scheduling** | Linux NUMA balancing, AutoNUMA | Coherence-aware memory placement (lower-bound benchmark) |

**Actions:**
- [ ] A1.3.1: Formalize the coherence-pressure scheduling problem as a graph optimization
- [ ] A1.3.2: Prove that dynamic min-cut provides bounded-approximation partition quality
- [ ] A1.3.3: Design the scheduler tick: {observe graph state} -> {compute pressure} -> {select task}
- [ ] A1.3.4: Benchmark ruvector-mincut update latency for partition-switch-time budget (<10us)

**Preconditions:** ruvector-mincut crate functional (it is)
**Effects:** Scheduling algorithm specified; latency bounds proven

### 1.4 Memory Coherence Protocols

**Goal state:** Design a memory coherence model for coherence domains that eliminates false sharing and minimizes remote traffic.

| Protocol | Why Study | Relevance |
|----------|----------|-----------|
| **MOESI** | Snooping protocol; AMD uses for multi-socket | Baseline understanding of cache coherence overhead |
| **Directory-based (DASH, SGI Origin)** | Scalable coherence for >4 sockets | Coherence domain as a directory entry abstraction |
| **ARM AMBA CHI** | Modern ARM coherence protocol for SoC | Target hardware protocol for Seed/Appliance chips |
| **CXL (Compute Express Link)** | Memory-semantic interconnect; CXL.mem for shared memory pools | Future interconnect for cross-chip coherence domains |
| **Barrelfish message-passing** | Eliminates shared memory entirely; replicate instead | Alternative: no coherence protocol, only message passing |

**Actions:**
- [ ] A1.4.1: Quantify coherence overhead: how much of current "VM exit" cost is actually coherence traffic
- [ ] A1.4.2: Design coherence domain memory model: regions are either local (no coherence) or shared (proof-gated coherence)
- [ ] A1.4.3: Prototype directory-based coherence for shared regions using ruvix-region policies
- [ ] A1.4.4: Define the "coherence score" metric that drives scheduling and migration decisions

**Preconditions:** A1.3.1 (graph model defined)
**Effects:** Memory model specified; coherence score formula defined

### 1.5 Formal Verification Approaches

**Goal state:** Identify which properties of the hypervisor can be formally verified, and with what tools.

| Approach | Tool | What It Proves |
|----------|------|---------------|
| **seL4 style** | Isabelle/HOL | Full functional correctness (gold standard, very expensive) |
| **Kani/Verus** | Rust-native model checkers | Bounded verification of Rust code; panic-freedom, overflow |
| **Prusti** | Viper + Rust | Pre/post condition verification with ownership |
| **lean-agentic (ruvector-verified)** | Lean 4 + Rust FFI | Dependent types for proof-carrying operations (we have this) |
| **TLA+/P** | Model checking | Protocol-level correctness (capability transfer, migration) |

**Actions:**
- [ ] A1.5.1: Use Kani to verify panic-freedom in ruvix-cap and ruvix-proof (no_std paths)
- [ ] A1.5.2: Use ruvector-verified to generate proof obligations for capability derivation correctness
- [ ] A1.5.3: Write TLA+ spec for coherence domain migration protocol
- [ ] A1.5.4: Define the verification budget: which crates get full verification vs. testing-only

**Preconditions:** ruvector-verified crate functional
**Effects:** Verification strategy decided; initial proofs for cap and proof crates

### 1.6 Agent Runtime Designs

**Goal state:** Design the WASM/agent partition interface that runs inside coherence domains.

| Runtime | Why Study | Relevance |
|---------|----------|-----------|
| **wasmtime** | Production WASM runtime with Cranelift JIT | Reference for WASM execution in restricted environments |
| **wasmer** | WASM with multiple backends (Cranelift, LLVM, Singlepass) | Singlepass backend for predictable compilation time |
| **lunatic** | Erlang-like actor system built on WASM | Actor model inside WASM for agent isolation |
| **wasm-micro-runtime (WAMR)** | Lightweight WASM interpreter for embedded | Minimal footprint for edge/embedded coherence domains |
| **Component Model (WASI P2)** | Typed interface composition for WASM | Interface types for agent-to-agent IPC |

**Actions:**
- [ ] A1.6.1: Benchmark WAMR vs wasmtime-minimal for partition boot time
- [ ] A1.6.2: Design the coherence domain WASM interface: capabilities exposed as WASM imports
- [ ] A1.6.3: Define agent IPC: WASM component model typed channels backed by ruvix-queue
- [ ] A1.6.4: Prototype: WASM partition that can query ruvix-vecgraph through capability-gated imports

**Preconditions:** A1.2 (capability model), ruvix-queue functional
**Effects:** Agent runtime selection made; IPC interface defined

---

## 2. Architecture Goals

### 2.1 Coherence Domains Without KVM

**Current world state:** ruvix has 6 primitives (Task, Capability, Region, Queue, Timer, Proof) but no concept of a "coherence domain" as a first-class hypervisor object.

**Goal state:** Coherence domains are the primary isolation and scheduling unit, replacing the VM abstraction.

#### Definition

A **coherence domain** is a graph-structured isolation unit consisting of:

```
CoherenceDomain {
    id: DomainId,
    graph: VecGraph,           // from ruvix-vecgraph, nodes=tasks, edges=data dependencies
    regions: Vec<RegionHandle>,  // memory owned by this domain
    capabilities: CapTree,       // capability subtree rooted at domain cap
    coherence_score: f32,        // spectral coherence metric
    mincut_partition: Partition,  // current min-cut boundary from ruvector-mincut
    witness_log: WitnessLog,     // domain-local witness chain
    tier: MemoryTier,            // Hot | Warm | Dormant | Cold
}
```

#### How It Replaces VMs

| VM Concept | Coherence Domain Equivalent |
|-----------|---------------------------|
| vCPU | Tasks within the domain's graph |
| Guest physical memory | Regions with domain-scoped capabilities |
| VM exit/enter | Partition switch (rescheduling at min-cut boundary) |
| Device passthrough | Lease-based device capability (time-bounded, revocable) |
| VM migration | Graph repartitioning via dynamic min-cut |
| Snapshot/restore | Witness log replay from checkpoint |

#### Key Architectural Decisions

**AD-1: No hardware virtualization extensions required.** RVM uses capability-based isolation (software) + MMU page table partitioning (hardware) instead of VT-x/AMD-V/EL2 trap-and-emulate. This means:
- No VM exits. No VMCS/VMCB. No nested page tables.
- Isolation comes from: (a) capability enforcement in ruvix-cap, (b) MMU page table boundaries per domain, (c) proof-gated mutation.
- A traditional VM is a degenerate coherence domain: single partition, opaque graph, no coherence scoring.

**AD-2: EL2 is used for page table management only.** On AArch64, the hypervisor runs at EL2. But EL2 is used purely to manage stage-2 page tables that enforce region boundaries -- not for trap-and-emulate virtualization.

**AD-3: Coherence score drives everything.** The coherence score (computed from the domain's graph structure via ruvector-coherence spectral methods) determines:
- Scheduling priority (high coherence = more CPU time)
- Memory tier (high coherence = hot tier; low coherence = demote to warm/dormant)
- Migration eligibility (domains with suboptimal min-cut partition are candidates)
- Reclamation order (lowest coherence reclaimed first under memory pressure)

**Actions:**
- [ ] A2.1.1: Add CoherenceDomain struct to ruvix-types
- [ ] A2.1.2: Add DomainCreate, DomainDestroy, DomainMigrate syscalls to ruvix-nucleus
- [ ] A2.1.3: Implement domain-scoped capability trees in ruvix-cap
- [ ] A2.1.4: Wire ruvector-coherence spectral scoring into ruvix-sched

### 2.2 Hardware Abstraction Layer

**Current state:** ruvix-hal defines traits for Console, Timer, InterruptController, Mmu, Power. ruvix-aarch64 has stubs.

**Goal state:** HAL supports three architectures with hypervisor-level primitives.

| Architecture | HAL Implementation | Priority | Hypervisor Feature |
|-------------|-------------------|----------|-------------------|
| **AArch64** | ruvix-aarch64 | P0 (primary) | EL2 page table management, GIC-400/GIC-600 |
| **RISC-V** | ruvix-riscv (new) | P1 | H-extension for VS/HS mode, PLIC/APLIC |
| **x86_64** | ruvix-x86 (new) | P2 | EPT page tables, APIC (lowest priority) |

**New HAL traits for hypervisor:**

```rust
pub trait HypervisorMmu {
    fn create_stage2_tables(&mut self, domain: DomainId) -> Result<PageTableRoot, HalError>;
    fn map_region_to_domain(&mut self, region: RegionHandle, domain: DomainId, perms: RegionPolicy) -> Result<(), HalError>;
    fn unmap_region(&mut self, region: RegionHandle, domain: DomainId) -> Result<(), HalError>;
    fn switch_domain(&mut self, from: DomainId, to: DomainId) -> Result<(), HalError>;
}

pub trait CoherenceHardware {
    fn read_cache_miss_counter(&self) -> u64;
    fn read_remote_memory_counter(&self) -> u64;
    fn flush_domain_tlb(&mut self, domain: DomainId) -> Result<(), HalError>;
}
```

**Actions:**
- [ ] A2.2.1: Extend ruvix-hal with HypervisorMmu and CoherenceHardware traits
- [ ] A2.2.2: Implement AArch64 EL2 page table management in ruvix-aarch64
- [ ] A2.2.3: Implement GIC-600 interrupt routing per coherence domain
- [ ] A2.2.4: Define RISC-V H-extension HAL (trait impl stubs)

### 2.3 Memory Model

**Current state:** ruvix-region provides Immutable/AppendOnly/Slab policies with mmap-backed storage. ruvix-physmem has a buddy allocator.

**Goal state:** Hybrid memory model with capability-gated regions and tiered coherence.

#### Design: Four-Tier Memory Hierarchy

```
Tier     | Backing         | Access Latency | Coherence State | Eviction Policy
---------|-----------------|----------------|-----------------|------------------
Hot      | L1/L2 resident  | <10ns          | Exclusive/Modified | Never (pinned)
Warm     | DRAM            | ~100ns         | Shared/Clean    | LRU with coherence weight
Dormant  | Compressed DRAM | ~1us           | Invalid (reconstructable) | Coherence score threshold
Cold     | NVMe/Flash      | ~10us          | Tombstone       | Witness log pointer only
```

**Key Innovation: Reconstructable Memory.**
Dormant regions are not stored as raw bytes. They are stored as:
1. A witness log checkpoint hash
2. A delta-compressed representation (using ruvector-temporal-tensor compression)
3. Reconstruction instructions that can rebuild the region from the witness log

This means memory reclamation does not destroy state -- it compresses it into the witness chain.

**Actions:**
- [ ] A2.3.1: Extend ruvix-region with MemoryTier enum and tier-transition methods
- [ ] A2.3.2: Implement dormant-region compression using witness log + delta encoding
- [ ] A2.3.3: Implement cold-tier eviction to NVMe with tombstone references
- [ ] A2.3.4: Wire physical memory allocator to tier-aware allocation (hot from buddy, warm from slab pool)
- [ ] A2.3.5: Define the page table structure for stage-2 domain isolation

### 2.4 Scheduler: Graph-Pressure-Driven

**Current state:** ruvix-sched has a coherence-aware scheduler with deadline pressure, novelty signal, and structural risk. Fixed partition model.

**Goal state:** Scheduler uses live graph state from ruvector-mincut to make scheduling decisions.

#### Scheduling Algorithm: CoherencePressure

```
EVERY scheduler_tick:
  1. For each active coherence domain D:
     a. Read D.graph edge weights (data flow rates between tasks)
     b. Compute min-cut value via ruvector-mincut (amortized O(n^{o(1)}))
     c. Compute coherence_score = spectral_gap(D.graph) / min_cut_value
     d. Compute pressure = deadline_urgency * coherence_score * novelty_boost
  2. Sort domains by pressure (descending)
  3. Assign CPU time proportional to pressure
  4. If any domain's coherence_score < threshold:
     - Trigger repartition: invoke ruvector-mincut to compute new boundary
     - If repartition improves score by >10%: execute migration
```

**Partition Switch Protocol (target: <10us):**

```
switch_partition(from: DomainId, to: DomainId):
  1. Save from.task_state to from.region (register dump, ~500ns)
  2. Switch stage-2 page table root (TTBR write, ~100ns)
  3. TLB invalidate for from domain (TLBI, ~2us on ARM)
  4. Load to.task_state from to.region (~500ns)
  5. Emit witness record for switch (~200ns with reflex proof)
  6. Resume execution in to domain
  Total budget: ~3.3us (well within 10us target)
```

**Actions:**
- [ ] A2.4.1: Refactor ruvix-sched to accept graph state from ruvix-vecgraph
- [ ] A2.4.2: Integrate ruvector-mincut as a scheduling oracle (no_std subset)
- [ ] A2.4.3: Implement partition switch protocol in ruvix-aarch64
- [ ] A2.4.4: Benchmark partition switch time on QEMU virt

### 2.5 IPC: Zero-Copy Message Passing

**Current state:** ruvix-queue provides io_uring-style ring buffers with zero-copy semantics. 47 tests passing.

**Goal state:** Cross-domain IPC through shared regions with capability-gated access.

#### Design

```
Inter-domain IPC:
  1. Sender domain S holds Capability(Queue Q, WRITE)
  2. Receiver domain R holds Capability(Queue Q, READ)
  3. Queue Q is backed by a shared Region visible in both S and R stage-2 page tables
  4. Messages are written as typed records with coherence metadata
  5. Every send/recv emits a witness record linking the two domains

Intra-domain IPC:
  Same as current ruvix-queue, but within a single stage-2 address space.
  No page table switch required. Pure ring buffer.
```

**Message Format:**

```rust
struct DomainMessage {
    header: MsgHeader,        // 16 bytes: sender, receiver, type, len
    coherence: CoherenceMeta, // 8 bytes: coherence score at send time
    witness: WitnessHash,     // 32 bytes: hash linking to witness chain
    payload: [u8],            // variable: zero-copy reference into shared region
}
```

**Actions:**
- [ ] A2.5.1: Extend ruvix-queue with cross-domain shared region support
- [ ] A2.5.2: Implement capability-gated queue access for inter-domain messages
- [ ] A2.5.3: Add CoherenceMeta and WitnessHash to message headers
- [ ] A2.5.4: Benchmark zero-copy IPC latency (target: <100ns intra-domain, <1us inter-domain)

### 2.6 Device Model: Lease-Based Access

**Goal state:** Devices are not "assigned" to domains. They are leased with capability-bounded time windows.

```rust
struct DeviceLease {
    device_id: DeviceId,
    domain: DomainId,
    capability: CapHandle,     // Revocable capability for device access
    lease_start: Timestamp,
    lease_duration: Duration,
    max_dma_budget: usize,     // Maximum DMA bytes allowed during lease
    witness: WitnessHash,      // Proof of lease grant
}
```

**Key properties:**
- Lease expiry automatically revokes capability (no explicit release needed)
- DMA budget prevents device from exhausting memory during lease
- Multiple domains can hold read-only leases to the same device simultaneously
- Exclusive write lease requires proof of non-interference (via min-cut: device node has no shared edges)

**Actions:**
- [ ] A2.6.1: Design DeviceLease struct and lease lifecycle
- [ ] A2.6.2: Implement lease-based MMIO region mapping in ruvix-drivers
- [ ] A2.6.3: Implement DMA budget enforcement in ruvix-dma
- [ ] A2.6.4: Wire lease expiry to capability revocation in ruvix-cap

### 2.7 Witness Subsystem: Compact Append-Only Log

**Current state:** ruvix-boot has WitnessLog with SHA-256 chaining. ruvix-proof has 3-tier proof engine.

**Goal state:** Hypervisor-wide witness log that enables deterministic replay, audit, and fault recovery.

#### Design

```
WitnessLog (per coherence domain):
  - Append-only ring buffer in a dedicated Region(AppendOnly)
  - Each entry: [timestamp: u64, action_type: u8, proof_hash: [u8; 32], prev_hash: [u8; 32], payload: [u8; N]]
  - Fixed 82-byte entries (ATTESTATION_SIZE from ruvix-types)
  - Hash chain: entry[i].prev_hash = SHA256(entry[i-1])
  - Compaction: when ring buffer wraps, emit a Merkle root of the evicted segment to cold storage

GlobalWitness (hypervisor-level):
  - Merges per-domain witness chains at partition switch boundaries
  - Enables cross-domain causality reconstruction
  - Uses ruvector-dag for causal ordering
```

**Actions:**
- [ ] A2.7.1: Implement per-domain witness log in ruvix-proof
- [ ] A2.7.2: Implement global witness merge at partition switch
- [ ] A2.7.3: Implement Merkle compaction for ring buffer overflow
- [ ] A2.7.4: Implement deterministic replay from witness log + checkpoint

---

## 3. Implementation Milestones

### M0: Bare-Metal Rust Boot on QEMU (No KVM, Direct Machine Code)

**Goal:** Boot RVM at EL2 on QEMU aarch64 virt, print to UART, emit first witness record.

**Preconditions:**
- ruvix-hal traits defined (done)
- ruvix-aarch64 boot stubs (partially done)
- aarch64-boot directory with linker script and build system (exists)

**Actions:**
- [ ] M0.1: Complete _start assembly: disable MMU, set up stack, branch to Rust
- [ ] M0.2: Initialize PL011 UART via ruvix-drivers
- [ ] M0.3: Initialize GIC-400 minimal (mask all interrupts except timer)
- [ ] M0.4: Set up EL2 translation tables (identity mapping for kernel, device MMIO)
- [ ] M0.5: Initialize witness log in a fixed RAM region
- [ ] M0.6: Emit first witness record (boot attestation)
- [ ] M0.7: Measure cold boot to first witness time (target: <250ms)

**Acceptance criteria:**
- `qemu-system-aarch64 -machine virt -cpu cortex-a72 -kernel ruvix.bin` boots
- UART prints "RVM Hypervisor Core v0.1.0"
- First witness hash printed within 250ms of power-on

**Estimated effort:** 2-3 weeks
**Dependencies:** None (all prerequisites exist)

### M1: Partition Object Model + Capability System

**Goal:** Coherence domains as first-class kernel objects with capability-gated access.

**Preconditions:** M0 complete

**Actions:**
- [ ] M1.1: Add CoherenceDomain to ruvix-types
- [ ] M1.2: Add DomainCreate/DomainDestroy/DomainQuery syscalls to ruvix-nucleus
- [ ] M1.3: Implement domain-scoped capability trees in ruvix-cap
- [ ] M1.4: Implement stage-2 page table creation per domain in ruvix-aarch64
- [ ] M1.5: Implement domain switch (save/restore + TTBR switch + TLB invalidate)
- [ ] M1.6: Test: create two domains, switch between them, verify isolation

**Acceptance criteria:**
- Two domains running concurrently with isolated memory
- Capability violation (cross-domain access without cap) triggers fault
- Domain switch measured at <10us

**Estimated effort:** 3-4 weeks
**Dependencies:** M0

### M2: Witness Logging + Proof Verifier

**Goal:** Every privileged action emits a witness record; proofs are verified before mutation.

**Preconditions:** M1 complete

**Actions:**
- [ ] M2.1: Implement per-domain witness log (AppendOnly region)
- [ ] M2.2: Wire all syscalls through proof verifier (ruvix-proof integration)
- [ ] M2.3: Implement 3-tier proof routing: Reflex for hot path, Standard for normal, Deep for privileged
- [ ] M2.4: Implement global witness merge at domain switch
- [ ] M2.5: Test: replay witness log from checkpoint, verify state reconstruction

**Acceptance criteria:**
- No syscall succeeds without valid proof
- Witness log captures all state changes
- Replay from checkpoint + witness log produces identical state

**Estimated effort:** 2-3 weeks
**Dependencies:** M1

### M3: Basic Scheduler with Coherence Scoring

**Goal:** Scheduler uses coherence scores from graph structure to drive scheduling decisions.

**Preconditions:** M1, M2 complete; ruvector-coherence available

**Actions:**
- [ ] M3.1: Integrate ruvector-coherence spectral scoring into ruvix-sched
- [ ] M3.2: Implement per-domain graph state tracking in ruvix-vecgraph
- [ ] M3.3: Implement coherence-pressure scheduling algorithm
- [ ] M3.4: Implement partition priority based on coherence score + deadline pressure
- [ ] M3.5: Benchmark: measure scheduling overhead per tick

**Acceptance criteria:**
- Domains with higher coherence scores get proportionally more CPU time
- Scheduling tick overhead < 1us
- Coherence-driven scheduling demonstrably reduces tail latency

**Estimated effort:** 2-3 weeks
**Dependencies:** M1, M2

### M4: Dynamic MinCut Integration from RuVector Crates

**Goal:** The hypervisor uses ruvector-mincut for live partition placement, migration, and reclamation.

**Preconditions:** M3 complete; ruvector-mincut and ruvector-sparsifier crates available

**Actions:**
- [ ] M4.1: Create no_std-compatible subset of ruvector-mincut for kernel use
- [ ] M4.2: Integrate min-cut computation into scheduler tick (amortized)
- [ ] M4.3: Implement partition migration protocol: compute new cut -> transfer regions -> switch
- [ ] M4.4: Implement memory reclamation: lowest-coherence partitions reclaimed first
- [ ] M4.5: Integrate ruvector-sparsifier for efficient graph state maintenance in kernel
- [ ] M4.6: Benchmark: min-cut update latency in kernel context

**Acceptance criteria:**
- Dynamic repartitioning of domains based on workload changes
- Min-cut computation completes within scheduler tick budget
- Memory reclamation recovers regions without data loss (witness-backed)
- 20% reduction in remote memory traffic vs. static partitioning

**Estimated effort:** 4-5 weeks
**Dependencies:** M3, ruvector-mincut, ruvector-sparsifier

### M5: Memory Tier Management (Hot/Warm/Dormant/Cold)

**Goal:** Four-tier memory hierarchy with coherence-driven promotion/demotion.

**Preconditions:** M4 complete

**Actions:**
- [ ] M5.1: Implement MemoryTier enum and tier metadata in ruvix-region
- [ ] M5.2: Implement hot -> warm demotion (unpin, allow eviction)
- [ ] M5.3: Implement warm -> dormant compression (delta encoding via witness log)
- [ ] M5.4: Implement dormant -> cold eviction (to NVMe/flash with tombstone)
- [ ] M5.5: Implement cold -> hot reconstruction (replay witness log from checkpoint)
- [ ] M5.6: Wire tier transitions to coherence score thresholds

**Acceptance criteria:**
- Memory tiers transition automatically based on coherence scoring
- Dormant regions reconstruct correctly from witness log
- Cold eviction and hot reconstruction maintain data integrity
- Memory footprint reduced by 50%+ for dormant workloads

**Estimated effort:** 3-4 weeks
**Dependencies:** M4

### M6: Agent Runtime Adapter (WASM Partitions)

**Goal:** WASM-based agent partitions run inside coherence domains with capability-gated access.

**Preconditions:** M5 complete; WASM runtime selection made (from A1.6)

**Actions:**
- [ ] M6.1: Integrate minimal WASM runtime (WAMR or wasmtime-minimal) into kernel
- [ ] M6.2: Implement WASM import interface: capabilities as host functions
- [ ] M6.3: Implement WASM partition boot: load .wasm from RVF package, instantiate in domain
- [ ] M6.4: Implement agent IPC: WASM component model typed channels -> ruvix-queue
- [ ] M6.5: Implement agent lifecycle: spawn, pause, resume, terminate (all proof-gated)
- [ ] M6.6: Test: multi-agent scenario with 10+ WASM partitions in different domains

**Acceptance criteria:**
- WASM partitions boot and execute within coherence domains
- Agent-to-agent IPC through typed channels with <1us latency
- Capability violations in WASM trapped and logged to witness
- 10 concurrent WASM agents run without interference

**Estimated effort:** 4-5 weeks
**Dependencies:** M5, A1.6

### M7: Seed/Appliance Hardware Bring-Up

**Goal:** Boot RVM on Cognitum Seed and Appliance hardware.

**Preconditions:** M6 complete; hardware available

**Actions:**
- [ ] M7.1: Implement device tree parsing for Seed/Appliance SoC in ruvix-dtb
- [ ] M7.2: Implement BCM2711 (or target SoC) interrupt controller driver
- [ ] M7.3: Implement board-specific boot sequence in ruvix-rpi-boot or equivalent
- [ ] M7.4: Implement NVMe driver for cold-tier storage
- [ ] M7.5: Implement network driver for cross-node coherence domain migration
- [ ] M7.6: Full integration test: boot, create domains, run WASM agents, migrate, recover

**Acceptance criteria:**
- RVM boots on physical hardware
- All M0-M6 acceptance criteria met on real hardware
- Fault recovery without global reboot demonstrated
- Cross-node migration demonstrated (if multi-node hardware available)

**Estimated effort:** 6-8 weeks
**Dependencies:** M6, hardware availability

---

## 4. RuVector Integration Plan

### 4.1 MinCut Drives Partition Placement

**Crate:** `ruvector-mincut` (subpolynomial dynamic min-cut)

**Integration points:**

| Hypervisor Function | MinCut Operation | Data Flow |
|--------------------|-----------------|-----------|
| Domain creation | Initial partition computation | Domain graph -> MinCutBuilder -> Partition |
| Scheduler tick | Amortized cut value query | MinCut.min_cut_value() -> coherence score input |
| Migration decision | Repartition computation | Updated graph -> MinCut.insert/delete_edge -> New partition |
| Memory reclamation | Cut-based ordering | MinCut values across domains -> reclamation priority |
| Fault isolation | Cut identifies blast radius | MinCut.min_cut_set() -> affected regions |

**no_std adaptation required:**
- ruvector-mincut currently depends on petgraph, rayon, dashmap, parking_lot (all require std/alloc)
- Create `ruvector-mincut-kernel` feature flag that uses:
  - Fixed-size graph representation (no heap allocation)
  - Single-threaded computation (no rayon)
  - Spin locks instead of parking_lot
  - Inline graph storage instead of petgraph

**Actions:**
- [ ] I4.1.1: Add `no_std` feature to ruvector-mincut with kernel-compatible subset
- [ ] I4.1.2: Implement fixed-size graph backend (max 256 nodes, 4096 edges)
- [ ] I4.1.3: Benchmark kernel-mode min-cut: target <5us for 64-node graphs
- [ ] I4.1.4: Wire into ruvix-sched as scheduling oracle

### 4.2 Sparsifier Enables Efficient Graph State

**Crate:** `ruvector-sparsifier` (dynamic spectral graph sparsification)

**Integration points:**

| Hypervisor Function | Sparsifier Operation | Purpose |
|--------------------|---------------------|---------|
| Graph maintenance | Sparsify domain graph | Keep O(n log n) edges instead of O(n^2) for coherence queries |
| Coherence scoring | Spectral gap from sparsified Laplacian | Fast coherence score without full eigendecomposition |
| Migration planning | Sparsified graph for min-cut | Approximate min-cut on sparsified graph (faster) |
| Memory accounting | Sparse representation of access patterns | Track which regions are accessed by which tasks |

**Key insight:** The sparsifier maintains a spectrally-equivalent graph with O(n log n / epsilon^2) edges. This means coherence scoring and min-cut computation can run on the sparse representation instead of the full graph, reducing kernel-mode computation time.

**Actions:**
- [ ] I4.2.1: Add `no_std` feature to ruvector-sparsifier
- [ ] I4.2.2: Implement incremental sparsification (update sparse graph on edge insert/delete)
- [ ] I4.2.3: Wire sparsified graph into scheduler for fast coherence queries
- [ ] I4.2.4: Benchmark: sparsified vs. full graph coherence scoring latency

### 4.3 Solver Handles Coherence Scoring

**Crate:** `ruvector-solver` (sublinear-time sparse solvers)

**Integration points:**

| Hypervisor Function | Solver Operation | Purpose |
|--------------------|-----------------|---------|
| Coherence score | Approximate Fiedler vector | Spectral gap computation |
| PageRank-style scoring | Forward push on domain graph | Task importance ranking |
| Migration cost estimation | Sparse linear system solve | Estimate data transfer cost |

**Key insight:** The solver's Neumann series and conjugate gradient methods can compute approximate spectral properties of the domain graph in O(sqrt(n)) time. This is fast enough for per-tick coherence scoring.

**Actions:**
- [ ] I4.3.1: Add `no_std` subset of ruvector-solver (Neumann series only, no nalgebra)
- [ ] I4.3.2: Implement approximate Fiedler vector computation for coherence scoring
- [ ] I4.3.3: Implement forward-push task importance ranking
- [ ] I4.3.4: Benchmark: solver latency for 64-node domain graphs

### 4.4 Embeddings Enable Semantic State Reconstruction

**Crate:** `ruvector-core` (HNSW indexing), `ruvix-vecgraph` (kernel vector/graph stores)

**Integration points:**

| Hypervisor Function | Embedding Operation | Purpose |
|--------------------|-------------------|---------|
| Dormant state reconstruction | Semantic similarity search | Find related state fragments for reconstruction |
| Novelty detection | Vector distance from recent inputs | Scheduler novelty signal |
| Fault diagnosis | Embedding-based anomaly detection | Detect divergent domain states |
| Cold tier indexing | HNSW index over tombstone references | Fast lookup of cold-tier state |

**Key insight:** When a dormant region needs reconstruction, the witness log provides the exact mutation sequence. But semantic embeddings can identify which other regions contain related state, enabling speculative prefetch during reconstruction.

**Actions:**
- [ ] I4.4.1: Implement kernel-resident micro-HNSW in ruvix-vecgraph (fixed-size, no_std)
- [ ] I4.4.2: Wire novelty detection into scheduler (vector distance from recent inputs)
- [ ] I4.4.3: Implement embedding-based prefetch for dormant region reconstruction
- [ ] I4.4.4: Implement anomaly detection for cross-domain state divergence

### 4.5 Additional RuVector Crate Integration

| Crate | Integration Point | Priority |
|-------|------------------|----------|
| `ruvector-raft` | Cross-node consensus for multi-node coherence domains | P2 (M7) |
| `ruvector-verified` | Formal proofs for capability derivation correctness | P1 (M2) |
| `ruvector-dag` | Causal ordering in global witness log | P1 (M2) |
| `ruvector-temporal-tensor` | Delta compression for dormant regions | P1 (M5) |
| `ruvector-coherence` | Spectral coherence scoring | P0 (M3) |
| `cognitum-gate-kernel` | 256-tile fabric as coherence domain topology | P2 (M7) |
| `ruvector-snapshot` | Checkpoint/restore for domain state | P1 (M5) |

---

## 5. Success Metrics

### 5.1 Performance Targets

| Metric | Target | Measurement Method | Milestone |
|--------|--------|--------------------|-----------|
| Cold boot to first witness | <250ms | QEMU timer from power-on to first witness UART print | M0 |
| Hot partition switch | <10us | ARM cycle counter around switch_partition() | M1 |
| Remote memory traffic reduction | 20% vs. static | Hardware perf counters (cache miss/remote access) | M4 |
| Tail latency reduction | 20% vs. round-robin | P99 latency of agent request/response | M4 |
| Full witness trail | 100% coverage | Audit: every syscall has witness record | M2 |
| Fault recovery without global reboot | Domain-local recovery | Kill one domain, verify others unaffected | M5 |
| WASM agent boot time | <5ms per agent | Timer around WASM instantiation | M6 |
| Zero-copy IPC latency | <100ns intra, <1us inter | Benchmark ring buffer round-trip | M1 |
| Coherence scoring overhead | <1us per domain per tick | Cycle counter around scoring function | M3 |
| Min-cut update amortized | <5us for 64-node graph | Benchmark in kernel context | M4 |

### 5.2 Correctness Targets

| Property | Verification Method | Milestone |
|----------|-------------------|-----------|
| Capability safety (no unauthorized access) | ruvector-verified + Kani | M1 |
| Witness chain integrity (no gaps, no forgery) | SHA-256 chain verification | M2 |
| Deterministic replay (same inputs -> same state) | Replay 10K syscall traces | M2 |
| Proof soundness (invalid proofs always rejected) | Fuzzing + proptest | M2 |
| Isolation (domain fault does not affect others) | Inject faults, verify containment | M5 |
| Memory safety (no UB in kernel code) | Miri + Kani + `#![forbid(unsafe_code)]` where possible | All |

### 5.3 Scale Targets

| Dimension | Target | Milestone |
|-----------|--------|-----------|
| Concurrent coherence domains | 256 | M4 |
| Tasks per domain | 64 | M3 |
| Regions per domain | 1024 | M1 |
| Graph nodes per domain | 256 | M4 |
| Graph edges per domain | 4096 | M4 |
| WASM agents total | 1024 | M6 |
| Witness log entries before compaction | 1M | M2 |
| Cross-node domains (federated) | 16 nodes | M7 |

---

## 6. Dependency Graph (GOAP Action Ordering)

```
Research Phase (parallel):
  A1.1 (bare-metal Rust) ---|
  A1.2 (capability OS)    --+--> Architecture Phase
  A1.3 (graph scheduling) --|
  A1.4 (memory coherence) --|
  A1.5 (formal verification)|
  A1.6 (agent runtimes)   --|

Architecture Phase (partially parallel):
  A2.1 (coherence domains) --> A2.4 (scheduler)
  A2.2 (HAL)               --> M0 (bare-metal boot)
  A2.3 (memory model)      --> A2.4 (scheduler)
  A2.4 (scheduler)         --> M3
  A2.5 (IPC)               --> M1
  A2.6 (device model)      --> M7
  A2.7 (witness)           --> M2

Implementation (sequential with overlap):
  M0 (boot)
   |
  M1 (partitions + caps)
   |
  M2 (witness + proofs) -- can overlap with M3
   |
  M3 (coherence scheduler)
   |
  M4 (mincut integration) -- critical path
   |
  M5 (memory tiers)
   |
  M6 (WASM agents)
   |
  M7 (hardware bring-up)

RuVector Integration (parallel with milestones):
  I4.1 (mincut no_std)      --> M4
  I4.2 (sparsifier no_std)  --> M4
  I4.3 (solver no_std)      --> M3
  I4.4 (embeddings kernel)  --> M5
```

### Critical Path

```
A2.2 (HAL) -> M0 -> M1 -> M3 -> M4 -> M5 -> M6 -> M7
                           ^
                           |
                     I4.1 (mincut no_std) -- this is the highest-risk integration
```

**Highest risk item:** Creating a no_std subset of ruvector-mincut that runs in kernel context within the scheduler tick budget. If the amortized min-cut update exceeds 5us for 64-node graphs, the scheduler design must fall back to periodic (not per-tick) repartitioning.

---

## 7. GOAP State Transitions

### World State Variables

```rust
struct WorldState {
    // Research
    bare_metal_research_complete: bool,
    capability_model_decided: bool,
    scheduling_algorithm_specified: bool,
    memory_model_designed: bool,
    verification_strategy_decided: bool,
    agent_runtime_selected: bool,

    // Infrastructure
    boots_on_qemu: bool,
    uart_works: bool,
    mmu_configured: bool,
    interrupts_working: bool,

    // Core features
    coherence_domains_exist: bool,
    capabilities_enforce_isolation: bool,
    witness_log_records_all: bool,
    proofs_gate_all_mutations: bool,
    scheduler_uses_coherence: bool,
    mincut_drives_partitioning: bool,
    memory_tiers_work: bool,
    wasm_agents_run: bool,

    // Performance
    boot_under_250ms: bool,
    switch_under_10us: bool,
    traffic_reduced_20pct: bool,
    tail_latency_reduced_20pct: bool,

    // Hardware
    runs_on_seed_hardware: bool,
    runs_on_appliance_hardware: bool,
}
```

### Initial State

```rust
WorldState {
    bare_metal_research_complete: false,
    capability_model_decided: true,  // seL4-inspired, already in ruvix-cap
    scheduling_algorithm_specified: false,
    memory_model_designed: false,
    verification_strategy_decided: false,
    agent_runtime_selected: false,

    boots_on_qemu: false,
    uart_works: false,
    mmu_configured: false,
    interrupts_working: false,

    coherence_domains_exist: false,
    capabilities_enforce_isolation: true,  // ruvix-cap works in hosted mode
    witness_log_records_all: false,
    proofs_gate_all_mutations: true,  // ruvix-proof works in hosted mode
    scheduler_uses_coherence: false,
    mincut_drives_partitioning: false,
    memory_tiers_work: false,
    wasm_agents_run: false,

    boot_under_250ms: false,
    switch_under_10us: false,
    traffic_reduced_20pct: false,
    tail_latency_reduced_20pct: false,

    runs_on_seed_hardware: false,
    runs_on_appliance_hardware: false,
}
```

### Goal State

All fields set to `true`.

### A* Search Heuristic

The heuristic for GOAP planning uses the number of `false` fields as the distance estimate. Each action sets one or more fields to `true`. The planner finds the minimum-cost path from initial to goal state.

**Cost model:**
- Research action: 1 week (cost = 1)
- Architecture action: 1-2 weeks (cost = 1.5)
- Implementation milestone: 2-5 weeks (cost = 3)
- Integration action: 1-3 weeks (cost = 2)
- Hardware bring-up: 6-8 weeks (cost = 7)

**Optimal plan total estimated duration: 28-36 weeks** (with parallelism in research and integration phases, critical path through M0->M1->M3->M4->M5->M6->M7).

---

## 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| MinCut no_std too slow for per-tick scheduling | Medium | High | Fall back to periodic repartitioning (every 100 ticks); use sparsified graph |
| EL2 page table management bugs | High | Medium | Extensive QEMU testing; Miri for unsafe blocks; compare with known-good implementations |
| WASM runtime too large for kernel integration | Medium | Medium | Use WAMR interpreter (smallest footprint); or run WASM in EL1 with EL2 capability enforcement |
| Witness log overhead degrades hot path | Low | High | Reflex proof tier (<100ns) is already within budget; batch witness records if needed |
| Hardware coherence counters unavailable | Medium | Low | Fall back to software instrumentation (memory access tracking via page faults) |
| Formal verification scope creep | High | Low | Strict verification budget: only ruvix-cap and ruvix-proof get full verification |
| Cross-node migration protocol correctness | High | High | TLA+ model before implementation; extensive simulation in qemu-swarm |

---

## 9. Existing Codebase Inventory

### What We Have (and reuse directly)

| Crate | LoC (est.) | Reuse Level | Notes |
|-------|-----------|-------------|-------|
| ruvix-types | ~2,000 | Direct | Add CoherenceDomain, MemoryTier types |
| ruvix-cap | ~1,500 | Direct | Add domain-scoped trees |
| ruvix-proof | ~1,800 | Direct | Add per-domain witness log |
| ruvix-sched | ~1,200 | Refactor | Wire to coherence scoring |
| ruvix-region | ~1,500 | Extend | Add tier management |
| ruvix-queue | ~1,000 | Extend | Add cross-domain shared regions |
| ruvix-boot | ~2,000 | Refactor | EL2 boot sequence |
| ruvix-vecgraph | ~1,200 | Extend | Add kernel HNSW |
| ruvix-nucleus | ~3,000 | Refactor | Add domain syscalls |
| ruvix-hal | ~800 | Extend | Add HypervisorMmu traits |
| ruvix-aarch64 | ~800 | Major work | EL2 implementation |
| ruvix-drivers | ~500 | Extend | Lease-based device model |
| ruvix-physmem | ~800 | Direct | Tier-aware allocation |
| ruvix-smp | ~500 | Direct | Multi-core domain placement |
| ruvix-dma | ~400 | Extend | Budget enforcement |
| ruvix-dtb | ~400 | Direct | Device tree parsing |
| ruvix-shell | ~600 | Direct | Debug interface |
| qemu-swarm | ~3,000 | Direct | Testing infrastructure |

### What We Have (reuse via no_std adaptation)

| Crate | Adaptation Needed |
|-------|------------------|
| ruvector-mincut | no_std feature, fixed-size graph backend |
| ruvector-sparsifier | no_std feature, remove rayon |
| ruvector-solver | no_std Neumann series only |
| ruvector-coherence | Already minimal, add spectral feature |
| ruvector-verified | Lean-agentic proofs for cap verification |
| ruvector-dag | no_std causal ordering |

### What We Need to Build

| Component | Estimated LoC | Milestone |
|-----------|-------------|-----------|
| CoherenceDomain lifecycle | ~2,000 | M1 |
| EL2 page table management | ~3,000 | M0/M1 |
| Partition switch protocol | ~500 | M1 |
| Per-domain witness log | ~1,000 | M2 |
| Global witness merge | ~800 | M2 |
| Graph-pressure scheduler | ~1,500 | M3 |
| MinCut kernel integration | ~2,000 | M4 |
| Memory tier manager | ~2,000 | M5 |
| WASM runtime adapter | ~3,000 | M6 |
| Device lease manager | ~1,000 | M6 |
| Hardware drivers (Seed/Appliance) | ~5,000 | M7 |
| **Total new code** | **~21,800** | |

Combined with ~20K lines of existing ruvix code being reused/extended, the total codebase at M7 completion is estimated at ~42K lines of Rust.

---

## 10. Next Steps (Immediate Actions)

### Week 1-2: Research Sprint

1. **Read** Theseus OS and RedLeaf papers (A1.1.1, A1.1.2)
2. **Audit** ruvix-cap against seL4 CNode spec (A1.2.1)
3. **Formalize** coherence-pressure scheduling problem (A1.3.1)
4. **Benchmark** ruvector-mincut update latency for kernel budget (A1.3.4)
5. **Select** WASM runtime (WAMR vs wasmtime-minimal) (A1.6.1)

### Week 3-4: M0 Sprint

1. **Complete** _start assembly for AArch64 EL2 boot (M0.1)
2. **Initialize** PL011 UART (M0.2)
3. **Configure** EL2 translation tables (M0.4)
4. **Emit** first witness record (M0.6)
5. **Measure** boot time (M0.7)

### Week 5-8: M1 + M2 Sprint

1. **Implement** CoherenceDomain in ruvix-types (M1.1)
2. **Add** domain syscalls (M1.2)
3. **Implement** stage-2 page tables (M1.4)
4. **Wire** witness logging to all syscalls (M2.2)

### Week 9-12: M3 + M4 Sprint (Critical Path)

1. **Integrate** ruvector-coherence into scheduler (M3.1)
2. **Create** ruvector-mincut no_std kernel subset (I4.1.1)
3. **Wire** min-cut into scheduler (I4.1.4 / M4.2)
4. **Implement** migration protocol (M4.3)

### Week 13-20: M5 + M6

1. **Implement** memory tier management (M5)
2. **Integrate** WASM runtime (M6)

### Week 21-28: M7

1. **Hardware bring-up** on target platform (M7)

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **Coherence domain** | The primary isolation unit in RVM; a graph-structured partition of tasks, regions, and capabilities managed by dynamic min-cut |
| **Coherence score** | A scalar metric derived from the spectral gap of a domain's task-data dependency graph; higher = more internally coherent, less external dependency |
| **Partition switch** | The act of saving one domain's state and loading another's; analogous to VM exit/enter but without hardware virtualization extensions |
| **Proof-gated mutation** | The invariant that no kernel state change occurs without a valid cryptographic proof token |
| **Witness log** | An append-only, hash-chained log recording every privileged action; enables deterministic replay and audit |
| **Reconstructable memory** | Dormant/cold memory that is not stored as raw bytes but as witness log references + delta compression, enabling reconstruction on demand |
| **Device lease** | A time-bounded, capability-gated grant of device access to a coherence domain; auto-revokes on expiry |
| **Min-cut boundary** | The set of edges in a domain's graph that, when removed, partitions the graph into the minimum-cost cut; used for migration and isolation decisions |

## Appendix B: Reference Papers

1. Bhandari et al. "Theseus: an Experiment in Operating System Structure and State Management." OSDI 2020.
2. Narayanan et al. "RedLeaf: Isolation and Communication in a Safe Operating System." OSDI 2020.
3. Klein et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009.
4. Watson et al. "CHERI: A Hybrid Capability-System Architecture for Scalable Software Compartmentalization." IEEE S&P 2015.
5. Baumann et al. "The Multikernel: A new OS architecture for scalable multicore systems." SOSP 2009.
6. Karger et al. "Minimum Cuts in Near-Linear Time." JACM 2000.
7. Shi & Malik. "Normalized Cuts and Image Segmentation." IEEE PAMI 2000.
8. Spielman & Teng. "Spectral Sparsification of Graphs." SIAM J. Computing 2011.
9. Levy et al. "Ownership is Theft: Experiences Building an Embedded OS in Rust." PLOS 2015 (Tock).
10. Klimovic et al. "Pocket: Elastic Ephemeral Storage for Serverless Analytics." OSDI 2018.
