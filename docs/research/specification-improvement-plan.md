# RVM Specification Improvement Plan

**Date**: 2026-04-04
**Scope**: Complete specification gap analysis and GOAP action plan
**Inputs**: 6 RVM ADRs (132, 134, 135, 142, 143, 144), ruvector submodule ADRs (001-141), 14 crates, 945 tests

---

## 1. Current State Assessment

### 1.1 What Exists

**RVM Main Repository (6 ADRs)**

| ADR | Title | Status | Scope |
|-----|-------|--------|-------|
| ADR-132 | RVM Hypervisor Core | Proposed | Master architecture, 15 design constraints, 4-phase roadmap |
| ADR-134 | Witness Schema and Log Format | Proposed | 64-byte record, hash chaining, ring buffer, replay, audit |
| ADR-135 | Proof Verifier Design | Proposed | 3-layer proof system, capability model, nonce tracker |
| ADR-142 | TEE-Backed Cryptographic Verification | Accepted | SHA-256 upgrade, WitnessSigner, TEE pipeline, constant-time |
| ADR-143 | Nightly Verified Release Pipeline | Accepted | CI/CD, benchmark regression, Claude Code version tracking |
| ADR-144 | GPU Compute Support | Accepted | rvm-gpu crate, 3-layer architecture, capability-gated GPU |

**RuVector Submodule (follow-on ADRs referenced but not copied into RVM)**

| ADR | Title | Status | Location |
|-----|-------|--------|----------|
| ADR-133 | Partition Object Model | Proposed | ruvector/docs/adr/ only |
| ADR-136 | Memory Hierarchy and Reconstruction | Proposed | ruvector/docs/adr/ only |
| ADR-137 | Bare-Metal Boot Sequence | Proposed | ruvector/docs/adr/ only |
| ADR-138 | Seed Hardware Bring-Up | Proposed | ruvector/docs/adr/ only |
| ADR-139 | Appliance Deployment Model | Proposed | ruvector/docs/adr/ only |
| ADR-140 | Agent Runtime Adapter | Proposed | ruvector/docs/adr/ only |
| ADR-141 | Coherence Engine Kernel Integration | Accepted | ruvector/docs/adr/ only |

**Implementation Crates (14)**

| Crate | ADR Coverage | Spec Gap |
|-------|-------------|----------|
| rvm-types | ADR-132, 133, 134 | Well-covered |
| rvm-boot | ADR-137 | ADR-137 not in RVM docs/ |
| rvm-cap | ADR-135 | Well-covered |
| rvm-coherence | ADR-141 | ADR-141 not in RVM docs/ |
| rvm-gpu | ADR-144 | New, well-specified |
| rvm-hal | ADR-137 | No dedicated HAL ADR |
| rvm-kernel | ADR-132 | Integration layer, needs integration spec |
| rvm-memory | ADR-136 | ADR-136 not in RVM docs/ |
| rvm-partition | ADR-133 | ADR-133 not in RVM docs/ |
| rvm-proof | ADR-135, 142 | Well-covered |
| rvm-sched | ADR-132 DC-4 | No dedicated scheduler ADR |
| rvm-security | ADR-142 | SecurityGate documented |
| rvm-wasm | ADR-140 | ADR-140 not in RVM docs/ |
| rvm-witness | ADR-134, 142 | Well-covered |

### 1.2 What Does Not Exist

**Missing from RVM docs/adr/**:
- ADR-133 through ADR-141 (except 134, 135) live only in the ruvector submodule
- No dedicated HAL specification
- No IPC protocol specification
- No SMP/multi-core specification
- No error model specification
- No formal security model document
- No performance budget specification
- No RVF integration specification for RVM
- No multi-node / cluster specification
- No upgrade/migration specification

---

## 2. Specification Gaps (Prioritized)

### Gap Category A: Critical -- ADRs exist in submodule but not in RVM

These specifications are written and referenced by implementation code, but a reader of the RVM repository alone cannot find them. This is a documentation hygiene problem that creates confusion for contributors.

| Priority | Gap | Impact |
|----------|-----|--------|
| A1 | ADR-133 (Partition Object Model) not in RVM docs/ | Partition is the core abstraction; its spec must be findable |
| A2 | ADR-136 (Memory Hierarchy) not in RVM docs/ | rvm-memory references ADR-136; readers cannot find it |
| A3 | ADR-137 (Boot Sequence) not in RVM docs/ | rvm-boot and rvm-hal reference it |
| A4 | ADR-140 (Agent Runtime) not in RVM docs/ | rvm-wasm references ADR-140 |
| A5 | ADR-141 (Coherence Engine Integration) not in RVM docs/ | rvm-coherence references it |
| A6 | ADR-138 (Seed Hardware Bring-Up) not in RVM docs/ | Hardware target spec |
| A7 | ADR-139 (Appliance Deployment Model) not in RVM docs/ | Primary deployment target |

### Gap Category B: Missing Specifications -- No ADR exists

These are areas where implementation exists but no specification captures the design rationale, constraints, or invariants.

| Priority | Gap | Affected Crates | Impact |
|----------|-----|----------------|--------|
| B1 | IPC Protocol | rvm-partition (ipc module) | IPC semantics (zero-copy, notification, queue) are implemented but not formally specified |
| B2 | SMP and Per-CPU Scheduling | rvm-sched (smp, per_cpu modules) | Multi-core scheduling exists but no ADR defines core affinity, IPI protocol, or load balancing |
| B3 | Hardware Abstraction Layer | rvm-hal | HAL trait boundaries, platform detection, and fallback semantics are unspecified |
| B4 | Error Model and Recovery Semantics | rvm-types (error module), rvm-kernel | F1-F4 failure classes are described in ADR-132 DC-14 but not formally specified with state machines |
| B5 | RVF Integration for RVM | rvm-boot, rvm-wasm | How RVM uses RVF packages for boot images, agent modules, and checkpoints is undocumented |
| B6 | Device Lease Protocol | rvm-partition (device module) | Device lease lifecycle (grant, renew, expire, revoke) exists in code but has no ADR |
| B7 | Coherence Graph Semantics | rvm-coherence (graph module) | Edge weight meaning, decay constants, graph capacity limits are implementation choices without specification |
| B8 | Security Gate Composition | rvm-security (gate module) | The SecurityGate integrates P1+P2+P3+witness but no ADR describes the composition rules |
| B9 | Agent Lifecycle State Machine | rvm-wasm (agent module) | 7-state machine referenced but not formally specified with transition guards |
| B10 | Benchmark Methodology | rvm-benches | Performance claims (10us switch, 50us mincut budget) need documented measurement methodology |

### Gap Category C: Inconsistencies Between Specs and Implementation

| Priority | Inconsistency | Details |
|----------|--------------|---------|
| C1 | ADR-132 says "5 ADRs" but 6 exist | ADR-143 was added after the master ADR was written |
| C2 | ADR-132 lists ADR-133 as follow-on but it is not in RVM docs/ | Planned ADRs (133-140) are listed but only 134, 135 are in RVM docs/ |
| C3 | ADR-134 addendum and ADR-142 partially overlap | ADR-134's addendum summarizes ADR-142 changes; the canonical source of truth is ambiguous for WitnessSigner defaults |
| C4 | ADR-135 addendum says P3 is implemented per ADR-142, but ADR-135 status is still "Proposed" | Status should be updated to "Accepted" with amendments |
| C5 | Partition limit: ADR-132 says DC-12 logical 4096, rvm-partition says MAX_PARTITIONS = 256 | The code enforces the physical limit; the logical multiplexing from DC-12 may not be implemented |
| C6 | GPU ActionKind variants not in ADR-134 witness enum | ADR-144 defines GPU witness events but ADR-134's ActionKind enum does not include them |
| C7 | rvm-coherence references ADR-139 in doc comment but ADR-139 is the Appliance model, not the coherence spec | Likely should reference ADR-141 |
| C8 | ADR-132 non-goals says "no GPU" but ADR-144 adds GPU | ADR-132 was written before GPU support was decided; non-goals section is now stale |

### Gap Category D: Specifications Needed for New Subsystems

| Priority | Specification | Justification |
|----------|--------------|---------------|
| D1 | GPU Witness Integration | ADR-144 defines GPU ActionKind variants but they are not formally registered in the ADR-134 witness schema |
| D2 | GPU-Accelerated MinCut Formal Model | ADR-144 describes the acceleration but does not specify correctness invariants (GPU result must match CPU result within epsilon) |
| D3 | Nightly Pipeline Verification Criteria | ADR-143 lists tests but does not specify the acceptance criteria for "verified" (what exactly must pass?) |
| D4 | Multi-Node Mesh Protocol | ADR-132 mentions mesh clustering but it is explicitly deferred; a placeholder ADR should capture the design space |
| D5 | Formal Verification Roadmap | ADR-132 says formal verification is deferred; a research ADR should capture what properties to verify and what tools to use |

---

## 3. GOAP Action Plan

### Goal State

```
{
  all_adrs_in_rvm_docs: true,       // Category A resolved
  missing_specs_written: true,       // Category B resolved
  inconsistencies_fixed: true,       // Category C resolved
  new_subsystem_specs: true,         // Category D resolved
  research_topics_documented: true,
  docs_structure_established: true
}
```

### Current State

```
{
  all_adrs_in_rvm_docs: false,       // 7 ADRs in submodule only
  missing_specs_written: false,      // 10 specs missing
  inconsistencies_fixed: false,      // 8 inconsistencies
  new_subsystem_specs: false,        // 5 new specs needed
  research_topics_documented: false,
  docs_structure_established: false
}
```

### Action Plan (Ordered by Dependencies)

---

#### Phase 1: Documentation Hygiene (Category A) -- Precondition: None

**Action 1.1: Copy Follow-On ADRs into RVM docs/adr/**

```
Action: copy_follow_on_adrs
  Preconditions: { ruvector_submodule_accessible: true }
  Effects: { all_adrs_in_rvm_docs: true }
  Cost: 1 (low -- file operations only)
  Tool: Bash (cp)
```

Copy ADR-133, 136, 137, 138, 139, 140, 141 from `ruvector/docs/adr/` into `docs/adr/`. Add a header note indicating the canonical source is the ruvector submodule. This makes the complete specification browsable from the RVM repository alone.

**Files to copy:**
- `ruvector/docs/adr/ADR-133-partition-object-model.md` -> `docs/adr/`
- `ruvector/docs/adr/ADR-136-memory-hierarchy-reconstruction.md` -> `docs/adr/`
- `ruvector/docs/adr/ADR-137-bare-metal-boot-sequence.md` -> `docs/adr/`
- `ruvector/docs/adr/ADR-138-seed-hardware-bring-up.md` -> `docs/adr/`
- `ruvector/docs/adr/ADR-139-appliance-deployment-model.md` -> `docs/adr/`
- `ruvector/docs/adr/ADR-140-agent-runtime-adapter.md` -> `docs/adr/`
- `ruvector/docs/adr/ADR-141-coherence-engine-kernel-integration.md` -> `docs/adr/`

---

#### Phase 2: Fix Inconsistencies (Category C) -- Precondition: Phase 1

**Action 2.1: Update ADR-132 to reflect current state**

```
Action: update_adr_132
  Preconditions: { all_adrs_in_rvm_docs: true }
  Effects: { adr_132_current: true }
  Cost: 2
  Tool: Edit
```

Changes needed:
- Update ADR count (now 13 ADRs: 132-144, minus the gap)
- Add ADR-142, 143, 144 to the follow-on table
- Remove "no GPU" from non-goals (now contradicted by ADR-144)
- Update DC-3 addendum to reference ADR-142 implementation
- Note 14 crates (was implied 13)

**Action 2.2: Update ADR-134 to reconcile with ADR-142**

```
Action: reconcile_adr_134_142
  Preconditions: { adr_132_current: true }
  Effects: { witness_schema_consistent: true }
  Cost: 2
  Tool: Edit
```

Changes needed:
- Add GPU ActionKind variants (0xA0-0xAF range) to the enum
- Mark ADR-134 status as "Accepted (amended by ADR-142)"
- Add cross-reference to ADR-144 for GPU witness events

**Action 2.3: Update ADR-135 status**

```
Action: update_adr_135_status
  Preconditions: { witness_schema_consistent: true }
  Effects: { proof_verifier_status_current: true }
  Cost: 1
  Tool: Edit
```

Change status from "Proposed" to "Accepted (P3 implemented per ADR-142)".

**Action 2.4: Fix rvm-coherence doc comment**

```
Action: fix_coherence_doc_reference
  Preconditions: {}
  Effects: { doc_references_correct: true }
  Cost: 1
  Tool: Edit
```

Change "ADR-139" reference in `rvm-coherence/src/lib.rs` to "ADR-141".

---

#### Phase 3: Write Missing Specifications (Category B) -- Precondition: Phase 2

**Action 3.1: ADR-145 IPC Protocol Specification**

```
Action: write_adr_145_ipc
  Preconditions: { adr_132_current: true, witness_schema_consistent: true }
  Effects: { ipc_specified: true }
  Cost: 5
  Tool: Write
```

**Action 3.2: ADR-146 SMP and Per-CPU Scheduling**

```
Action: write_adr_146_smp
  Preconditions: { ipc_specified: true }
  Effects: { smp_specified: true }
  Cost: 5
  Tool: Write
```

**Action 3.3: ADR-147 Hardware Abstraction Layer**

```
Action: write_adr_147_hal
  Preconditions: {}
  Effects: { hal_specified: true }
  Cost: 4
  Tool: Write
```

**Action 3.4: ADR-148 Error Model and Recovery State Machine**

```
Action: write_adr_148_error_model
  Preconditions: {}
  Effects: { error_model_specified: true }
  Cost: 4
  Tool: Write
```

**Action 3.5: ADR-149 RVF Integration for RVM**

```
Action: write_adr_149_rvf_integration
  Preconditions: {}
  Effects: { rvf_integration_specified: true }
  Cost: 3
  Tool: Write
```

**Action 3.6: ADR-150 Device Lease Protocol**

```
Action: write_adr_150_device_lease
  Preconditions: { hal_specified: true }
  Effects: { device_lease_specified: true }
  Cost: 3
  Tool: Write
```

---

#### Phase 4: New Subsystem Specifications (Category D) -- Precondition: Phase 3

**Action 4.1: ADR-151 GPU Witness Event Registry**

```
Action: write_adr_151_gpu_witness
  Preconditions: { witness_schema_consistent: true }
  Effects: { gpu_witness_registered: true }
  Cost: 2
  Tool: Write
```

**Action 4.2: ADR-152 GPU MinCut Correctness Model**

```
Action: write_adr_152_gpu_mincut_correctness
  Preconditions: { gpu_witness_registered: true }
  Effects: { gpu_mincut_correctness_specified: true }
  Cost: 3
  Tool: Write
```

**Action 4.3: ADR-153 Multi-Node Mesh Protocol (Design Space)**

```
Action: write_adr_153_mesh_protocol
  Preconditions: { ipc_specified: true, smp_specified: true }
  Effects: { mesh_protocol_space_documented: true }
  Cost: 4
  Tool: Write
```

**Action 4.4: ADR-154 Formal Verification Roadmap**

```
Action: write_adr_154_formal_verification
  Preconditions: { error_model_specified: true }
  Effects: { formal_verification_roadmap: true }
  Cost: 4
  Tool: Write
```

---

#### Phase 5: Research and Documentation Infrastructure -- Precondition: Phase 2

**Action 5.1: Establish docs/research/ directory structure**

```
Action: create_research_structure
  Preconditions: {}
  Effects: { docs_structure_established: true }
  Cost: 1
  Tool: Bash (mkdir)
```

**Action 5.2: Write research topic briefs**

```
Action: write_research_briefs
  Preconditions: { docs_structure_established: true }
  Effects: { research_topics_documented: true }
  Cost: 5
  Tool: Write
```

---

## 4. New ADR Proposals

### ADR-145: Inter-Partition Communication Protocol

**Summary**: Specifies the three IPC mechanisms available in RVM: synchronous message passing via `MessageQueue`, asynchronous notification via `NotificationSignal`, and zero-copy shared region via `ZeroCopyShare`. Defines message format, queue depth limits, backpressure semantics, and the requirement that every IPC operation updates the coherence graph edge weight (the auto-feeding mechanism from ADR-141). Establishes that IPC is always capability-gated (WRITE right on the source CommEdge) and that all sends emit a witness record. Specifies the ordering guarantees: FIFO within a single CommEdge, no global ordering across edges.

### ADR-146: Symmetric Multi-Processing and Per-CPU Scheduling

**Summary**: Specifies how RVM manages multiple CPU cores. Defines the per-CPU scheduler state (`PerCpuScheduler`), the IPI (inter-processor interrupt) protocol for cross-core partition migration, core affinity semantics for partitions, and the SMP boot sequence where the BSP (bootstrap processor) initializes the kernel and then wakes APs (application processors). Establishes that each CPU runs its own scheduler tick independently, coherence engine recomputation is delegated to a single "coherence CPU" to avoid contention, and partition switch latency targets apply per-core. Defines the relationship between `PartitionId`, `VcpuId`, and physical CPU index.

### ADR-147: Hardware Abstraction Layer

**Summary**: Specifies the HAL trait boundaries that isolate platform-specific code from kernel logic. Defines traits for `Timer` (monotonic nanosecond clock), `Uart` (debug console), `Mmu` (stage-2 page table operations), `Interrupt` (GIC/PLIC/APIC abstraction), `Iommu` (DMA protection), and `PowerManagement` (core enable/disable, frequency scaling). Establishes that all HAL implementations are `no_std`, that the HAL is selected at compile time via feature flags (`hal-aarch64`, `hal-riscv64`, `hal-x86_64`), and that the HAL provides a `PlatformInfo` struct populated from DTB/ACPI at boot. Specifies the fallback behavior when hardware features are unavailable (e.g., no IOMMU degrades to software-enforced DMA bounds).

### ADR-148: Error Model and Recovery State Machine

**Summary**: Formalizes the F1-F4 failure classification from ADR-132 DC-14 as a state machine with explicit transition guards and escalation rules. Specifies that F1 (agent failure) allows 3 restart attempts before escalating to F2, F2 (partition failure) triggers checkpoint-based reconstruction, F3 (memory corruption) triggers region rollback from the dormant tier, and F4 (kernel failure) triggers A/B image failover. Defines the `RecoveryStateMachine` with states `Normal`, `Degraded`, `Recovering`, and `FailSafe`, along with the witness events emitted at each transition. Establishes invariants: no recovery action may proceed without a witness record, no escalation may skip a level (F1 cannot jump to F3), and the system must reach a stable state within a bounded time (configurable per failure class).

### ADR-149: RVF Integration for RVM

**Summary**: Specifies how the RVF (RuVector Format) package system integrates with RVM across three use cases: (1) Boot images -- the RVF manifest defines the Appliance image layout including kernel binary, DTB overlay, initial partitions, and agent modules; (2) Agent deployment -- WASM agent modules are distributed as RVF packages with signed manifests, capability declarations, and resource quota requirements; (3) Checkpoint persistence -- the cold tier (Tier 3) serializes recovery checkpoints as RVF containers with content-addressed storage. Specifies the RVF manifest fields required for each use case, the signature verification flow at boot (ML-DSA-65 per ADR-042), and the relationship between RVF component IDs and partition IDs.

### ADR-150: Device Lease Protocol

**Summary**: Specifies the complete lifecycle of a device lease: request (partition submits a capability-gated lease request), grant (kernel assigns the device with IOMMU isolation and time bounds), renew (partition extends the lease before expiry), expire (kernel reclaims the device on timeout), and revoke (kernel forces device reclamation on security event or partition termination). Defines the `DeviceLease` struct fields (device ID, partition ID, grant time, expiry time, IOMMU context), the capability requirements (READ for query, EXECUTE+WRITE for grant), the witness events for each lifecycle transition, and the interaction with GPU device leases introduced in ADR-144.

### ADR-151: GPU Witness Event Registry

**Summary**: Extends the ADR-134 `ActionKind` enum with GPU-specific witness events in the 0xA0-0xAF range: `GpuContextCreate` (0xA0), `GpuContextDestroy` (0xA1), `GpuKernelLaunch` (0xA2), `GpuKernelComplete` (0xA3), `GpuKernelTimeout` (0xA4), `GpuBufferAlloc` (0xA5), `GpuBufferFree` (0xA6), `GpuTransfer` (0xA7), `GpuBudgetExceeded` (0xA8), `GpuIommuViolation` (0xA9), `GpuDeviceNotFound` (0xAA), `GpuCompileFail` (0xAB). Specifies the payload encoding for each event (kernel ID, buffer size, compute duration, budget remaining) and the audit query patterns for GPU forensics.

### ADR-152: GPU MinCut Correctness Model

**Summary**: Specifies the correctness contract for GPU-accelerated mincut. The GPU result must satisfy: (1) the cut value equals the exact Stoer-Wagner result (no approximation for N <= 32), (2) the partition assignment is identical to the CPU path (verified by comparing partition bitmasks), and (3) if the GPU path exceeds the DC-2 budget (50us), it falls back to the last known CPU result with a `MinCutBudgetExceeded` witness. Defines the testing strategy: every GPU mincut result is cross-validated against the CPU result in debug builds, and a nightly benchmark tracks GPU vs CPU divergence. Specifies the acceptable numerical tolerance (zero for integer weights, epsilon=1e-6 for floating-point weights).

### ADR-153: Multi-Node Mesh Protocol (Design Space)

**Summary**: A design-space ADR (status: Draft) that captures the requirements and open questions for RVM multi-node mesh operation. Identifies four sub-problems: (1) Partition migration across nodes (requires serializing partition state, transferring via network, rebuilding on destination), (2) Cross-node coherence graph maintenance (requires gossip or consensus protocol for edge weight propagation), (3) Distributed capability delegation (requires cross-node capability tokens with node-specific attestation), (4) Witness chain federation (requires merging per-node witness chains into a globally consistent audit trail). Does not propose a solution; establishes the design space and evaluation criteria for future work.

### ADR-154: Formal Verification Roadmap

**Summary**: A research ADR that outlines the path toward formal verification of critical RVM properties. Identifies four verification targets: (1) Capability monotonic attenuation (property: derived capabilities never exceed parent rights), (2) Witness chain integrity (property: any chain break is detectable), (3) Partition isolation (property: no stage-2 mapping allows cross-partition memory access without capability), (4) Scheduler liveness (property: every runnable partition is eventually scheduled). Evaluates three verification approaches: Kani (Rust model checker, suitable for bounded verification of capability operations), Prusti (Rust verifier, suitable for pre/post-condition checking on proof system), and Coq/Lean (theorem provers for deep properties like isolation). Proposes starting with Kani on `rvm-cap` as a pilot.

---

## 5. Research Topics

### 5.1 Theoretical Foundation Strengthening

| Topic | Question | Relevance | Priority |
|-------|----------|-----------|----------|
| R1: Spectral gap and coherence convergence | Under what conditions does the coherence score converge as the communication graph evolves? What is the mixing time? | Validates that coherence scoring is stable, not oscillatory | High |
| R2: Mincut budget analysis | For the Stoer-Wagner algorithm on N nodes, what is the exact worst-case time as a function of N and edge count? What is the largest N that fits within 50us on Cortex-A72? | Validates DC-2 budget on target hardware | High |
| R3: Capability delegation depth and authority propagation | What is the maximum authority surface reachable through depth-8 delegation? Can we bound the number of active capabilities? | Validates that bounded delegation prevents authority explosion | Medium |
| R4: Witness chain FNV-to-SHA migration formal properties | Does the chain migration (FNV tail + SHA-256 head) preserve the tamper-evidence property? Under what adversary model? | Validates ADR-142 migration strategy | Medium |
| R5: Dormant reconstruction fidelity | Under what conditions does checkpoint + delta replay produce byte-identical state to the original? What happens with concurrent mutations during checkpoint? | Validates the "memory time travel" claim from ADR-136 | High |
| R6: GPU determinism for integer mincut | Is the GPU parallel reduction provably bit-identical to the sequential CPU path for integer adjacency matrices? | Validates ADR-152 correctness claim | Medium |

### 5.2 Comparative Analysis

| Topic | Comparison | Deliverable |
|-------|-----------|-------------|
| R7: RVM vs seL4 capability model | Map RVM's 7-right, depth-8 model onto seL4's CNode/CSlot model. Identify where RVM diverges and why. | Comparison document with security implications |
| R8: RVM vs Firecracker boot path | Trace both boot sequences step by step. Quantify where RVM adds latency (no KVM) and where it saves (no Linux). | Benchmark comparison document |
| R9: Coherence scheduling vs CFS/EEVDF | Compare RVM's 2-signal scheduler against Linux CFS and EEVDF under equivalent workloads. | Simulation or microbenchmark results |
| R10: Memory tier efficiency vs zswap/ZRAM | Compare RVM's 4-tier model against Linux zswap for memory-constrained workloads. | Benchmark document with methodology |

### 5.3 Security Research

| Topic | Threat | Deliverable |
|-------|--------|-------------|
| R11: Side-channel resistance of P2 constant-time path | Verify that compiler optimizations do not break constant-time semantics on AArch64 and x86-64. | Assembly audit of P2 verify path |
| R12: GPU covert channel analysis | Can two partitions communicate through GPU timing side channels despite IOMMU isolation? | Threat model document with mitigations |
| R13: TEE collateral expiry attack surface | If TDX collateral expires (30-day window), what is the blast radius? Can an attacker force expiry? | Attack tree analysis |
| R14: Witness chain truncation attack | If the ring buffer overwrites un-drained records, can an attacker exploit the sequence gap? | Formal analysis of gap detection |

---

## 6. Recommended docs/research/ Directory Structure

```
docs/
  adr/                              # Architecture Decision Records
    ADR-132-ruvix-hypervisor-core.md
    ADR-133-partition-object-model.md        # (copy from ruvector)
    ADR-134-witness-schema-log-format.md
    ADR-135-proof-verifier-design.md
    ADR-136-memory-hierarchy-reconstruction.md  # (copy from ruvector)
    ADR-137-bare-metal-boot-sequence.md         # (copy from ruvector)
    ADR-138-seed-hardware-bring-up.md           # (copy from ruvector)
    ADR-139-appliance-deployment-model.md       # (copy from ruvector)
    ADR-140-agent-runtime-adapter.md            # (copy from ruvector)
    ADR-141-coherence-engine-kernel-integration.md  # (copy from ruvector)
    ADR-142-tee-backed-cryptographic-verification.md
    ADR-143-nightly-verified-release-pipeline.md
    ADR-144-gpu-compute-support.md
    ADR-145-ipc-protocol.md                     # (new)
    ADR-146-smp-per-cpu-scheduling.md           # (new)
    ADR-147-hardware-abstraction-layer.md       # (new)
    ADR-148-error-model-recovery.md             # (new)
    ADR-149-rvf-integration.md                  # (new)
    ADR-150-device-lease-protocol.md            # (new)
    ADR-151-gpu-witness-registry.md             # (new)
    ADR-152-gpu-mincut-correctness.md           # (new)
    ADR-153-multi-node-mesh-protocol.md         # (new, Draft status)
    ADR-154-formal-verification-roadmap.md      # (new, Draft status)

  research/
    specification-improvement-plan.md           # (this document)

    theory/
      coherence-convergence.md                  # R1
      mincut-budget-analysis.md                 # R2
      capability-authority-bounds.md            # R3
      chain-migration-properties.md             # R4
      reconstruction-fidelity.md                # R5
      gpu-determinism-proof.md                  # R6

    comparisons/
      rvm-vs-sel4-capabilities.md               # R7
      rvm-vs-firecracker-boot.md                # R8
      coherence-vs-cfs-scheduling.md            # R9
      tier-memory-vs-zswap.md                   # R10

    security/
      p2-constant-time-audit.md                 # R11
      gpu-covert-channel-analysis.md            # R12
      tee-collateral-expiry.md                  # R13
      witness-chain-truncation.md               # R14

    benchmarks/
      measurement-methodology.md                # B10: How we measure
      baseline-results.md                       # Criterion JSON baseline reference
      regression-thresholds.md                  # What constitutes a regression

  RUVECTOR-INTEGRATION.md                       # (existing)
```

---

## 7. Execution Summary

### Phase Dependency Graph

```
Phase 1 (Copy ADRs)           Cost: 1    Preconditions: None
    |
    v
Phase 2 (Fix Inconsistencies) Cost: 6    Preconditions: Phase 1
    |
    v
Phase 3 (Missing Specs)       Cost: 24   Preconditions: Phase 2
    |
    v
Phase 4 (New Subsystem Specs) Cost: 13   Preconditions: Phase 3
    |
    v
Phase 5 (Research + Docs)     Cost: 6    Preconditions: Phase 2
```

**Total estimated cost units: 50**

### Priority Matrix

| Priority | Actions | Rationale |
|----------|---------|-----------|
| **P0 (Do Now)** | 1.1, 2.1, 2.4 | Documentation hygiene -- zero-risk, high visibility |
| **P1 (This Week)** | 2.2, 2.3, 5.1 | Fix inconsistencies before writing new specs |
| **P2 (Next Sprint)** | 3.1, 3.2, 3.3, 3.4 | Core missing specs that block contributor onboarding |
| **P3 (Following Sprint)** | 3.5, 3.6, 4.1, 4.2, 4.3 | Completeness specs and new subsystem formalization |
| **P4 (Ongoing)** | 4.4, 5.2 | Research topics and formal verification -- long-term |

### Replanning Triggers

The plan should be re-evaluated if any of these conditions arise:

1. **New crate added** -- any new RVM crate requires a specification check
2. **ADR-142 TEE providers become hardware-testable** -- may require ADR updates
3. **Multi-node work begins** -- ADR-153 must be promoted from Draft to Proposed
4. **Formal verification pilot completes** -- ADR-154 must be updated with results
5. **Performance regression detected by nightly pipeline** -- may indicate spec budget violations
6. **Security audit findings** -- any new audit may invalidate ADR-142 assumptions

### Success Criteria

The specification improvement is complete when:

1. All 13+ ADRs are browsable from `docs/adr/` without requiring submodule navigation
2. Every RVM crate has at least one ADR that covers its design rationale
3. No ADR status field contradicts the implementation state
4. The `ActionKind` witness enum covers all privileged actions including GPU operations
5. The `docs/research/` directory contains at least one document per research category
6. The benchmark methodology document exists and is referenced by ADR-143
7. A contributor can understand the full RVM architecture by reading only `docs/adr/` files in numeric order

---

## Appendix A: ADR Numbering Inventory

| Number | Title | Location | Status |
|--------|-------|----------|--------|
| 132 | RVM Hypervisor Core | RVM docs/adr/ | Proposed |
| 133 | Partition Object Model | ruvector only | Proposed |
| 134 | Witness Schema and Log Format | RVM docs/adr/ | Proposed (needs update) |
| 135 | Proof Verifier Design | RVM docs/adr/ | Proposed (needs update) |
| 136 | Memory Hierarchy and Reconstruction | ruvector only | Proposed |
| 137 | Bare-Metal Boot Sequence | ruvector only | Proposed |
| 138 | Seed Hardware Bring-Up | ruvector only | Proposed |
| 139 | Appliance Deployment Model | ruvector only | Proposed |
| 140 | Agent Runtime Adapter | ruvector only | Proposed |
| 141 | Coherence Engine Kernel Integration | ruvector only | Accepted |
| 142 | TEE-Backed Cryptographic Verification | RVM docs/adr/ | Accepted |
| 143 | Nightly Verified Release Pipeline | RVM docs/adr/ | Accepted |
| 144 | GPU Compute Support | RVM docs/adr/ | Accepted |
| 145-154 | (Proposed new ADRs) | Not yet written | -- |

## Appendix B: Crate-to-ADR Coverage Matrix

| Crate | Primary ADR | Secondary ADRs | Missing Coverage |
|-------|------------|----------------|-----------------|
| rvm-types | 132, 133, 134 | 135, 136 | None |
| rvm-boot | 137 | 132, 138, 139 | RVF boot manifest (proposed ADR-149) |
| rvm-cap | 135 | 132 | None |
| rvm-coherence | 141 | 132 DC-1/DC-2 | Graph semantics (part of ADR-141) |
| rvm-gpu | 144 | 132 DC-2 | GPU witness (ADR-151), correctness (ADR-152) |
| rvm-hal | 137 | 132 | **Dedicated HAL ADR missing (proposed ADR-147)** |
| rvm-kernel | 132 | All | Integration spec adequate in ADR-132 |
| rvm-memory | 136 | 132 | None |
| rvm-partition | 133 | 132, 135, 141 | IPC (ADR-145), device lease (ADR-150) |
| rvm-proof | 135, 142 | 132, 134 | None |
| rvm-sched | 132 DC-4 | 141 | **SMP ADR missing (proposed ADR-146)** |
| rvm-security | 142 | 135 | Security gate composition (covered by ADR-142) |
| rvm-wasm | 140 | 132, 133 | Agent lifecycle (documented in ADR-140) |
| rvm-witness | 134, 142 | 132 | GPU events (ADR-151) |
