# ADR-139: Appliance Deployment Model — Edge Hub with Coherence-Native Control

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-136 (Memory Hierarchy and Reconstruction), ADR-140 (Agent Runtime Adapter)

---

## Context

ADR-132 defines three target platforms for RVM: Seed (tiny, event-driven), Appliance (edge hub, deterministic orchestration), and Chip (future Cognitum silicon). Of these three, the Appliance is the primary proof point for the entire architecture. If coherence-native control cannot demonstrate measurable value on a bounded edge hub with real hardware, the Seed and Chip targets lose credibility.

### Problem Statement

1. **No deployment model exists for RVM on commodity edge hardware**: The architecture document and GOAP plan describe the system abstractly. This ADR specifies the concrete deployment target: what hardware, what image format, what partition budget, what device model, what update mechanism.
2. **Edge hubs today are Linux-based and VM-centric**: Existing edge orchestrators (K3s, Azure IoT Edge, AWS Greengrass) run on Linux and use containers or VMs. They inherit Linux's scheduling overhead, memory management complexity, and attack surface. RVM replaces all of this with a single bootable image.
3. **Coherence-native control needs a proof point**: The mincut-driven placement, cut-pressure scheduling, and witness-native audit described in ADR-132 are novel claims. They must be demonstrated on real hardware under real multi-agent workloads. The Appliance is where this happens.
4. **Multi-agent edge computing lacks deterministic orchestration**: Factory floor controllers, retail AI hubs, and autonomous vehicle compute nodes need bounded latency and provable isolation between tenants. Containers on Linux cannot provide this.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| AWS Greengrass v2 | Edge runtime with local ML inference, component model | Baseline for edge agent deployment; Linux-dependent, no coherence awareness |
| Azure IoT Edge | Container-based edge modules, device twin | Container isolation model; RVM replaces with capability-enforced partitions |
| K3s (Rancher) | Lightweight Kubernetes for edge | Demonstrates demand for edge orchestration; still requires Linux kernel |
| balenaOS | Immutable container OS for edge fleets | Single-image deployment model; RVM adopts similar update philosophy |
| Tock OS | Embedded Rust OS with grant regions | Capability-based device access on constrained hardware; informs device lease model |
| Hubris (Oxide) | Embedded Rust RTOS, static allocation | Deterministic scheduling on bounded hardware; informs Reflex mode design |

---

## Decision

The Appliance is the **primary deployment target** for RVM v1. It is a single-image, bootable edge hub that runs the full RVM stack (kernel + coherence engine + agent runtime) on commodity ARM or x86 hardware. All six ADR-132 success criteria must pass on Appliance hardware.

### Hardware Profile

| Parameter | Range | Reference Target |
|-----------|-------|-----------------|
| CPU cores | 1-16 | 4-core ARM Cortex-A72 (Raspberry Pi CM4 class) or x86-64 Atom/Xeon-D |
| RAM | 1-32 GB | 4 GB (minimum viable), 8 GB (recommended) |
| Storage | SSD or eMMC | 16 GB eMMC minimum; NVMe SSD for cold-tier storage |
| Network | Ethernet + optional WiFi | Gigabit Ethernet required; WiFi for mesh clustering |
| Architecture | AArch64 or x86-64 | AArch64 primary (matches QEMU virt development target) |
| Accelerators | Optional | Crypto accelerator (if present), GPU (if present) |

The Appliance is not a microcontroller. It has enough resources to run the full coherence engine, multiple WASM agent partitions, and the 4-tier memory model. It is also not a server — it is a bounded, dedicated device.

### Deployment Model: Single-Image Bootable

The Appliance boots from a single binary image. There is no installer, no host OS, no bootloader menu.

```
RVF Image Layout:
  [RVF Header]          -- Signature, version, manifest hash
  [RVM Kernel]        -- Bare-metal Rust binary (EL2/VMX root)
  [Device Tree Overlay]  -- Hardware-specific DTB or ACPI tables
  [Boot RVF Package]    -- Initial partition configs + WASM agent modules
  [Witness Seed]        -- Initial witness chain root (attestation anchor)
  [Cold Storage Map]    -- Partition layout for persistent storage
```

**Boot sequence** (from ADR-132 Layer 0-1):
1. Reset vector jumps to RVM kernel
2. Hardware detection via DTB/ACPI
3. MMU + hypervisor mode initialization
4. Capability table and witness log initialization
5. Boot RVF package unpacked: initial partitions created
6. First witness emitted (target: <250ms from power-on)
7. Scheduler loop entered; agent partitions begin execution

### Partition Budget

| Parameter | Minimum | Maximum | Default |
|-----------|---------|---------|---------|
| Concurrent partitions | 4 | 64 | 16 |
| WASM agents per partition | 1 | 8 | 1 |
| CommEdges per partition | 1 | 32 | 4 |
| Total WASM agents | 4 | 128 | 16 |

Each partition is a coherence domain (ADR-132). The coherence engine manages all partitions as nodes in the communication graph, with CommEdges as weighted edges. The mincut algorithm operates over this graph to derive placement, migration, and split/merge decisions.

64 is the **total** (active + dormant + suspended). Active partition density is strictly bounded:

```
active_partitions_per_core <= 8   (hard limit, configurable down)
total_partitions = active + suspended + dormant + hibernated
```

| State | Resource Cost | Count Range |
|-------|-------------- |-------------|
| Active (Running) | Full CPU slice + Hot memory | 4-32 (bounded by cores x 8) |
| Suspended | Metadata only, no CPU | 0-32 |
| Dormant | Compressed in Dormant tier | 0-64 |
| Hibernated | Cold storage only | Unbounded |

At 64 total partitions on 4 cores, most partitions are NOT simultaneously active. The coherence engine (or static affinity in degraded mode) decides which partitions are active. This prevents the cache thrash and memory pressure that would result from 16 active partitions per core.

### Full Memory Model (All Four Tiers)

The Appliance runs the complete 4-tier memory hierarchy from ADR-132:

| Tier | Appliance Backing | Capacity | Role |
|------|-------------------|----------|------|
| **Hot** | L1/L2 cache + pinned DRAM | 10-20% of RAM | Active execution state for running partitions |
| **Warm** | DRAM (unpinned) | 40-60% of RAM | Recently-used state, shared regions |
| **Dormant** | Compressed DRAM (LZ4) | 20-30% of RAM | Suspended agents, proof objects, embeddings |
| **Cold** | SSD/eMMC/NVMe | Full storage capacity | Checkpoints, historical state, witness log archive |

Pages transition between tiers based on `cut_value + recency_score > eviction_threshold` (ADR-132 memory model). On the Appliance, the cold tier uses local persistent storage — no network dependency for state recovery.

**Predictive warm promotion**: Cold-tier reconstruction on eMMC/SD can exceed 100ms. To avoid latency spikes:

```
predictive_promotion_signals:
    1. graph_proximity: if neighbor partition is active, promote its CommEdge peers to Warm
    2. recent_access: if cold page was accessed in last N epochs, promote to Warm preemptively
    3. scheduler_hint: if scheduler plans to wake a suspended partition, promote its Hot set first
```

This pre-loads state before it's needed, avoiding the worst-case cold-tier reconstruction latency on slow storage.

### Scheduling Configuration

| Mode | Appliance Behavior |
|------|-------------------|
| **Flow** | Primary mode. `priority = deadline_urgency + cut_pressure_boost` (ADR-132, DC-4). Coherence-aware placement via mincut. |
| **Reflex** | Available for real-time partitions. Bounded local execution, no cross-partition traffic, deterministic worst-case latency. Used by factory-floor control loops, sensor polling. |
| **Recovery** | Available. Replay witness log, rollback to checkpoint, split partitions, rebuild from dormant tier. Triggered by fault detection or operator command. |

The scheduler runs per-CPU (architecture doc, Section 5.4). On a 4-core Appliance, four `PerCpuScheduler` instances coordinate through the `GlobalScheduler`, with partition-to-CPU assignment informed by the coherence graph.

### Coherence Engine: ACTIVE

The coherence engine (ADR-132, Layer 2) runs fully on the Appliance. This is the critical differentiator — the Appliance is where mincut-driven placement demonstrates measurable value over static allocation.

**Coherence engine operations on the Appliance:**

| Operation | Frequency | Budget | Fallback |
|-----------|-----------|--------|----------|
| Mincut value query | Every scheduler epoch | <50 us (DC-2) | Last known cut |
| Cut pressure computation | Every epoch | Included in mincut budget | Stale pressure, degraded flag |
| Partition migration | On threshold breach | <10 ms | Defer to next epoch |
| Partition split/merge | On structural trigger | <50 ms | Defer; log witness |
| Coherence score refresh | Every 10 epochs | <500 us | Stale score |

**Adaptive frequency**: On constrained 4-core hardware, the coherence engine frequency adapts to load:

```
if cpu_load > 80%:
    coherence_frequency = every 4th epoch    (reduce overhead under pressure)
    mincut_mode = incremental_only           (no full recomputation)
elif cpu_load > 60%:
    coherence_frequency = every 2nd epoch    (balanced)
elif cpu_load < 30%:
    coherence_frequency = every epoch        (full precision when idle)
    mincut_mode = full_recompute_allowed     (take advantage of spare cycles)
```

This prevents scheduler starvation and jitter on resource-constrained appliance hardware. The coherence engine is an optimization — it must never compete with the workloads it serves.

If the coherence engine exceeds its budget or fails, the kernel degrades to locality-based scheduling (DC-1). This is tested as part of the fault recovery success criterion.

### Device Model: Lease-Based Access

Devices on the Appliance are accessed through the lease model (architecture doc, Section 3.6):

| Device Class | Lease Type | Typical Leaseholder |
|-------------|------------|-------------------|
| Storage (SSD/eMMC) | Long-term, shared read | Witness log partition, cold-tier manager |
| Network (Ethernet) | Time-bounded, exclusive write | Network agent partition |
| Crypto accelerator | Short-term, exclusive | Attestation partition, secure boot |
| GPU (if present) | Time-bounded, exclusive | ML inference agent partition |
| Serial/UART | Debug only | Kernel (not leased) |
| Timer | Kernel-owned | Scheduler (not leased) |

Lease expiry automatically revokes capabilities. DMA budget enforcement prevents a rogue partition from exhausting memory through device DMA.

### Network Model

**Local (single appliance):**
- All IPC is through CommEdges (zero-copy where possible)
- Witness log streamed to persistent storage continuously
- Local witness log queryable by partitions with WITNESS capability

**Mesh (multi-appliance cluster, future):**
- Inter-appliance communication over Ethernet
- Partition migration between appliances (Phase 4+, M7)
- Distributed witness log merge across appliance cluster
- Cross-appliance coherence graph maintained by designated coordinator partition

### Monitoring and Audit

The witness log is the primary monitoring mechanism. On the Appliance:
- Witness records are appended to a dedicated storage partition
- Records are queryable locally (partitions with WITNESS capability can read the log)
- A monitoring agent partition can stream witness records over the network to an external collector
- Merkle compaction occurs when the ring buffer wraps, preserving the hash chain to cold storage

### Update Mechanism

| Property | Specification |
|----------|--------------|
| Image format | RVF-packaged (RuVector Format), signed |
| Signature verification | ML-DSA-65 attestation (from ruvix-boot) |
| Delivery | Network pull or USB/SD card |
| Rollback | Dual-partition A/B scheme; rollback to previous image on boot failure |
| Attestation | Measured boot: each stage hashes the next and extends the witness chain |
| Downtime | Cold reboot required for kernel update; agent-only updates can hot-swap partitions |

The A/B partition scheme uses two storage slots. The running image occupies slot A. An update is written to slot B, verified, and the boot pointer is atomically switched. If the new image fails to emit a first witness within the timeout, the watchdog reverts to slot A.

**Witness chain continuity invariant**: The witness chain MUST survive upgrades.

```
upgrade_witness_protocol:
    1. emit witness(UPGRADE_INITIATED, old_version, new_version, chain_head_hash)
    2. write new image to slot B
    3. emit witness(UPGRADE_VERIFIED, new_image_hash)
    4. atomic boot pointer switch
    5. new kernel reads chain_head_hash from upgrade witness in old log
    6. new kernel continues chain from that hash (no break)
    7. emit witness(UPGRADE_COMPLETE, new_version, old_chain_head_hash)
```

If the chain breaks, the audit trail breaks, and trust breaks. This invariant is non-negotiable.

### Control Partition (Operator Interface)

The Appliance includes a **control partition** — a privileged partition for operator interaction, debugging, and system management. It is the only partition with WITNESS read capability and system-level query rights.

| Function | Mechanism |
|----------|-----------|
| Witness query | Read witness log, filter by partition/time/action |
| Partition inspection | List active/suspended/dormant partitions, view CoherenceScores |
| Operator commands | Create/destroy/migrate partitions, grant/revoke capabilities |
| Health monitoring | Track epoch summaries, detect anomalies, trigger Recovery mode |
| Debug console | Serial/UART or network SSH to control partition shell |
| Metrics export | Stream partition metrics and witness summaries over network |

The control partition runs in Flow mode with elevated capabilities but is still subject to the capability discipline — it cannot bypass proof-gated mutation. It is created at boot as the first user partition after the kernel initializes.

### Failure Classification

Failure recovery requires explicit classification. Not all failures are equal.

| Class | Scope | Detection | Response | Example |
|-------|-------|-----------|----------|---------|
| **F1: Agent failure** | Single WASM agent within a partition | WASM trap, timeout, resource limit exceeded | Restart agent within partition. Emit witness(AGENT_RESTART). | Agent panics, infinite loop, OOM within WASM linear memory |
| **F2: Partition failure** | Single partition | Capability violation, unrecoverable agent state, memory corruption detected by checksums | Terminate partition. Reconstruct from checkpoint + witness log. Emit witness(PARTITION_RECONSTRUCT). | Corrupted partition state, repeated F1 failures |
| **F3: Memory corruption** | Cross-partition or kernel memory | ECC error, hash mismatch on witness chain, page table corruption | Rollback affected region to last valid checkpoint. Enter Recovery mode for affected partitions. Emit witness(MEMORY_ROLLBACK). | Bitflip in DRAM, storage corruption |
| **F4: Kernel failure** | Entire system | Kernel panic, watchdog timeout, unrecoverable scheduler state | Full reboot from A/B image. Witness chain preserved on persistent storage. Emit witness(KERNEL_REBOOT) on next boot. | Kernel bug, hardware fault beyond software recovery |

**Escalation rule**: F1 → F2 after 3 restart failures within a cooldown window. F2 → F3 if reconstruction fails. F3 → F4 if rollback fails. Each escalation is witnessed.

### Security Model

| Property | Mechanism |
|----------|-----------|
| Measured boot | Each boot stage hashes the next; extends witness chain from hardware root of trust |
| Attestation | ML-DSA-65 signature over boot measurements; verifiable by remote party |
| Tenant isolation | Capability-enforced partition boundaries (ADR-132 proof system, P1+P2) |
| No ambient authority | Every resource access requires an explicit capability |
| Device isolation | Lease-based access with DMA budget enforcement |
| Witness integrity | Append-only, hash-chained log; tamper-evident by construction |
| Network security | TLS for inter-appliance communication; capability-gated network device access |

---

## Success Criteria

All six ADR-132 success criteria must pass on Appliance hardware:

| # | Criterion | Target | Appliance-Specific Note |
|---|-----------|--------|------------------------|
| 1 | Cold boot to first witness | <250ms | On physical ARM/x86 board, not just QEMU |
| 2 | Hot partition switch latency | <10 us | Measured with ARM cycle counter or x86 TSC |
| 3 | Remote memory traffic reduction | >=20% vs naive placement | Compared against round-robin partition assignment on same hardware |
| 4 | Tail latency reduction | >=20% under mixed partition pressure | 16+ concurrent agent partitions, mixed Flow and Reflex |
| 5 | Witness completeness | Full trail for every migration, remap, device lease | Verified by witness log replay producing identical state |
| 6 | Fault recovery | Recover from injected fault without global reboot | Kill one agent partition, verify others continue; corrupt one region, verify reconstruction |

### Additional Appliance-Specific Criteria

| # | Criterion | Target |
|---|-----------|--------|
| A1 | Sustained 16-partition operation for 24 hours | No memory leaks, no witness chain breaks |
| A2 | A/B update with rollback | Successful update, then forced rollback, both produce valid witness chains |
| A3 | Multi-agent communication throughput | >=10,000 messages/second across 8 CommEdges |
| A4 | Cold-tier reconstruction | Reconstruct a dormant agent from cold storage within 100ms |

---

## Use Cases

### Smart Factory Floor Controller

An Appliance on the factory floor runs:
- 4 Reflex-mode partitions for PLC communication (deterministic latency)
- 8 Flow-mode partitions for ML inference agents (anomaly detection, predictive maintenance)
- 2 partitions for data aggregation and upstream reporting
- 1 monitoring partition for local dashboard

The coherence engine places PLC-communication agents on the same core as their paired ML agents (high CommEdge weight), while isolating upstream reporting agents on a separate core (low coupling).

### Retail Edge AI Hub

An Appliance behind the checkout area runs:
- Camera inference agents (one per camera, Flow mode)
- Inventory tracking agents (shared state via CommEdges)
- POS integration agent (Reflex mode for transaction latency)
- Loss prevention agent (cross-references camera + POS data)

Tenant isolation ensures the POS agent cannot be affected by a camera inference crash. The witness log provides a complete audit trail for every transaction-related event.

### Autonomous Vehicle Compute Node

An Appliance in the vehicle runs:
- Sensor fusion agents (LiDAR, camera, radar — Reflex mode)
- Path planning agent (Flow mode, high priority)
- Comfort system agents (HVAC, seat, infotainment — Flow mode, low priority)
- V2X communication agent (network-connected)

The coherence engine keeps sensor fusion and path planning agents tightly coupled (high coherence score, co-located cores). Comfort agents are isolated and can be preempted without affecting safety-critical partitions.

### Secure Multi-Agent Orchestrator

An Appliance running untrusted third-party AI agents:
- Each agent in its own partition (double-sandboxed: capability boundary + WASM)
- No ambient authority — agents can only communicate through explicitly granted CommEdges
- Full witness log for every inter-agent message
- Resource quotas prevent any single agent from monopolizing CPU or memory
- Attestation proves to remote parties which agents are running and what code they contain

---

## Implementation Milestones

The Appliance deployment model is validated at **M7** (ADR-132, Phase 4) but requires work across all phases:

| Phase | Appliance-Relevant Work |
|-------|------------------------|
| Phase 1 (M0-M1) | Boot on QEMU virt (Appliance emulation), partition model, capability system |
| Phase 2 (M2-M3) | Witness log on persistent storage, scheduler with Flow + Reflex modes |
| Phase 3 (M4-M5) | Coherence engine on multi-core, 4-tier memory with SSD cold tier |
| Phase 4 (M6-M7) | WASM agent runtime, hardware bring-up, A/B update, all success criteria |

---

## Consequences

### Positive

- **Proof point for the architecture**: If coherence-native control works on the Appliance — bounded hardware, real workloads, measurable metrics — then the Seed and Chip targets become credible extrapolations rather than speculative claims.
- **No OS dependency**: Single bootable image eliminates the Linux kernel, its CVE surface, its scheduling unpredictability, and its memory management overhead.
- **Deterministic multi-tenant edge**: Capability-enforced isolation with Reflex-mode scheduling provides guarantees that containers on Linux cannot.
- **Self-auditing**: Witness-native operation means the Appliance carries its own audit trail. No external logging infrastructure required for compliance.
- **Commodity hardware**: ARM SBCs and x86 edge boxes are cheap and widely available. No custom silicon required for v1.

### Negative

- **No Linux binary compatibility**: Existing edge software (containerized microservices, Python ML scripts) cannot run unmodified. Agents must be compiled to WASM.
- **Limited device support**: v1 supports only the devices in the minimal device model (storage, network, timer, interrupt controller). No USB, no display, no audio.
- **Update requires reboot**: Kernel updates require a cold reboot. Hot-swapping the hypervisor kernel is not supported in v1.
- **Single-appliance only in v1**: Multi-appliance mesh clustering and cross-node migration are deferred to post-v1.

### Risks

| Risk | Mitigation |
|------|-----------|
| Coherence engine overhead exceeds budget on 4-core hardware | DC-2 hard budget; fallback to locality-based scheduling; benchmark at M4 |
| WASM overhead makes agent performance uncompetitive | Benchmark against native partitions at M6; consider AOT compilation |
| Cold-tier SSD latency too high for reconstruction | Prefetch based on coherence graph prediction; keep reconstruction-critical state in Dormant tier |
| A/B update mechanism adds storage overhead | Minimum 16 GB eMMC accommodates two images plus witness log |

---

## References

- ADR-132: RVM Hypervisor Core
- ADR-136: Memory Hierarchy and Reconstruction
- ADR-140: Agent Runtime Adapter
- RVM Architecture Document: `docs/research/ruvm/architecture.md`
- RVM GOAP Plan: `docs/research/ruvm/goap-plan.md`
- Agache, A., et al. "Firecracker: Lightweight Virtualization for Serverless Applications." NSDI 2020.
- Levy, A., et al. "Tock: A Secure Embedded Operating System for Cortex-M Microcontrollers." SEC 2017.
- Hubris: Oxide Computer Company. https://github.com/oxidecomputer/hubris
