# ADR-139: Appliance Deployment Model

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

ADR-132 defines the Appliance as the primary deployment target: an edge hub with 1-32 GB RAM, multi-core processor, and hardware virtualization extensions (ARM VHE or similar). Unlike Seed (ADR-138), the Appliance has sufficient resources to run the full RVM stack: coherence engine, WASM runtime, dynamic partitioning, and GPU compute.

The Appliance is where RVM's differentiating features are exercised: graph-theoretic partition placement, dynamic split/merge, coherence-weighted scheduling, agent workloads, and measured boot with TEE attestation.

## Decision

### Hardware Profile

| Resource | Appliance Range | Design Point |
|----------|----------------|-------------|
| RAM | 1 - 32 GB | 4 GB typical for edge deployment |
| Cores | 2 - 16 | SMP scheduling with per-core Hot tier memory |
| MMU | Full stage-2 | ARM VHE or RISC-V H-extension; hardware VMID support |
| Storage | 16 GB - 1 TB SSD/eMMC | Witness log persistence, Cold tier storage |
| Network | Ethernet / WiFi | Agent migration between Appliance nodes (post-v1) |
| GPU | Optional (feature-gated) | Compute offload for ML agent workloads |
| TEE | Optional (TrustZone/CCA) | Measured boot, witness signing |

### Full Feature Set

The Appliance enables all RVM features:

1. **Coherence engine**: Full graph state, MinCut computation (Stoer-Wagner builtin or RuVector backend), adaptive recomputation frequency based on CPU load, cut pressure scoring, split/merge recommendations.

2. **Dynamic partitioning**: Up to 256 physical partition slots (ARM VMID). Dynamic split when cut pressure exceeds threshold (7500 basis points default). Dynamic merge when mutual coherence exceeds threshold (7000 basis points). Scored region assignment during split (DC-9).

3. **WASM agent runtime**: WebAssembly modules execute inside partitions. 7-state agent lifecycle (Initializing, Running, Suspended, Migrating, Hibernated, Reconstructing, Terminated). 13 host functions including 5 GPU operations. Per-partition resource quotas enforced per epoch.

4. **SMP scheduling**: Multi-core scheduler with per-core run queues. Two-signal priority: `deadline_urgency + cut_pressure_boost` (DC-4). Flow, Reflex, and Recovery modes. Partition switch target: < 10 microseconds.

5. **GPU compute** (feature-gated): Optional GPU subsystem for ML inference workloads. Host functions: GpuLaunch, GpuAlloc, GpuFree, GpuTransfer, GpuSync. Capability-checked; requires EXECUTE+WRITE rights for kernel launch.

6. **Full memory hierarchy**: All four tiers active. Hot tier uses per-core SRAM/L1-adjacent memory. Warm tier in shared DRAM with coherence-driven eviction. Dormant tier with checkpoint + witness delta reconstruction. Cold tier on persistent storage.

7. **Control partition** (DC-15): First user partition created at boot. Provides witness log queries, partition inspection, health monitoring, and debug console (serial or network). Subject to capability discipline.

### Resource Quotas

Each WASM-hosting partition is subject to per-epoch resource budgets:

| Resource | Default Budget | Enforcement |
|----------|---------------|-------------|
| CPU time | 10 ms per epoch | Lowest-priority agent terminated on exceed |
| Memory pages | 256 pages (16 MiB) | Allocation fails beyond limit |
| IPC messages | 1024 per epoch | Send fails beyond limit |
| Concurrent agents | 32 | Spawn fails beyond limit |

Quota enforcement uses atomic check-and-record operations to prevent TOCTOU races. Per-epoch counters (CPU, IPC) reset at each scheduler epoch; memory and agent counts persist.

### Deployment Configuration

An Appliance deployment is configured via a static manifest specifying:

- Number and type of initial partitions.
- Per-partition resource quotas.
- Coherence engine parameters (mincut budget, recomputation interval, split/merge thresholds).
- Scheduler mode (Flow default, Reflex for real-time partitions).
- TEE signing configuration (NullSigner, HMAC-SHA256, or Ed25519).
- GPU feature enablement.

### Success Criteria

All six ADR-132 success criteria are validated on Appliance:

1. Cold boot to first witness: < 250ms.
2. Hot partition switch: < 10 microseconds.
3. Remote memory traffic reduction: >= 20% vs. naive placement.
4. Tail latency reduction: >= 20% under mixed partition pressure.
5. Witness completeness: full trail for every privileged action.
6. Fault recovery: recover from injected fault without global reboot.

## Consequences

### Positive

- **Full feature demonstration**: Appliance is the only target where all RVM innovations (coherence, split/merge, WASM agents, GPU) are exercised together.
- **Edge-optimized**: Bounded workloads, deterministic scheduling, and local operation make Appliance ideal for edge AI deployments.
- **Hardware-assisted isolation**: Stage-2 page tables and VMID-based TLB tagging provide strong partition isolation without software overhead.

### Negative

- **Complex configuration**: The full feature set requires careful tuning of coherence thresholds, quota budgets, and scheduler parameters. Misconfiguration can cause excessive split/merge churn.
- **GPU adds attack surface**: The GPU subsystem introduces 5 additional host functions and a device lease model. Feature-gating mitigates this for deployments that don't need GPU.
- **Power consumption**: Unlike Seed, Appliance does not support deep sleep. Multi-core operation and continuous coherence recomputation consume significant power.

### Neutral

- Appliance is the validation platform for v1. Chip (future Cognitum silicon) will provide hardware-accelerated versions of features that are software-only on Appliance.

## References

- ADR-132: RVM Hypervisor Core (DC-4, DC-5, DC-15, success criteria)
- ADR-133: Partition Object Model (split/merge semantics)
- ADR-136: Memory Hierarchy and Reconstruction (four-tier model)
- ADR-138: Seed Hardware Profile (contrast with constrained target)
- ADR-140: Agent Runtime Adapter (WASM lifecycle)
- ADR-141: Coherence Engine Integration (graph and scoring)
- ADR-144: GPU Compute Support
