# ADR-146: SMP Scheduling Model

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core, DC-10 witness batching), ADR-144 (GPU Compute Support)

---

## Context

The deep review identified that the multi-core scheduling model -- the interplay
between `SmpCoordinator`, `PerCpuScheduler`, `CpuState`, `SwitchContext`, and
`SchedulerMode` -- is implemented across four files in `rvm-sched` but lacks a
unified specification. The relationship between VMID-aware partition assignment,
coherence-driven load balancing, epoch accounting, and GPU context switching is
not documented as a cohesive protocol.

### Problem Statement

1. **No CPU lifecycle state machine**: `CpuState` tracks `online` and `idle` booleans, but the valid state transitions (Offline -> Online -> Idle -> Busy -> Idle -> Offline) are not specified.
2. **VMID-to-CPU mapping is implicit**: `SmpCoordinator::assign_partition()` stores the partition, but how VMIDs (encoded in `SwitchContext::vttbr_el2` bits [55:48]) relate to partition assignment is undocumented.
3. **Rebalance hint is advisory only**: `rebalance_hint()` returns `(overloaded_cpu, idle_cpu)` based on epoch_ticks, but the rebalance policy is not specified.
4. **GPU context switching is undocumented**: `SwitchContext` conditionally includes `gpu_queue_head` and `gpu_pt_base` under `#[cfg(feature = "gpu")]`, but the save/restore protocol for GPU state is not specified.
5. **Epoch accounting is underspecified**: `CpuState::epoch_ticks` increments on partition assignment but the relationship to the global epoch counter and witness batching (DC-10) is not defined.

---

## Decision

### 1. CPU Lifecycle State Machine

Each physical CPU follows a strict state machine:

```
            bring_online()              assign_partition()
  Offline ──────────────► Online/Idle ──────────────────► Online/Busy
     ▲                       ▲                                │
     │                       │          release_partition()   │
     │    take_offline()     └────────────────────────────────┘
     └───────────────────────┘
           (requires idle)
```

State transitions and their guards:

| Transition | Method | Guard |
|-----------|--------|-------|
| Offline -> Online/Idle | `bring_online(cpu_id)` | `cpu_id < cpu_count`, CPU is offline |
| Online/Idle -> Online/Busy | `assign_partition(cpu_id, pid)` | CPU is online and idle |
| Online/Busy -> Online/Idle | `release_partition(cpu_id)` | Always succeeds; returns previous partition |
| Online/Idle -> Offline | `take_offline(cpu_id)` | CPU is online and idle (no active partition) |

Attempting an invalid transition returns `Err(RvmError::InvalidPartitionState)`.
A CPU with an active partition cannot be taken offline; the caller must
`release_partition()` first.

### 2. VMID-Aware Partition-to-CPU Assignment

Each partition is identified by a `PartitionId` (u32) and has an associated
`SwitchContext` whose `vttbr_el2` field encodes a 8-bit VMID in bits [55:48].
The VMID provides hardware-level TLB isolation on AArch64: the MMU tags all TLB
entries with the VMID, so a context switch only requires a VTTBR_EL2 write and
a VMID-scoped TLB invalidation rather than a full TLB flush.

Assignment protocol:

1. `SmpCoordinator::assign_partition(cpu_id, partition_id)` marks the CPU busy.
2. `partition_switch(&mut from_ctx, &to_ctx)` validates the target (`validate_for_switch()`), writes `to_ctx.vttbr_el2` to VTTBR_EL2, performs `TLBI VMALLE1` + `DSB ISH` + `ISB`, restores registers, and returns `SwitchResult { from_vmid, to_vmid, elapsed_ns }`.
3. `SwitchContext::vmid()` extracts `(vttbr_el2 >> 48) as u16`; `s2_table_base()` extracts `vttbr_el2 & 0x0000_FFFF_FFFF_FFFE`.

`partition_affinity(partition_id)` returns the CPU currently running a given
partition, enabling the coherence engine to collocate communicating partitions.

### 3. Load Balancing via Coherence Pressure

The `rebalance_hint()` method returns an advisory `(overloaded_cpu, idle_cpu)` pair:

- **Overloaded CPU**: the online, busy CPU with the highest `epoch_ticks` (cumulative assignment count).
- **Idle CPU**: any online, idle CPU.

The coherence engine uses this hint combined with `CommEdge` weights to decide
rebalancing:

1. Query `IpcManager::comm_weight()` for edges involving the overloaded CPU's partition.
2. If the partition's strongest communication edge connects to a partition on the idle CPU's NUMA domain, migrate.
3. If migration would increase coherence score (DC-2), execute the rebalance.
4. Otherwise, leave the assignment unchanged.

`epoch_ticks` is incremented by `saturating_add(1)` on each `assign_partition()` call.
It is never reset, serving as a monotonic load indicator. The coherence engine
compares relative tick rates across CPUs to detect imbalance.

### 4. Per-CPU Scheduler State

`PerCpuScheduler` is `#[repr(C, align(64))]` to prevent false sharing. Each instance tracks `cpu_id`, `current: Option<PartitionId>`, `mode: SchedulerMode`, and `idle: bool`. The three scheduler modes:

| Mode | Behaviour | Use Case |
|------|-----------|----------|
| `Reflex` | Hard real-time; bounded local execution only; no coherence queries | Interrupt handling, safety-critical partitions |
| `Flow` | Normal execution with coherence-aware placement | General workloads |
| `Recovery` | Stabilization: replay, rollback, split operations | Partition recovery (ADR-148 F2/F3) |

### 5. GPU Context Fields in SwitchContext

When compiled with `#[cfg(feature = "gpu")]`, `SwitchContext` includes two
additional fields:

```rust
#[cfg(feature = "gpu")]
pub gpu_queue_head: u64,  // GPU command queue head pointer
#[cfg(feature = "gpu")]
pub gpu_pt_base: u64,     // GPU page table base address
```

GPU context save/restore protocol:

1. On `partition_switch()`, the outgoing partition's `gpu_queue_head` and `gpu_pt_base` are saved into `from_ctx` (via `save_from()`).
2. The incoming partition's GPU page table base is written to the GPU IOMMU.
3. The GPU command queue head is restored to resume submitted work.
4. `SwitchContext::init()` zeroes both GPU fields for new partitions.

GPU context switching adds overhead proportional to the IOMMU flush cost.
On deployments without the `gpu` feature, these fields are compiled out entirely,
adding zero overhead to the hot path.

### 6. Epoch-Based Witness Batching (DC-10)

Individual context switches are **not** witnessed. At thousands of switches per
second, per-switch witness records would overwhelm the witness log. Instead:

- Each CPU accumulates `epoch_ticks` across the epoch.
- At epoch boundary, the scheduler emits an `EpochSummary` witness record containing:
  - Per-CPU: partition assignments, total ticks, mode changes.
  - Per-channel: accumulated IPC weight (from `IpcManager::comm_weight()`).
  - Aggregate: total switches, rebalance events, GPU context switches.
- The witness record is appended to the log as a single batched entry (ADR-134).

---

## Consequences

### Positive

- Explicit state machine prevents invalid CPU transitions at compile-documented boundaries.
- VMID encoding in VTTBR_EL2 provides hardware-accelerated TLB isolation.
- Cache-line alignment of `PerCpuScheduler` eliminates false sharing.
- Feature-gated GPU fields add zero cost when GPU support is not compiled.
- Epoch batching keeps witness log growth bounded (DC-10).

### Negative

- Rebalance hints are advisory; no automatic migration is implemented in v1.
- `epoch_ticks` is a coarse load indicator -- it does not account for partition execution duration.
- GPU context switching is not yet implemented in the HAL; only the data model is specified.
- No work stealing between CPUs; v1 is a cooperative model.

### Risks

- Without coherence-driven rebalance, communicating partitions may remain on distant CPUs.
- Monotonic `epoch_ticks` can bias rebalance hints toward the same CPU, requiring normalization.

---

## References

- `rvm-sched/src/smp.rs` -- `SmpCoordinator`, `CpuState`
- `rvm-sched/src/per_cpu.rs` -- `PerCpuScheduler`
- `rvm-sched/src/switch.rs` -- `SwitchContext`, `SwitchResult`, `partition_switch()`
- `rvm-sched/src/modes.rs` -- `SchedulerMode` (Reflex, Flow, Recovery)
- ADR-132, Section DC-2 -- Coherence graph and mincut
- ADR-132, Section DC-10 -- Epoch-based witness batching
- ADR-144 -- GPU compute support (GPU context fields)
