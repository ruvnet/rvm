# Partitions and Scheduling: The Heart of RVM

Partitions are the central abstraction in RVM. Everything else -- capabilities, witnesses, memory tiers, scheduling -- exists to serve partitions. This chapter is split into two parts: Part 1 covers what a partition is and how it lives; Part 2 covers how the scheduler decides which partition runs next.

---

## Part 1: Partitions

### 1. What Is a Partition?

A partition is **not** a virtual machine. There is no emulated hardware, no guest BIOS, no virtual device model. A partition is a lightweight container for:

- **A scoped capability table** -- the set of access rights visible to code running inside the partition (see [Capabilities and Proofs](05-capabilities-proofs.md))
- **Communication edges** -- weighted links to other partitions that represent how much two partitions talk to each other
- **Coherence and cut-pressure metrics** -- graph-derived numbers that tell the scheduler how isolated or connected this partition is
- **CPU affinity and VMID assignment** -- which physical cores the partition may run on, and the ARM VMID used for stage-2 address translation

Partitions are the unit of:

| Concern | What It Means |
|---------|---------------|
| **Scheduling** | The scheduler picks which partition runs next on each CPU |
| **Isolation** | Stage-2 page tables enforce memory boundaries per partition |
| **Migration** | A partition (and its agents) can move between physical cores |
| **Fault containment** | A crash inside one partition cannot corrupt another |

**Hard limit:** `MAX_PARTITIONS = 256`. This comes from the 8-bit ARM VMID field in `VTTBR_EL2`. Every partition gets a unique VMID; with 256 available, that is the ceiling. The constant lives in `rvm-partition/src/partition.rs`.

### 2. Partition Lifecycle

Every partition progresses through a well-defined state machine. The states are defined by the `PartitionState` enum:

```
                 +-----------+
                 |  Created  |
                 +-----+-----+
                       |
              +--------+--------+
              v                 v
         +----+----+     +-----+-----+
         | Running |     | Destroyed |
         +----+----+     +-----------+
              |                 ^
     +--------+--------+       |
     v                 v       |
+----+------+    +-----+-----+|
| Suspended |    | Hibernated |+
+----+------+    +-----+------+
     |                 |
     +--> Running      +--> Created
```

The valid transitions, enforced by `valid_transition()` in `rvm-partition/src/lifecycle.rs`:

| From | To | When |
|------|----|------|
| Created | Running | First activation |
| Created | Destroyed | Tear down before ever running |
| Running | Suspended | Pause all vCPUs |
| Running | Hibernated | Serialize state to cold storage |
| Running | Destroyed | Clean shutdown |
| Suspended | Running | Resume execution |
| Suspended | Hibernated | Hibernate while paused |
| Suspended | Destroyed | Tear down while paused |
| Hibernated | Created | Restore from hibernation (re-enter the lifecycle) |
| Hibernated | Destroyed | Discard the hibernation snapshot |

Any transition not in this table is rejected. Destroyed is a terminal state: nothing can leave it. Every lifecycle transition emits a witness record before the mutation commits (see [Witness and Audit](06-witness-audit.md)).

### 3. The Partition Manager

`PartitionManager` in `rvm-partition/src/manager.rs` owns the array of all partitions. It provides:

- **`create(partition_type, vcpu_count, epoch)`** -- allocate a slot, assign a unique `PartitionId`, return the ID. Fails with `PartitionLimitExceeded` if all 256 slots are full.
- **`get(id)` / `get_mut(id)`** -- O(1) lookup via a direct index (falls back to linear scan for IDs beyond the index range).
- **`remove(id)`** -- free a slot for reuse.
- **`active_ids()`** -- iterate over all currently occupied partition IDs.
- **`count()`** -- number of active partitions.

Partition ID 0 is reserved for the hypervisor itself (`PartitionId::HYPERVISOR`). The first user partition gets ID 1.

The `Partition` struct itself carries:

```rust
pub struct Partition {
    pub id: PartitionId,
    pub state: PartitionState,
    pub partition_type: PartitionType,   // Agent | Infrastructure | Root
    pub coherence: CoherenceScore,       // 0..10000 basis points
    pub cut_pressure: CutPressure,       // graph-derived isolation signal
    pub vcpu_count: u16,
    pub cpu_affinity: u64,               // bitmask of allowed physical CPUs
    pub epoch: u32,                      // creation epoch
}
```

New partitions start with a default coherence score of 5000 basis points (50%) and a CPU affinity of `u64::MAX` (all CPUs allowed).

There are three partition types (`PartitionType`):

| Type | Purpose |
|------|---------|
| `Agent` | Normal workload partition for user agents |
| `Infrastructure` | Driver domain or service partition |
| `Root` | The bootstrap authority partition (created first) |

For the config structure used when creating partitions through the `PartitionOps` trait, see `PartitionConfig` in `rvm-partition/src/ops.rs`.

### 4. Communication Edges

Partitions do not communicate through shared memory. They send messages along **communication edges** (`CommEdge`), defined in `rvm-partition/src/comm_edge.rs`:

```rust
pub struct CommEdge {
    pub id: CommEdgeId,
    pub source: PartitionId,
    pub dest: PartitionId,
    pub weight: u64,            // accumulated message bytes, decayed per epoch
    pub last_epoch: u32,
}
```

Each `CommEdgeId` is a unique `u64` identifier. Edge weights track how much traffic flows between two partitions. These weights are the raw material for the coherence engine: high-weight edges mean strong coupling; low-weight edges mean the partitions are drifting apart. The coherence engine uses these weights to compute mincut boundaries, drive tier placement, and inform split/merge decisions.

Every IPC send increments the edge weight (see section 5 below). Edge weights decay per epoch to reflect recent communication patterns rather than historical totals.

### 5. IPC (Inter-Partition Communication)

`IpcManager` in `rvm-partition/src/ipc.rs` provides zero-copy message passing between partitions. It is parameterized by two const generics:

- `MAX_EDGES` -- maximum number of concurrent IPC channels
- `QUEUE_SIZE` -- per-channel message queue capacity (must be a power of two)

**Creating a channel:**

```rust
let edge_id = ipc_mgr.create_channel(from_partition, to_partition)?;
```

**Sending a message:**

```rust
let msg = IpcMessage {
    sender: caller_id,
    receiver: target_id,
    edge_id,
    payload_len: 128,
    msg_type: 1,
    sequence: next_seq,
    capability_hash: 0xABCD,
};
ipc_mgr.send(edge_id, msg, caller_id)?;
```

The `send()` method enforces two security checks:

1. **Sender identity:** `msg.sender` must match `caller_id` (no spoofing).
2. **Channel authorization:** the caller must be the source endpoint of the channel.

Both checks return `InsufficientCapability` on failure. A separate `send_unchecked()` exists for kernel-internal paths that have already validated authorization.

Each `MessageQueue` is a fixed-size ring buffer. When the queue is full, `send()` returns `ResourceLimitExceeded`. Messages are delivered in FIFO order.

Every successful send increments the channel's weight counter, which feeds back into the coherence graph for mincut computation. See [Core Concepts](02-core-concepts.md) for how coherence scoring works.

### 6. Split and Merge

Split and merge are novel partition operations. No prior hypervisor offers them. They allow RVM to dynamically restructure its partition topology in response to changing agent communication patterns.

**Split** divides one partition into two. The key function is `scored_region_assignment()` in `rvm-partition/src/split.rs`. Given a memory region's coherence score and the coherence scores of the two candidate partitions, it returns a placement score in `[0, 10000]`:

- **7500** = assign to the left partition (closer match)
- **2500** = assign to the right partition (closer match)
- Ties break left

Split is configured through `SplitConfig`, which specifies the minimum coherence threshold required for the split to proceed. Regions are assigned to whichever child partition has the closer coherence score, ensuring that tightly-coupled regions stay together.

**Merge** combines two partitions into one. Before merging, all preconditions must be satisfied. There are two levels of checking:

1. **`merge_preconditions_met(coherence_a, coherence_b)`** -- basic check: both partitions must exceed the merge coherence threshold (default: 7000 basis points = 70%).

2. **`merge_preconditions_full(coherence_a, coherence_b, are_adjacent, combined_cap_count, max_caps_per_partition)`** -- full DC-11 check adding:
   - The partitions must be **adjacent** in the coherence graph (they share a `CommEdge`)
   - The combined capability count must not exceed the per-partition maximum

When a precondition fails, `MergePreconditionError` explains exactly what went wrong:

| Error | Meaning |
|-------|---------|
| `InsufficientCoherence` | One or both partitions are below the 70% threshold |
| `NotAdjacent` | The partitions do not share a communication edge |
| `ResourceLimitExceeded` | The merged partition would have too many capabilities |

Preconditions are checked in priority order: coherence first, then adjacency, then resources. This means a coherence failure is always reported even if adjacency would also fail.

For advanced split/merge scenarios including live migration during split, see [Advanced: Live Split/Merge](13-advanced-exotic.md).

### 7. Device Management

`DeviceLeaseManager` in `rvm-partition/src/device.rs` handles hardware device access. Leases are:

- **Time-bounded** -- each lease has a `granted_epoch` and `expiry_epoch`
- **Revocable** -- the hypervisor can call `revoke_lease()` at any time
- **Exclusive** -- a device may only be leased to one partition at a time
- **Capability-gated** -- the `capability_hash` field records which capability token authorized the grant

The manager is parameterized by `MAX_DEVICES` (registered hardware) and `MAX_LEASES` (concurrent active leases). Key operations:

| Operation | Description |
|-----------|-------------|
| `register_device(info)` | Add a hardware device to the pool |
| `grant_lease(device_id, partition, duration, epoch, cap_hash)` | Grant time-bounded exclusive access |
| `revoke_lease(lease_id)` | Immediately revoke and release the device |
| `check_lease(lease_id, current_epoch)` | Verify a lease is still valid; returns `DeviceLeaseExpired` if not |
| `expire_leases(current_epoch)` | Bulk-expire all leases past their deadline |

`DeviceInfo` describes a registered device:

```rust
pub struct DeviceInfo {
    pub id: u32,
    pub class: DeviceClass,       // Network, Storage, Serial, Timer, Graphics, ...
    pub mmio_base: u64,
    pub mmio_size: u64,
    pub irq: Option<u32>,
    pub available: bool,
}
```

`ActiveLease` tracks a currently held lease:

```rust
pub struct ActiveLease {
    pub lease_id: DeviceLeaseId,
    pub device_id: u32,
    pub partition_id: PartitionId,
    pub granted_epoch: u64,
    pub expiry_epoch: u64,
    pub capability_hash: u32,
}
```

When a lease expires or is revoked, the device returns to the available pool and can be leased to another partition. Double-grants are rejected with `DeviceLeaseConflict`.

---

## Part 2: Scheduling

### 8. The Two-Signal Scheduler

RVM's scheduler computes partition priority from exactly two signals:

```
priority = deadline_urgency + cut_pressure_boost
```

- **`deadline_urgency`** (`u16`) -- how close the partition is to missing its deadline. Higher values mean the partition is more urgent. This is the classic real-time scheduling signal.

- **`cut_pressure_boost`** (`CutPressure`, fixed-point) -- a graph-derived signal from the coherence engine. When a partition's cut pressure is high, it means the partition is becoming isolated from its communication neighbors. Boosting its priority helps it run sooner, giving it a chance to re-establish communication and reduce its isolation.

The `compute_priority()` function in `rvm-sched/src/priority.rs` combines them:

```rust
pub fn compute_priority(deadline_urgency: u16, cut_pressure: CutPressure) -> u32 {
    let pressure_boost = (cut_pressure.as_fixed() >> 16).min(u16::MAX as u32) as u16;
    deadline_urgency as u32 + pressure_boost as u32
}
```

The result is a `u32` in `[0, 131070]`. Higher values mean higher priority. When the coherence engine is absent (DC-1/DC-6 degraded mode), `cut_pressure` is zero and the scheduler falls back to deadline-only scheduling.

This two-signal design is what makes RVM coherence-native: the scheduler does not just schedule by deadline, it also schedules by graph structure.

### 9. Three Modes

The scheduler operates in one of three modes, defined by `SchedulerMode` in `rvm-sched/src/modes.rs`:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Reflex** | Hard real-time. Bounded local execution only. No cross-partition traffic allowed. Target: <10 us context switch. | Latency-critical control loops, interrupt handling |
| **Flow** | Normal execution with coherence-aware placement. Cross-partition IPC is allowed. The scheduler uses both deadline urgency and cut-pressure boost. | Default mode for most workloads |
| **Recovery** | Stabilization mode. Used during replay, rollback, and split operations. The scheduler restricts scheduling decisions to ensure deterministic execution during recovery. | Fault recovery, partition reconstruction |

Each per-CPU scheduler tracks its own mode independently. One CPU can be in Reflex mode handling a real-time partition while another CPU is in Flow mode running normal workloads.

### 10. Partition Switch

The partition switch is the hot path. It must be fast. The design constraints are absolute:

- **No allocation.** Zero heap activity.
- **No graph work.** No coherence computation.
- **No policy evaluation.** The decision was already made; this just executes it.

The five steps of `partition_switch()` in `rvm-sched/src/switch.rs`:

1. Save current registers into the outgoing `SwitchContext` (on AArch64: MRS sequence)
2. Write `to.vttbr_el2` to `VTTBR_EL2` (stage-2 page table base + VMID)
3. TLB invalidate (`TLBI VMALLE1`)
4. Memory barrier (`DSB ISH` + `ISB`)
5. Restore registers from the incoming `SwitchContext`

The target is <10 microseconds. Benchmarks measure approximately 6 nanoseconds on host builds (the HAL stub path). On real AArch64 hardware, the TLB invalidation dominates.

`SwitchContext` is the saved register state for a partition:

```rust
#[repr(C, align(64))]    // cache-line aligned to prevent false sharing
pub struct SwitchContext {
    pub vttbr_el2: u64,   // stage-2 page table base + VMID
    pub elr_el2: u64,     // return address (Exception Link Register)
    pub spsr_el2: u64,    // saved program status
    pub sp_el1: u64,      // guest stack pointer
    pub gp_regs: [u64; 31],  // general-purpose registers x0-x30
}
```

Hot fields (`vttbr_el2`, `elr_el2`, `spsr_el2`, `sp_el1`) are placed first so they fit in a single 64-byte cache line. The general-purpose registers are cold-path fields accessed after the initial switch.

Before switching, `validate_for_switch()` checks two safety conditions:

1. The entry point (`elr_el2`) is not zero
2. The entry point is below the hypervisor address space boundary (`0xFFFF_0000_0000_0000`)

If validation fails, `partition_switch()` returns `Err(InvalidPartitionState)` and no switch occurs.

`SwitchResult` captures the outcome:

```rust
pub struct SwitchResult {
    pub from_vmid: u16,    // VMID of the outgoing partition
    pub to_vmid: u16,      // VMID of the incoming partition
    pub elapsed_ns: u64,   // switch duration (from HAL timer)
}
```

For bare-metal boot details and how `SwitchContext::init()` prepares a partition for first entry, see [Bare Metal](12-bare-metal.md).

### 11. Per-CPU and SMP

**Per-CPU scheduling** is handled by `PerCpuScheduler` in `rvm-sched/src/per_cpu.rs`:

```rust
#[repr(C, align(64))]    // cache-line aligned per CPU
pub struct PerCpuScheduler {
    pub cpu_id: u16,
    pub current: Option<PartitionId>,
    pub mode: SchedulerMode,
    pub idle: bool,
}
```

Each physical CPU has its own `PerCpuScheduler` instance. The cache-line alignment (`align(64)`) ensures that per-CPU data does not share cache lines across CPUs (false sharing prevention).

**Multi-core coordination** is handled by `SmpCoordinator` in `rvm-sched/src/smp.rs`, parameterized by `MAX_CPUS`:

| Operation | Description |
|-----------|-------------|
| `bring_online(cpu_id)` | Mark a CPU as available for scheduling |
| `take_offline(cpu_id)` | Remove a CPU (must release partition first) |
| `assign_partition(cpu_id, partition)` | Bind a partition to a CPU |
| `release_partition(cpu_id)` | Unbind and return the partition to the idle pool |
| `find_idle_cpu()` | Find the first online, idle CPU |
| `partition_affinity(partition)` | Which CPU is running a given partition |
| `rebalance_hint()` | Suggest `(overloaded_cpu, idle_cpu)` pairs for migration |

`CpuState` tracks each physical CPU:

```rust
pub struct CpuState {
    pub cpu_id: u8,
    pub online: bool,
    pub current_partition: Option<PartitionId>,
    pub idle: bool,
    pub epoch_ticks: u64,
}
```

The `epoch_ticks` counter increments each time a partition is assigned to the CPU. The rebalance hint uses this to identify the most heavily loaded CPU and suggest migrating work to an idle one.

V1 uses a cooperative scheduling model. Lock-free work stealing is deferred to post-v1.

### 12. Epoch Tracking

Scheduler epochs are the unit of bulk witness logging. Individual context switches are **not** witnessed (this is a deliberate design choice, DC-10): at thousands of switches per second, per-switch witnessing would be prohibitively expensive.

Instead, `EpochTracker` in `rvm-sched/src/epoch.rs` aggregates switch statistics per epoch:

```rust
pub struct EpochSummary {
    pub epoch: u32,           // epoch number
    pub switch_count: u16,    // total context switches this epoch
    pub runnable_count: u16,  // partitions that were runnable
}
```

Usage:

1. Call `record_switch()` after each context switch (increments the counter)
2. At the epoch boundary, call `advance(runnable_count)` which:
   - Returns an `EpochSummary` for the completed epoch
   - Resets the switch counter to zero
   - Increments the epoch number

The returned `EpochSummary` is then emitted as a single witness record covering all the switches in that epoch. This gives auditors a complete picture of scheduling activity without the overhead of per-switch witnessing.

For how epoch summaries integrate with the witness trail, see [Witness and Audit](06-witness-audit.md). For how the coherence engine uses epoch data, see [Core Concepts](02-core-concepts.md).

---

## Cross-References

| Topic | Chapter |
|-------|---------|
| Capability tables scoped to partitions | [Capabilities and Proofs](05-capabilities-proofs.md) |
| Witness records emitted by lifecycle transitions | [Witness and Audit](06-witness-audit.md) |
| Memory regions owned by partitions | [Memory Model](08-memory-model.md) |
| WASM agents running inside partitions | [WASM Agents](09-wasm-agents.md) |
| Coherence scoring and mincut computation | [Core Concepts](02-core-concepts.md) |
| Stage-2 page tables and VMID handling | [Bare Metal](12-bare-metal.md) |
| Live split/merge advanced scenarios | [Advanced and Exotic](13-advanced-exotic.md) |
| Security gate and attestation | [Security](10-security.md) |
| Performance benchmarks for partition switch | [Performance](11-performance.md) |
| Full API reference for `rvm-partition` and `rvm-sched` | [Crate Reference](04-crate-reference.md) |
