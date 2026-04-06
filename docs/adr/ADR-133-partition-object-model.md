# ADR-133: Partition Object Model

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

ADR-132 establishes partitions as the primary abstraction in RVM -- not VMs. A partition is a coherence domain container for scheduling, isolation, migration, and fault containment. However, ADR-132 specifies partitions at the architectural level without defining the concrete object model: lifecycle states, transition rules, split/merge semantics, communication edges, device leases, or the relationship between logical and physical partition slots.

Without a precise object model, implementations risk diverging on fundamental questions: What states can a partition occupy? When is a split legal? How are capabilities handled during merge? This ADR answers those questions.

## Decision

### Partition Structure

A partition is a fixed-size kernel object containing:

- **PartitionId**: Unique identifier (u32), recyclable after destruction.
- **PartitionState**: Lifecycle state enum (see below).
- **PartitionType**: `Agent` (workload), `Infrastructure` (driver domain), or `Root` (bootstrap authority).
- **CoherenceScore**: Current locality metric from the coherence graph.
- **CutPressure**: Graph-derived isolation signal; high pressure triggers migration or split.
- **vCPU count and CPU affinity**: Scheduling parameters.
- **Epoch**: Creation epoch for capability staleness detection.

### Lifecycle States

```
Created --> Running --> Suspended --> Running --> Hibernated --> Created
    |          |            |            |            |
    +----------+------------+------------+----------->Destroyed
```

| State | Description |
|-------|-------------|
| `Created` | Allocated, capability table initialized, not yet scheduled |
| `Running` | Actively scheduled on physical CPU(s) |
| `Suspended` | All vCPUs paused, state preserved in-place (Hot/Warm tier) |
| `Hibernated` | State serialized to Cold storage, physical resources released |
| `Destroyed` | Resources reclaimed, ID available for reuse |

All transitions are validated by `valid_transition()` and emit witness records. Invalid transitions return `RvmError::InvalidPartitionState`.

### MAX_PARTITIONS = 256

The hard limit of 256 active physical partition slots is derived from the ARM VMID width (8 bits). Logical partitions may exceed this limit (DC-12 allows up to 4096 logical partitions); physical slots are multiplexed via TLB flush and VMID reassignment when logical count exceeds physical capacity.

### Split Semantics

Partition split divides one partition into two, triggered by high cut pressure. Preconditions:

1. Source partition must be in `Running` or `Suspended` state.
2. The coherence engine provides a scored region assignment (DC-9): each memory region is assigned to the side with higher `alpha * local_access_fraction + beta * remote_access_cost_avoided + gamma * size_penalty`.
3. Capabilities follow their target objects (DC-8): if a capability's target is on side A, it goes to partition A only. Shared targets get READ_ONLY attenuation in both, with a `CAPABILITY_ATTENUATED_ON_SPLIT` witness.
4. Two new `PartitionId` values are allocated; the original ID is destroyed.

### Merge Semantics

Partition merge combines two partitions into one. Seven preconditions must all hold (DC-11):

1. A shared `CommEdge` exists between the two partitions.
2. Mutual coherence score exceeds the merge threshold (7000 basis points default).
3. No conflicting device leases.
4. No overlapping mutable memory regions.
5. Capability intersection is valid (no escalation).
6. Both partitions are in `Running` or `Suspended` state.
7. P2 proof validates merge authority.

Failure of any precondition results in rejection plus a witness record. The `merge_preconditions_full()` function checks all seven and returns a typed `MergePreconditionError` identifying which conditions failed.

### CommEdge Model

A `CommEdge` is a weighted directed edge in the coherence graph representing inter-partition communication. Each edge carries:

- **CommEdgeId**: Unique edge identifier.
- Source and destination `PartitionId`.
- Weight (communication volume, decayed per epoch).

CommEdges are the input to the mincut algorithm. The scheduler uses cut pressure derived from these edges to boost scheduling priority (DC-4: `priority = deadline_urgency + cut_pressure_boost`).

### IPC

The `IpcManager` provides fixed-capacity message queues between partitions. Each `MessageQueue` is bounded (default 64 messages) and supports zero-copy semantics via shared memory regions. IPC messages emit `IpcSend` / `IpcReceive` witness records.

### Device Leases

A `DeviceLeaseManager` tracks time-bounded, revocable access grants to hardware devices. Each `ActiveLease` records the partition, device, expiry time, and capability used to acquire the lease. Device leases are checked during merge preconditions (condition 3) to prevent conflicts.

## Consequences

### Positive

- **Precise lifecycle** prevents invalid state transitions at compile time via exhaustive match.
- **Scored region assignment** during split avoids oscillation from hotspot access patterns.
- **Seven merge preconditions** prevent authority leaks and resource conflicts.
- **Fixed-size structures** (`MAX_PARTITIONS = 256`) enable fully stack-allocated operation in `no_std`.

### Negative

- **256 physical slots** may become a bottleneck for large agent workloads; VMID multiplexing (DC-12) adds TLB flush overhead.
- **Seven merge preconditions** are conservative; some legitimate merges may be rejected by condition 4 (overlapping regions) when the overlap is intentional shared memory.

### Neutral

- The split/merge operations are novel for a hypervisor. No existing system provides a direct comparison for performance baseline.

## References

- ADR-132: RVM Hypervisor Core (DC-8, DC-9, DC-11, DC-12)
- `crates/rvm-partition/src/lib.rs` -- Partition module root
- `crates/rvm-partition/src/partition.rs` -- Core struct and constants
- `crates/rvm-partition/src/lifecycle.rs` -- State transition validation
- `crates/rvm-partition/src/split.rs` -- Scored region assignment
- `crates/rvm-partition/src/merge.rs` -- Merge precondition checks
- `crates/rvm-partition/src/comm_edge.rs` -- CommEdge model
- `crates/rvm-partition/src/ipc.rs` -- IPC message queues
- `crates/rvm-partition/src/device.rs` -- Device lease management
