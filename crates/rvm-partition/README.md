# rvm-partition

Partition lifecycle, isolation, and coherence domain management.

A partition is **not** a VM. It has no emulated hardware, no guest BIOS, and
no virtual device model. A partition is a container for a scoped capability
table, communication edges to other partitions, coherence metrics, and CPU
affinity. Partitions are the unit of scheduling, isolation, migration, and
fault containment. Every lifecycle transition emits a witness record.

## Key Types

- `Partition` -- the partition object: state, type, coherence, capability table, edges
- `PartitionManager` -- create, destroy, lookup partitions (max 256 per instance)
- `PartitionState` -- lifecycle states (e.g., `Created`, `Running`, `Suspended`)
- `PartitionType` -- classification (e.g., `Agent`, `Service`)
- `CapabilityTable` -- per-partition capability slot table
- `CommEdge`, `CommEdgeId` -- inter-partition communication edges
- `PartitionOps`, `PartitionConfig`, `SplitConfig` -- lifecycle operations
- `valid_transition` -- validates state machine transitions
- `merge_preconditions_met` -- checks merge eligibility (coherence threshold)
- `scored_region_assignment` -- heuristic region assignment during split
- `CutPressureLocal` -- local cut-pressure accumulator

## Example

```rust
use rvm_partition::{PartitionManager, PartitionType};

let mut mgr = PartitionManager::new();
let id = mgr.create(PartitionType::Agent, 2, 1).unwrap();
assert_eq!(mgr.count(), 1);
assert!(mgr.get(id).is_some());
```

## Design Constraints

- **DC-1**: Coherence engine is optional; partition model works without it
- **DC-8**: Capabilities follow objects during partition split (type only)
- **DC-11**: Merge requires coherence above threshold
- **DC-12**: Max 256 physical VMIDs
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-133: partition switch target < 10 us

## Workspace Dependencies

- `rvm-types`
- `rvm-cap`
- `rvm-witness`
- `spin`
