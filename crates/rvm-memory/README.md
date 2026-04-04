# rvm-memory

Guest physical address space management for the RVM microhypervisor.

Provides safe abstractions over stage-2 page table mappings with
capability-gated access. Each partition has an independent guest physical
address space. All mapping operations are recorded in the witness trail.
Memory regions can be shared between partitions with explicit grants.

## Key Types and Functions

- `MemoryRegion` -- descriptor: guest base, host base, page count, permissions, owner
- `MemoryPermissions` -- RWX permission flags with constants (`READ_ONLY`, `READ_WRITE`, `READ_EXECUTE`)
- `validate_region(region)` -- checks alignment, page count, and permission validity
- `regions_overlap(a, b)` -- detects overlapping regions within the same partition
- `PAGE_SIZE` -- 4 KiB page size constant

## Example

```rust
use rvm_memory::{MemoryRegion, MemoryPermissions, validate_region, PAGE_SIZE};
use rvm_types::{GuestPhysAddr, PhysAddr, PartitionId};

let region = MemoryRegion {
    guest_base: GuestPhysAddr::new(0x8000_0000),
    host_base: PhysAddr::new(0x4000_0000),
    page_count: 16,
    permissions: MemoryPermissions::READ_WRITE,
    owner: PartitionId::new(1),
};
assert!(validate_region(&region).is_ok());
```

## Design Constraints

- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-138: capability-gated mappings; witness-logged operations

## Workspace Dependencies

- `rvm-types`
- `rvm-hal`
- `rvm-partition`
- `rvm-witness`
