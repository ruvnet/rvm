# rvm-types

Foundation types for the RVM coherence-native microhypervisor.

This crate defines the type vocabulary shared by all RVM crates: addresses,
identifiers, capabilities, witness records, coherence scores, and error types.
It has zero external dependencies beyond `bitflags` and compiles under `no_std`
with no heap allocation in the default configuration.

## Key Types

- `PartitionId`, `VcpuId` -- newtype identifiers (`Copy + Eq`)
- `PhysAddr`, `GuestPhysAddr`, `VirtAddr` -- address types with alignment helpers
- `Capability`, `CapToken`, `CapRights`, `CapType` -- unforgeable authority tokens
- `WitnessRecord` -- 64-byte, cache-line-aligned audit record
- `WitnessHash` -- 32-byte hash used in witness chains
- `CoherenceScore`, `CutPressure`, `PhiValue` -- fixed-point coherence metrics
- `MemoryRegion`, `MemoryTier`, `RegionPolicy` -- typed memory descriptors
- `CommEdge`, `CommEdgeId` -- inter-partition communication edges
- `DeviceLease`, `DeviceClass` -- time-bounded device access grants
- `ProofTier`, `ProofToken`, `ProofResult` -- proof system primitives
- `PartitionConfig`, `PartitionState`, `PartitionType` -- partition descriptors
- `EpochConfig`, `EpochSummary`, `Priority`, `SchedulerMode` -- scheduler types
- `FailureClass`, `RecoveryCheckpoint` -- fault recovery types
- `RvmError`, `RvmResult` -- unified error type
- `RvmConfig` -- system-wide configuration

## Example

```rust
use rvm_types::{PartitionId, CoherenceScore, CapToken, CapType, CapRights};

let id = PartitionId::new(42);
assert_eq!(id.vmid(), 42); // VMID for hardware

let score = CoherenceScore::from_basis_points(7500); // 75%
assert!(score.is_coherent());

let token = CapToken::new(1, CapType::Partition, CapRights::READ, 0);
assert!(token.has_rights(CapRights::READ));
```

## Design Constraints

- **DC-3**: Capabilities are unforgeable, monotonically attenuated
- **DC-9**: Coherence score range [0.0, 1.0] as fixed-point basis points
- **DC-12**: Max 256 physical VMIDs (8-bit VMID from `PartitionId`)
- **DC-14**: Failure classes: transient, recoverable, permanent, catastrophic
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Workspace Dependencies

None (leaf crate). Only depends on `bitflags`.
