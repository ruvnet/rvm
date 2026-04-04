# rvm-witness

Append-only witness trail with FNV-1a hash-chain integrity.

Implements ADR-134: every privileged action emits a 64-byte witness record
before the mutation is committed. If emission fails, the mutation does not
proceed ("no witness, no mutation"). Records are stored in a fixed-capacity
ring buffer and linked by a hash chain for tamper-evident auditing.

## Record Layout (64 bytes, cache-line aligned)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | sequence (u64) |
| 8 | 8 | timestamp_ns (u64) |
| 16 | 1 | action_kind (u8) |
| 17 | 1 | proof_tier (u8) |
| 18 | 2 | flags (u16) |
| 20 | 4 | actor_partition_id (u32) |
| 24 | 4 | target_object_id (u32) |
| 28 | 4 | capability_hash (u32) |
| 32 | 8 | payload (u64) |
| 40 | 8 | prev_hash (u64) |
| 48 | 8 | record_hash (u64) |
| 56 | 8 | aux (u64) |

## Key Types

- `WitnessLog<N>` -- generic ring buffer of capacity `N` records
- `WitnessEmitter` -- builds records with auto-incrementing sequence and hash chain
- `WitnessRecord`, `ActionKind` -- the 64-byte record and action discriminant
- `WitnessSigner`, `NullSigner` -- pluggable record signing trait
- `verify_chain` -- verify hash-chain integrity of a record slice
- `ChainIntegrityError` -- error returned on chain verification failure
- `fnv1a_64`, `compute_record_hash`, `compute_chain_hash` -- hash utilities

## Example

```rust
use rvm_witness::{WitnessEmitter, WitnessLog};
use rvm_types::ActionKind;

let mut emitter = WitnessEmitter::new();
let record = emitter.emit(ActionKind::PartitionCreate, 1, 100, 1_000_000);

let mut log = WitnessLog::<256>::new();
log.append(record);
assert_eq!(log.len(), 1);
```

## Design Constraints

- **DC-10**: Epoch-based witness batching (no per-switch records)
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-134: record is exactly 64 bytes; FNV-1a hash chain

## Workspace Dependencies

- `rvm-types`
- `spin`
