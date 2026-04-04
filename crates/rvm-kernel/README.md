# rvm-kernel

Top-level integration crate for the RVM coherence-native microhypervisor.

Wires together all 12 subsystem crates (HAL, capabilities, witness, proof,
partitions, scheduler, memory, coherence, boot, Wasm, and security) into a
single API surface. Each subsystem is re-exported as a named module. This
crate contains no logic of its own beyond the re-exports and version
constants.

## Re-exported Modules

- `kernel::types` -- `rvm-types`
- `kernel::hal` -- `rvm-hal`
- `kernel::cap` -- `rvm-cap`
- `kernel::witness` -- `rvm-witness`
- `kernel::proof` -- `rvm-proof`
- `kernel::partition` -- `rvm-partition`
- `kernel::sched` -- `rvm-sched`
- `kernel::memory` -- `rvm-memory`
- `kernel::coherence` -- `rvm-coherence`
- `kernel::boot` -- `rvm-boot`
- `kernel::wasm` -- `rvm-wasm`
- `kernel::security` -- `rvm-security`

## Constants

- `VERSION` -- crate version string (from `Cargo.toml`)
- `CRATE_COUNT` -- `13` (total subsystem crates including this one)

## Example

```rust
use rvm_kernel::{types, cap, boot, partition};

assert!(!rvm_kernel::VERSION.is_empty());
assert_eq!(rvm_kernel::CRATE_COUNT, 13);

let id = types::PartitionId::new(1);
```

## Features

- `std` -- propagates `std` to all subsystem crates
- `alloc` -- propagates `alloc` to all subsystem crates
- `wasm` -- enables WebAssembly guest support
- `coherence-sched` -- enables coherence-scheduler feedback loop

## Design Constraints

- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Workspace Dependencies

All 12 other RVM crates.
