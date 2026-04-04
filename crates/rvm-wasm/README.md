# rvm-wasm

Optional WebAssembly guest runtime for RVM partitions.

When enabled, partitions can host Wasm modules as an alternative to native
AArch64/RISC-V/x86-64 guests. Wasm modules execute in a sandboxed
interpreter, host functions are exposed through the capability system, and
all state transitions are witness-logged. This crate is compile-time
optional; disabling it removes all Wasm code from the final binary.

## Key Types and Functions

- `WasmModuleState` -- lifecycle: `Loaded`, `Validated`, `Running`, `Terminated`
- `WasmModuleInfo` -- module metadata: partition, state, size, export/import counts
- `validate_header(bytes)` -- checks the 8-byte Wasm preamble (magic + version 1)
- `MAX_MODULE_SIZE` -- maximum module size (1 MiB default)

## Example

```rust
use rvm_wasm::{validate_header, WasmModuleState};

let wasm_bytes = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
assert!(validate_header(&wasm_bytes).is_ok());

let bad_magic = [0xFF; 8];
assert!(validate_header(&bad_magic).is_err());
```

## Design Constraints

- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Capability-gated host function exposure
- Witness-logged state transitions

## Workspace Dependencies

- `rvm-types`
- `rvm-partition`
- `rvm-cap`
- `rvm-witness`
