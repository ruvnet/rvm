# rvm-tests

Cross-crate integration tests for the RVM microhypervisor.

This crate exercises the public APIs of all 13 RVM subsystem crates in
combination. It is not published and exists solely for `cargo test`
validation of the workspace.

## What is Tested

- `PartitionId` round-trip and VMID extraction
- `CoherenceScore` clamping and threshold checks
- `WitnessHash` zero detection
- `WitnessRecord` size assertion (must be exactly 64 bytes)
- `CapToken` rights checking (single and combined rights)
- `GuestPhysAddr` / `PhysAddr` page alignment helpers
- `BootTracker` sequential phase completion and out-of-order rejection
- `WasmModuleInfo` header validation (magic, version, truncated input)
- `GateRequest` security enforcement (type match and mismatch)
- `WitnessLog` append and length tracking
- `WitnessEmitter` record construction with action kind and actor
- `EmaFilter` initial sample pass-through and EMA computation
- `PartitionManager` create and lookup
- `rvm-kernel` version and crate count constants
- `ActionKind` subsystem discriminant
- `fnv1a_64` determinism

## Running

```bash
cargo test -p rvm-tests
```

## Workspace Dependencies

All 13 RVM crates (rvm-types through rvm-kernel).
