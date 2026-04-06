# ADR-140: Agent Runtime Adapter

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

ADR-132 establishes that RVM supports WASM agent workloads as an optional execution adapter (DC-13). Agents are the primary workload type for multi-agent edge deployments: small, fast-switching, communication-heavy processes that benefit from RVM's coherence-driven partitioning.

The agent runtime must define a precise lifecycle state machine, a bounded set of host functions for kernel interaction, a migration protocol with hard time bounds, and per-partition resource quotas to prevent denial-of-service. All of this must work within the `no_std` constraint with zero heap allocation.

## Decision

### Agent Lifecycle (7 States)

```
Initializing --> Running --> Suspended --> Running
                    |            |
                    |            +--> Migrating --> Running (at destination)
                    |            |
                    |            +--> Hibernated --> Reconstructing --> Running
                    |
                    +--> Terminated
```

| State | Description | Valid Transitions |
|-------|-------------|-------------------|
| Initializing | Module loaded, being validated | Running, Terminated |
| Running | Actively executing instructions | Suspended, Terminated |
| Suspended | Paused, state preserved in-place | Running, Migrating, Hibernated, Terminated |
| Migrating | Being transferred to another partition | Running (at dest), Aborted->Suspended |
| Hibernated | State serialized to cold storage | Reconstructing, Terminated |
| Reconstructing | Being restored from hibernation | Running, Terminated |
| Terminated | Resources freed, slot available for reuse | (terminal) |

Every state transition emits a witness record. The `AgentManager<const MAX>` uses a fixed-size array of `Option<Agent>` slots; terminated agents free their slots immediately for reuse (preventing resource exhaustion).

### Agent Identity

Agents are identified by `AgentId`, a transparent wrapper around a `u32` badge value. Badges are derived from capabilities: the capability used to spawn an agent determines its badge. Duplicate active badges within a partition are rejected.

### Host Functions (13)

WASM agents interact with the kernel through a fixed set of host functions, each capability-checked before dispatch:

| Function | ID | Required Rights | Purpose |
|----------|----|----------------|---------|
| Send | 0 | WRITE | Send IPC message to another agent/partition |
| Receive | 1 | READ | Receive pending IPC message |
| Alloc | 2 | WRITE | Allocate linear memory pages |
| Free | 3 | WRITE | Free allocated memory pages |
| Spawn | 4 | EXECUTE | Spawn child agent within same partition |
| Yield | 5 | READ | Yield current execution quantum |
| GetTime | 6 | READ | Read monotonic timer (nanoseconds) |
| GetId | 7 | READ | Return caller's agent identifier |
| GpuLaunch | 8 | EXECUTE+WRITE | Submit GPU compute kernel |
| GpuAlloc | 9 | WRITE | Allocate GPU buffer memory |
| GpuFree | 10 | WRITE | Free GPU buffer memory |
| GpuTransfer | 11 | READ+WRITE | Copy between CPU and GPU buffers |
| GpuSync | 12 | READ | Wait for GPU operation completion |

GPU functions (8-12) are feature-gated behind `#[cfg(feature = "gpu")]`. When GPU is disabled, these functions return `RvmError::InternalError`.

The `dispatch_host_call()` function performs capability checking via `CapToken::has_rights()` before routing to the `HostContext` trait implementation. The `HostContext` trait is pluggable: `StubHostContext` provides default behavior for testing; production kernels implement it to connect to real IPC, memory, and GPU subsystems.

### Migration Protocol (7 Steps)

Agent migration moves a WASM agent from one partition to another. The protocol has 7 steps with a hard DC-7 time budget of 100 milliseconds:

| Step | State | Operation |
|------|-------|-----------|
| 1 | Serializing | Serialize agent state to portable format |
| 2 | PausingComms | Pause inter-partition communication for this agent |
| 3 | TransferringRegions | Transfer memory regions to destination partition |
| 4 | UpdatingEdges | Update CommEdge weights in the coherence graph |
| 5 | UpdatingGraph | Recompute coherence topology with new placement |
| 6 | Verifying | Verify state integrity at destination |
| 7 | Resuming | Resume agent execution at destination |

The `MigrationTracker` enforces:
- **Strict step ordering**: Each step advances to the next via `advance()`.
- **DC-7 timeout**: If elapsed time exceeds the deadline (100ms default), the migration aborts automatically with `RvmError::MigrationTimeout` and a witness record.
- **Self-migration rejection**: Source and destination partitions must differ; self-migration is rejected at plan creation.
- **Atomic completion**: Migration either completes all 7 steps or aborts entirely. Partial migration is not permitted.

On abort, the source partition is restored to its pre-migration state. The aborted agent is marked migration-ineligible for a cooldown period.

### Quota Management

Per-partition resource quotas prevent agent workloads from monopolizing system resources:

| Quota | Default | Scope |
|-------|---------|-------|
| CPU time | 10,000 us/epoch | Per-epoch, reset at epoch boundary |
| Memory pages | 256 (16 MiB) | Persistent across epochs |
| IPC messages | 1,024/epoch | Per-epoch, reset at epoch boundary |
| Concurrent agents | 32 | Persistent |

The `QuotaTracker<const MAX>` provides atomic `check_and_record_*` methods that eliminate TOCTOU races in the deprecated `check_quota()` + `record_usage()` two-step pattern. If a resource increment would exceed the quota, no usage is recorded and `ResourceLimitExceeded` is returned.

### WASM Module Validation

Before execution, WASM modules are validated by `validate_module()`:
- Magic number (`\0asm`) and version (1).
- Section structure: valid IDs, declared sizes fit within module, non-decreasing order (except custom sections), no duplicate non-custom sections.
- Size limit: modules cannot exceed `MAX_MODULE_SIZE` (1 MiB default) per DC-7 budget constraint.

## Consequences

### Positive

- **7-state lifecycle** covers all agent operational modes including migration and hibernation, with every transition witnessed.
- **Hard migration timeout** (DC-7) prevents unbounded migration from becoming a liveness hazard.
- **Atomic quota enforcement** eliminates a class of TOCTOU resource-exhaustion attacks.
- **Pluggable HostContext** enables testing without real kernel subsystems and future extension without modifying the dispatch path.

### Negative

- **13 host functions is a large surface**: Each function requires capability checking and witness logging. GPU functions add 5 more entry points to the TCB.
- **100ms migration timeout** may be too aggressive for partitions with large memory footprints. The timeout is configurable per partition size class but requires tuning.
- **No streaming migration**: The protocol serializes all state before transfer. Iterative pre-copy (like live VM migration) would reduce downtime but adds significant complexity.

### Neutral

- The WASM interpreter itself is not specified in this ADR. The runtime is pluggable via the `HostContext` trait; a `wasmtime`-based or custom interpreter can be swapped without changing the lifecycle or host function model.

## References

- ADR-132: RVM Hypervisor Core (DC-7, DC-13, DC-14)
- ADR-133: Partition Object Model (partition state machine)
- ADR-134: Witness Schema (TaskSpawn, TaskTerminate, PartitionMigrate action kinds)
- ADR-144: GPU Compute Support (GpuLaunch through GpuSync)
- `crates/rvm-wasm/src/lib.rs` -- Module root, WASM validation
- `crates/rvm-wasm/src/agent.rs` -- AgentManager and lifecycle
- `crates/rvm-wasm/src/host_functions.rs` -- Host function dispatch
- `crates/rvm-wasm/src/migration.rs` -- 7-step migration protocol
- `crates/rvm-wasm/src/quota.rs` -- QuotaTracker and resource budgets
