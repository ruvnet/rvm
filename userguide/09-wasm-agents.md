# WebAssembly Agents: Running Code in Partitions

RVM partitions can host WebAssembly modules as an alternative to native AArch64 guests. WASM support is optional and compile-time gated: when disabled, all WASM-related code is excluded from the binary entirely.

This chapter covers module loading and validation, the agent lifecycle, host function dispatch, resource quotas, and the migration protocol.

---

## 1. What Is WASM in RVM?

RVM does not include a full WASM runtime with JIT compilation. Instead, it provides the infrastructure for executing WASM modules inside a sandboxed interpreter within a partition. The key properties:

- **Optional feature.** The `rvm-wasm` crate is compiled into the kernel workspace by default, but all its code is behind `#![no_std]` and `#![forbid(unsafe_code)]`. On a bare-metal deployment where WASM is not needed, it can be excluded from the final binary.

- **Sandboxed execution.** WASM modules run within a partition's memory region. They cannot access memory outside their partition. They cannot make system calls. Their only interface to the hypervisor is through a fixed set of host functions.

- **Capability-gated host functions.** Every host function call is checked against the calling agent's capability token before dispatch. An agent without `WRITE` rights cannot call `Send`. An agent without `EXECUTE` rights cannot call `Spawn`. See section 5 for the full mapping.

- **Witness-logged state transitions.** Every agent lifecycle event (spawn, suspend, resume, terminate, migrate) emits a witness record before the mutation commits. See [Witness and Audit](06-witness-audit.md).

- **Size limit.** `MAX_MODULE_SIZE = 1,048,576` bytes (1 MiB). Modules larger than this are rejected at validation time.

## 2. Module Lifecycle

A WASM module within a partition progresses through four states, defined by `WasmModuleState`:

```
  Loaded  --->  Validated  --->  Running  --->  Terminated
```

| State | Meaning |
|-------|---------|
| `Loaded` | The module bytes have been received but not yet checked |
| `Validated` | The module has passed structural validation and is ready to execute |
| `Running` | The module is actively executing instructions |
| `Terminated` | The module has been shut down and its resources freed |

**`WasmModuleInfo`** tracks metadata for a loaded module:

```rust
pub struct WasmModuleInfo {
    pub partition: PartitionId,    // hosting partition
    pub state: WasmModuleState,
    pub size_bytes: u32,
    pub export_count: u16,         // number of exported functions
    pub import_count: u16,         // number of imported (host) functions
}
```

## 3. Module Validation

`validate_module()` in `rvm-wasm/src/lib.rs` performs structural validation on WASM binary data. It checks four things:

**Step 1: Header check.** The first 8 bytes must be the WASM magic number and version:

```
Bytes 0-3:  0x00 0x61 0x73 0x6D   (\0asm)
Bytes 4-7:  0x01 0x00 0x00 0x00   (version 1)
```

**Step 2: Size check.** The total module size must not exceed `MAX_MODULE_SIZE` (1 MiB).

**Step 3: Section validation.** After the 8-byte header, the validator walks through each section:

- Each section has a 1-byte ID followed by an LEB128-encoded `u32` size
- The section ID must be a valid `WasmSectionId` (0 through 12)
- The declared size must fit within the remaining module bytes

**Step 4: Ordering and uniqueness.** Non-custom section IDs must appear in strictly increasing order. No non-custom section may appear twice. Custom sections (ID 0) may appear anywhere and may repeat.

The 13 recognized section types (`WasmSectionId`):

| ID | Name | Content |
|----|------|---------|
| 0 | Custom | Name + opaque data (can appear multiple times) |
| 1 | Type | Function signatures |
| 2 | Import | Imported functions, tables, memories, globals |
| 3 | Function | Type indices for defined functions |
| 4 | Table | Table definitions |
| 5 | Memory | Memory definitions |
| 6 | Global | Global variable definitions |
| 7 | Export | Exported functions, tables, memories, globals |
| 8 | Start | Index of the start function |
| 9 | Element | Table initialization data |
| 10 | Code | Function bodies |
| 11 | Data | Data segment initialization |
| 12 | DataCount | Number of data segments (bulk memory proposal) |

On success, `validate_module()` returns a `WasmValidationResult`:

```rust
pub struct WasmValidationResult {
    pub section_count: u16,
    pub has_type: bool,
    pub has_function: bool,
    pub has_memory: bool,
    pub has_export: bool,
    pub has_code: bool,
    pub total_payload_bytes: u32,
}
```

This tells the caller which sections are present without requiring a second pass. LEB128 decoding rejects non-canonical (over-long) encodings: on the 5th byte of a `u32`, only the low 4 bits may be set.

## 4. Agent Lifecycle

WASM agents have a 7-state lifecycle defined in `rvm-wasm/src/agent.rs`, governed by ADR-140:

```
                    +---------------+
                    | Initializing  |
                    +-------+-------+
                            |
                   activate |
                            v
                    +-------+-------+
            +------>|    Running    |<------+
            |       +---+---+---+--+       |
            |           |   |   |          |
      resume|  suspend  |   |   | terminate
            |           v   |   |
            |   +-------+-+ |   |
            +---| Suspended | |   |
                +-------+-+ |   |
                        |   |   |
               hibernate|   |   |
                        v   |   v
              +---------+-+ | +-+----------+
              | Hibernated| | | Terminated |
              +-----+-----+ | +------------+
                    |        |
          reconstruct|       | migrate
                    v        v
          +---------+--+ +---+-------+
          |Reconstructing| | Migrating |
          +-----+------+ +-----+-----+
                |               |
       activate |       complete|
                v               v
            Running          Running (at dest)
```

The seven states (`AgentState`):

| State | Meaning |
|-------|---------|
| `Initializing` | Agent is being set up (module loading, validation) |
| `Running` | Agent is actively executing instructions |
| `Suspended` | Execution is paused; state is preserved in-place |
| `Migrating` | Agent is being transferred to another partition (see section 6) |
| `Hibernated` | Agent state has been serialized to cold storage |
| `Reconstructing` | Agent is being restored from a hibernation snapshot |
| `Terminated` | Agent has been shut down and resources freed |

**`AgentManager<MAX>`** manages agents within a partition. Key operations:

| Operation | From State | To State | Witness Event |
|-----------|-----------|----------|---------------|
| `spawn(config, witness_log)` | -- | Initializing | `TaskSpawn` |
| `activate(id)` | Initializing or Reconstructing | Running | -- |
| `suspend(id, witness_log)` | Running | Suspended | `PartitionSuspend` |
| `resume(id, witness_log)` | Suspended | Running | `PartitionResume` |
| `terminate(id, witness_log)` | Any non-terminated | Terminated | `TaskTerminate` |

Each agent is identified by an `AgentId` derived from a capability badge (`AgentId::from_badge(badge)`). Duplicate badges are rejected. When an agent is terminated, its slot is freed for reuse -- without this, terminated agents would permanently occupy slots and eventually exhaust the capacity.

**`AgentConfig`** specifies how to spawn an agent:

```rust
pub struct AgentConfig {
    pub badge: u32,                // badge value -> AgentId
    pub partition_id: PartitionId, // hosting partition
    pub max_memory_pages: u32,     // memory budget
}
```

## 5. Host Functions

WASM agents interact with the hypervisor through a fixed set of 8 host functions, defined in `rvm-wasm/src/host_functions.rs`. Every call is capability-checked before dispatch.

**The host function table:**

| Function | ID | Description | Required Rights |
|----------|----|-------------|----------------|
| `Send` | 0 | Send a message to another agent or partition | `WRITE` |
| `Receive` | 1 | Receive a pending message | `READ` |
| `Alloc` | 2 | Allocate linear memory pages | `WRITE` |
| `Free` | 3 | Free previously allocated pages | `WRITE` |
| `Spawn` | 4 | Spawn a child agent in the same partition | `EXECUTE` |
| `Yield` | 5 | Yield the current execution quantum | `READ` |
| `GetTime` | 6 | Read the monotonic timer (nanoseconds) | `READ` |
| `GetId` | 7 | Return the caller's agent identifier | `READ` |

If the agent's capability token does not include the required rights, the call returns `InsufficientCapability` immediately.

**Dispatch flow:**

```rust
let result = dispatch_host_call(
    agent_id,       // who is calling
    function,       // which host function
    &args,          // up to 3 u64 arguments
    &cap_token,     // the agent's capability token
    &mut host_ctx,  // the kernel's HostContext implementation
);
```

The `HostContext` trait connects host function dispatch to real kernel subsystems. Implement it on your kernel struct to wire up IPC, memory allocation, and scheduling. A `StubHostContext` is provided for testing.

**`HostCallResult`** is either `Success(u64)` or `Error(RvmError)`:

```rust
match result {
    HostCallResult::Success(value) => { /* use value */ }
    HostCallResult::Error(err) => { /* handle error */ }
}
```

The capability check is the first thing that happens in `dispatch_host_call()`. No kernel subsystem is touched until the caller's rights have been verified. This is a defense-in-depth measure: even if a WASM module has a bug that constructs an invalid function call, the capability gate stops it.

## 6. Migration

WASM agents can be migrated between partitions to optimize coherence. The migration protocol has 7 steps, defined in `rvm-wasm/src/migration.rs`:

| Step | State | What Happens |
|------|-------|-------------|
| 1 | Serializing | Agent state is serialized to a portable format |
| 2 | PausingComms | Inter-partition communication is paused |
| 3 | TransferringRegions | Memory regions are transferred to the destination partition |
| 4 | UpdatingEdges | Communication edges in the coherence graph are updated |
| 5 | UpdatingGraph | The coherence graph topology is updated |
| 6 | Verifying | State integrity is verified at the destination |
| 7 | Resuming | The agent resumes execution at the destination |

After step 7, the state becomes `Complete`. If any step fails or the total time exceeds the deadline, the state becomes `Aborted`.

**DC-7 timeout:** `MIGRATION_TIMEOUT_NS = 100,000,000` (100 ms). Every call to `advance()` checks the elapsed time. If the migration has been running longer than the deadline, it is automatically aborted with `MigrationTimeout` and a witness record is emitted.

**`MigrationPlan`** describes a planned migration:

```rust
pub struct MigrationPlan {
    pub agent_id: AgentId,
    pub source_partition: PartitionId,
    pub dest_partition: PartitionId,
    pub deadline_ns: u64,          // defaults to MIGRATION_TIMEOUT_NS
}
```

Migrating a partition to itself is rejected at `begin()` time -- it is a no-op that would corrupt coherence edges.

**`MigrationTracker`** tracks progress:

```rust
let mut tracker = MigrationTracker::begin(plan, now_ns)?;

// Advance through each step, passing the current timestamp
loop {
    match tracker.advance(now_ns, &witness_log) {
        Ok(MigrationState::Complete) => break,
        Ok(_) => continue,
        Err(RvmError::MigrationTimeout) => { /* handle timeout */ }
        Err(e) => { /* handle other error */ }
    }
}
```

A completion witness record (`PartitionMigrate`) is emitted when the migration reaches the `Complete` state. A timeout witness record (`MigrationTimeout`) is emitted on abort.

## 7. Resource Quotas

`QuotaTracker` in `rvm-wasm/src/quota.rs` enforces per-partition resource budgets. Each partition running WASM agents is subject to four limits:

**`PartitionQuota`** defines the budget:

```rust
pub struct PartitionQuota {
    pub max_cpu_us_per_epoch: u64,   // CPU microseconds per scheduler epoch
    pub max_memory_pages: u32,       // WASM linear memory pages (64 KiB each)
    pub max_ipc_per_epoch: u32,      // IPC messages per epoch
    pub max_agents: u16,             // concurrent agents
}
```

The defaults:

| Resource | Default Limit |
|----------|--------------|
| CPU time per epoch | 10,000 us (10 ms) |
| Memory pages | 256 (16 MiB) |
| IPC messages per epoch | 1,024 |
| Concurrent agents | 32 |

**Atomic check-and-record:** The quota tracker provides three atomic methods that check the budget and record usage in a single step:

- `check_and_record_cpu(partition, us)` -- check and record CPU microseconds
- `check_and_record_memory(partition, pages)` -- check and record memory pages
- `check_and_record_ipc(partition)` -- check and record one IPC message

These replace the older `check_quota()` + `record_usage()` two-step pattern, which was vulnerable to TOCTOU (time-of-check-to-time-of-use) races: a concurrent caller could pass the check before either caller recorded its usage. The atomic methods eliminate this race.

If the requested amount would exceed the quota, no usage is recorded and `ResourceLimitExceeded` is returned.

**`ResourceUsage`** tracks current consumption:

```rust
pub struct ResourceUsage {
    pub cpu_us: u64,          // CPU microseconds consumed this epoch
    pub memory_pages: u32,    // pages currently allocated
    pub ipc_count: u32,       // IPC messages sent this epoch
    pub agent_count: u16,     // currently active agents
}
```

**Epoch reset:** At the start of each scheduler epoch, call `reset_epoch_counters()` to zero out the per-epoch counters (CPU and IPC). Memory usage is persistent across epochs since memory is not reclaimed at epoch boundaries.

**Enforcement:** `enforce_quota(partition)` returns `true` if the partition is over budget on any dimension. When a partition exceeds its budget, the kernel can terminate the lowest-priority agent to bring usage back under control.

## 8. Enabling WASM

The `rvm-wasm` crate is included in the workspace by default. To use it in a custom kernel build, add it as a dependency:

```toml
[dependencies]
rvm-wasm = { path = "crates/rvm-wasm" }
```

For bare-metal builds, the crate works under `#![no_std]`. Enable `alloc` or `std` features for host testing:

```toml
rvm-wasm = { path = "crates/rvm-wasm", features = ["std"] }
```

When you do not need WASM support, simply omit `rvm-wasm` from your dependency list. Since the crate is a separate compilation unit, excluding it removes all WASM code from the final binary.

For how feature flags work across the entire crate tree, see [Architecture: Feature Flags](03-architecture.md). For bare-metal deployment considerations when choosing which optional crates to include, see [Bare Metal](12-bare-metal.md).

---

## Cross-References

| Topic | Chapter |
|-------|---------|
| Partitions that host WASM agents | [Partitions and Scheduling](07-partitions-scheduling.md) |
| Capability tokens used for host function gating | [Capabilities and Proofs](05-capabilities-proofs.md) |
| Witness records emitted by agent lifecycle events | [Witness and Audit](06-witness-audit.md) |
| Memory regions and tier placement for agent data | [Memory Model](08-memory-model.md) |
| Security gate and attestation for WASM modules | [Security](10-security.md) |
| Coherence graph that drives migration decisions | [Core Concepts](02-core-concepts.md) |
| Architecture and crate dependency graph | [Architecture](03-architecture.md) |
| Bare-metal deployment with/without WASM | [Bare Metal](12-bare-metal.md) |
| Benchmark results for WASM validation | [Performance](11-performance.md) |
| Full API reference for `rvm-wasm` | [Crate Reference](04-crate-reference.md) |
