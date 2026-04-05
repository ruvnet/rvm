# Crate Reference: All 13 RVM Crates

This chapter provides a concise reference for every crate in the RVM workspace.
Each section describes what the crate does, lists its key public types, notes
its feature flags and internal dependencies, and points to the chapter with
deeper coverage.

For the big picture of how these crates fit together, see
[Architecture](03-architecture.md). For a quick setup guide, see
[Quickstart](01-quickstart.md).

---

## 1. rvm-types

**Foundation types for the entire hypervisor.**

`rvm-types` defines every shared type used across the workspace. It has no
dependencies on other RVM crates and only one external dependency (`bitflags`),
making it the stable foundation that all other crates build on. If you are
reading RVM source code for the first time, start here.

**Key public types:**

- `PartitionId` -- 16-bit identifier for a partition
- `VcpuId` -- virtual CPU identifier
- `CapRights`, `CapToken`, `CapType`, `Capability`, `CapabilityId` -- capability model primitives
- `WitnessHash`, `WitnessRecord`, `ActionKind` -- witness trail types
- `CoherenceScore`, `CommEdge`, `CutPressure`, `PhiValue` -- coherence monitoring types
- `PartitionConfig`, `PartitionState` -- partition lifecycle types
- `MemoryRegion`, `MemoryTier` -- memory model types
- `DeviceLease` -- device assignment type
- `ProofResult`, `ProofTier`, `ProofToken` -- proof engine types
- `Priority`, `SchedulerMode` -- scheduling types
- `FailureClass`, `RecoveryCheckpoint` -- fault recovery types
- `RvmConfig` -- top-level configuration
- `RvmError`, `RvmResult` -- error handling

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** None (only `bitflags`)

**See also:** [Core Concepts](02-core-concepts.md) for how these types model
the hypervisor's domain, [Glossary](15-glossary.md) for definitions.

---

## 2. rvm-hal

**Hardware abstraction layer.**

`rvm-hal` defines the trait boundaries between RVM and the underlying hardware
platform. It does not contain any hardware-specific code itself; instead, it
specifies what a platform implementation must provide. A bare-metal deployment
supplies a concrete implementation of these traits; the test suite uses stubs.

**Key public traits:**

- `Platform` -- top-level platform trait: `cpu_count()`, `total_memory()`, `halt()`
- `MmuOps` -- memory management unit: `map_page()`, `unmap_page()`, `translate()`, `flush_tlb()`
- `TimerOps` -- timer access: `now_ns()`, `set_deadline_ns()`, `cancel_deadline()`
- `InterruptOps` -- interrupt controller: `enable()`, `disable()`, `acknowledge()`, `end_of_interrupt()`

**Modules:**

- `aarch64` -- type stubs for AArch64 bare-metal targets

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** `rvm-types`

**See also:** [Bare-Metal Deployment](12-bare-metal.md) for writing a HAL
implementation, [Architecture](03-architecture.md) for where `rvm-hal` sits in
the dependency tree.

---

## 3. rvm-cap

**Capability-based access control.**

`rvm-cap` manages the capability tables that control which partitions can
access which resources. Capabilities form a derivation tree: a parent
capability can delegate a subset of its rights to a child, up to a configurable
maximum delegation depth. Revocation cascades from parent to all descendants.

**Key public types and functions:**

- `CapabilityManager` -- top-level manager for creating, delegating, and revoking capabilities
- `CapabilityTable` -- per-partition table mapping `CapabilityId` to `Capability`
- `DerivationTree` -- tracks parent-child relationships for cascading revocation
- `ProofVerifier` -- verifies proof tokens against capability state
- `GrantPolicy` -- policy for whether a delegation request should be allowed
- `revoke_single()` -- revoke a single capability and its descendants

**Constants:**

- `DEFAULT_MAX_DELEGATION_DEPTH` = 8
- `DEFAULT_CAP_TABLE_CAPACITY` = 256

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** `rvm-types`, `spin`

**See also:** [Capabilities and Proofs](05-capabilities-proofs.md) for the
full capability model, [Security](10-security.md) for hardening guidance.

---

## 4. rvm-witness

**Tamper-evident witness logging.**

`rvm-witness` maintains an append-only ring buffer of `WitnessRecord` entries.
Every security decision, partition lifecycle event, and state transition is
logged here. Records are cryptographically signed (when the `crypto-sha256`
feature is enabled) and can be chained to detect tampering.

**Key public types and functions:**

- `WitnessEmitter` -- emits new witness records into the log
- `WitnessLog` -- the ring buffer holding all records
- `WitnessRecord` -- a single audit entry: partition, action, timestamp, signature
- `verify_chain()` -- verify the cryptographic integrity of a range of records
- `query_by_partition()` -- filter records by partition ID
- `query_by_action_kind()` -- filter records by action type
- `query_by_time_range()` -- filter records by timestamp range

**Signers:**

- `DefaultSigner` -- HMAC-SHA256 signer (requires `crypto-sha256`)
- `StrictSigner` -- enforces non-null signatures (default behavior with `strict-signing`)
- `HmacWitnessSigner` -- explicit HMAC-based signer for witness records

**Constants:**

- `DEFAULT_RING_CAPACITY` = 262,144 entries

**Feature flags:** `std`, `alloc`, `crypto-sha256` (on by default),
`strict-signing` (on by default), `null-signer` (off -- testing only)

**Workspace dependencies:** `rvm-types`, `spin`, optionally `sha2` and `hmac`

**See also:** [Witness and Audit](06-witness-audit.md) for querying and
verifying the witness trail, [Security](10-security.md) for why
`null-signer` should never be used in production.

---

## 5. rvm-proof

**Proof-gated state transitions.**

`rvm-proof` ensures that every state-mutating operation in the hypervisor is
backed by a verifiable proof. Proofs operate at three tiers of increasing
strength. The crate also provides software TEE (Trusted Execution Environment)
support for environments that lack hardware TEE.

**Key public types and functions:**

- `ProofTier` -- the three proof tiers: `Hash`, `Witness`, `Zk`
- `Proof` -- a proof object containing tier, data hash, and optional signature
- `verify()` -- verify a standalone proof
- `verify_with_cap()` -- verify a proof in the context of a capability
- `compute_data_hash()` -- compute the SHA-256 hash of a data buffer

**TEE support:**

- `SoftwareTeeProvider` -- software-emulated TEE for development and testing
- `SoftwareTeeVerifier` -- verifies attestations from the software TEE
- `TeeWitnessSigner` -- signs witness records using TEE-derived keys

**Modules:**

- `policy` -- proof policy engine with a context builder for constructing policy decisions

**Feature flags:** `std`, `alloc`, `crypto-sha256` (on by default),
`ed25519` (off -- adds Ed25519 signature support via `ed25519-dalek`),
`strict-signing` (on by default), `null-signer` (off -- testing only)

**Workspace dependencies:** `rvm-types`, `rvm-cap`, `rvm-witness`, `spin`,
`subtle`, optionally `sha2`, `hmac`, `ed25519-dalek`

**See also:** [Capabilities and Proofs](05-capabilities-proofs.md) for proof
tiers and verification flow, [Security](10-security.md) for TEE attestation
guidance.

---

## 6. rvm-partition

**Partition lifecycle and communication.**

`rvm-partition` defines the partition -- the fundamental isolation boundary in
RVM. A partition owns a set of memory regions, capabilities, virtual CPUs, and
device leases. This crate also manages inter-partition communication (IPC) via
message queues and scored region assignment for partition split and merge.

**Key public types:**

- `PartitionManager` -- creates, destroys, and queries partitions
- `Partition` -- the partition object itself
- `CapabilityTable` -- per-partition capability storage (delegated from `rvm-cap`)
- `CommEdge` -- a communication edge between two partitions in the coherence graph
- `IpcManager` -- manages IPC channels between partitions
- `MessageQueue` -- bounded message queue for inter-partition messages
- `DeviceLeaseManager` -- assigns and revokes device leases to partitions

**Operations:**

- Split: `scored_region_assignment()` -- assigns memory regions to child partitions based on scoring
- Merge: `merge_preconditions_met()` -- checks whether two partitions can be safely merged

**Constants:**

- `MAX_PARTITIONS` = 256

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** `rvm-types`, `rvm-cap`, `rvm-witness`, `spin`

**See also:** [Partitions and Scheduling](07-partitions-scheduling.md) for the
full partition lifecycle, [Memory Model](08-memory-model.md) for how partitions
own memory regions.

---

## 7. rvm-sched

**Coherence-aware scheduler.**

`rvm-sched` assigns virtual CPUs to physical CPUs. It supports three
scheduling modes that adapt to the current system state. When the `coherence`
feature is enabled at the kernel level, the scheduler can receive coherence
feedback to prioritize partitions that contribute to overall system coherence.

**Key public types and functions:**

- `Scheduler` -- the top-level scheduler interface
- `PerCpuScheduler` -- per-physical-CPU run queue and dispatch logic
- `SmpCoordinator` -- coordinates scheduling decisions across multiple CPUs
- `EpochTracker` -- tracks scheduling epochs for fairness and starvation prevention
- `SchedulerMode` -- the three modes: `Reflex` (low-latency), `Flow` (throughput), `Recovery` (fault handling)
- `compute_priority()` -- compute the effective priority for a partition based on base priority, coherence score, and mode
- `partition_switch()` -- perform a context switch between partitions

**Context switch types:**

- `SwitchContext` -- captures the state needed for a partition switch
- `SwitchResult` -- the outcome of a switch attempt

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** `rvm-types`, `rvm-partition`, `rvm-witness`, `spin`

**See also:** [Partitions and Scheduling](07-partitions-scheduling.md) for
scheduling modes and priority computation,
[Performance](11-performance.md) for tuning scheduler parameters.

---

## 8. rvm-memory

**Memory management and address spaces.**

`rvm-memory` manages physical memory allocation and guest physical address
spaces. It provides a buddy allocator for page-level allocation, a region
manager for tracking which memory regions belong to which partitions, and a
tiered memory system that classifies memory by access frequency.

**Key public types and functions:**

- `BuddyAllocator` -- power-of-two page allocator
- `TierManager` -- classifies memory regions into four tiers: `Hot`, `Warm`, `Dormant`, `Cold`
- `RegionManager` -- tracks ownership and permissions of memory regions
- `ReconstructionPipeline` -- reconstructs memory state after a partition crash or migration
- `MemoryRegion` -- describes a contiguous range of physical memory
- `MemoryPermissions` -- read/write/execute permission flags
- `validate_region()` -- checks that a memory region is well-formed
- `regions_overlap()` -- checks whether two guest regions overlap
- `regions_overlap_host()` -- checks whether a guest region overlaps a host-reserved range

**Constants:**

- `PAGE_SIZE` = 4096 bytes

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** `rvm-types`

**See also:** [Memory Model](08-memory-model.md) for the full memory
architecture, [Bare-Metal Deployment](12-bare-metal.md) for physical memory
layout on real hardware.

---

## 9. rvm-coherence

**Coherence monitoring and Phi computation.**

`rvm-coherence` implements the coherence monitoring engine that distinguishes
RVM from traditional hypervisors. It models the partition communication
topology as a graph and computes coherence metrics inspired by Integrated
Information Theory (IIT). These metrics can feed back into the scheduler to
prioritize partitions that contribute to system-wide coherence.

**Key public types and functions:**

- `CoherenceGraph` -- a graph of partitions connected by communication edges
- `EmaFilter` -- exponential moving average filter for smoothing sensor readings
- `MinCutBridge` -- computes the minimum cut of the coherence graph using a Stoer-Wagner heuristic
- `CoherenceEngine` -- computes coherence scores from the graph topology
- `AdaptiveCoherenceEngine` -- extends `CoherenceEngine` with adaptive thresholds and hysteresis
- `SensorReading` -- a raw coherence measurement from a partition pair
- `phi_to_coherence_bp()` -- converts a raw Phi value to a coherence score in basis points

**Feature flags:** `std`, `alloc`, `sched` (enables scheduler integration via
`rvm-sched`), `ruvector` (enables bridge to external ruvector crates)

**Workspace dependencies:** `rvm-types`, `rvm-partition`, optionally `rvm-sched`

**See also:** [Core Concepts](02-core-concepts.md) for what coherence means in
RVM, [Advanced and Exotic Features](13-advanced-exotic.md) for the Phi
computation algorithm, [Partitions and Scheduling](07-partitions-scheduling.md)
for how coherence scores influence scheduling.

---

## 10. rvm-boot

**Deterministic boot sequence.**

`rvm-boot` orchestrates the seven-phase boot sequence that brings RVM from
reset to a running system. Each phase is gated: it must complete before the
next begins, and every transition is recorded in the witness trail. The crate
also supports measured boot, where a hash chain accumulates over all phase
measurements to produce a boot attestation.

**Key public types and functions:**

- `BootTracker` -- tracks progress through the seven boot phases
- `BootPhase` -- enum of the seven phases: `HalInit`, `MemoryInit`, `CapabilityInit`, `WitnessInit`, `SchedulerInit`, `RootPartition`, `Handoff`
- `BootSequence` -- the full boot sequence executor (ADR-137)
- `BootContext` -- context object passed between boot phases
- `MeasuredBootState` -- hash-chain accumulator for boot attestation
- `run_boot_sequence()` -- execute the complete boot sequence
- `BootStage`, `PhaseTiming` -- boot stage metadata and timing information

**HAL initialization:**

- `HalInit` -- trait that a platform must implement to initialize hardware during Phase 0
- `StubHal` -- stub implementation for testing
- `UartConfig`, `MmuConfig`, `InterruptConfig` -- configuration types for HAL initialization

**Feature flags:** `std`, `alloc`, `crypto-sha256` (on by default, enables
measured boot hash chain)

**Workspace dependencies:** `rvm-types`, `rvm-hal`, `rvm-partition`,
`rvm-witness`, `rvm-sched`, `rvm-memory`, `subtle`, optionally `sha2`

**See also:** [Architecture](03-architecture.md) for the boot phase table,
[Bare-Metal Deployment](12-bare-metal.md) for booting on real hardware,
[Security](10-security.md) for measured boot verification.

---

## 11. rvm-wasm

**WebAssembly guest runtime.**

`rvm-wasm` provides an optional WebAssembly runtime for hosting lightweight
agents inside RVM partitions. It validates Wasm modules, manages agent
lifecycle (load, validate, run, terminate), supports live migration between
partitions, and enforces resource quotas to prevent a misbehaving agent from
starving other workloads.

**Key public types and functions:**

- `WasmModuleInfo` -- metadata about a loaded Wasm module
- `WasmModuleState` -- lifecycle states: `Loaded`, `Validated`, `Running`, `Terminated`
- `validate_module()` -- validates a Wasm binary for structural correctness and safety
- `WasmSectionId` -- identifies sections within a Wasm module

**Modules:**

- Agent lifecycle management (load, start, stop, terminate)
- Migration support (snapshot state, transfer, resume)
- Quota enforcement (memory limits, instruction budgets)

**Constants:**

- `MAX_MODULE_SIZE` = 1 MB

**Feature flags:** `std`, `alloc` (both off by default)

**Workspace dependencies:** `rvm-types`, `rvm-partition`, `rvm-cap`, `rvm-witness`

**See also:** [WASM Agents](09-wasm-agents.md) for writing and deploying Wasm
agents, [Partitions and Scheduling](07-partitions-scheduling.md) for how Wasm
agents interact with the partition model.

---

## 12. rvm-security

**Unified security gate.**

`rvm-security` is the single entry point for all security policy enforcement
in RVM. Every hypercall passes through its three-stage gate: capability check,
proof verification, and witness logging. The crate also provides input
validation, attestation chain management, and DMA/resource budget enforcement.

**Key public types and functions:**

- `SecurityGate`, `SignedSecurityGate` -- the three-stage security gate (the signed variant uses cryptographic witness signatures)
- `GateRequest`, `GateResponse` -- request and response types for the gate
- `PolicyDecision` -- `Allow` or `Deny(RvmError)`
- `PolicyRequest` -- lightweight policy evaluation request
- `SecurityError` -- security-specific error type
- `P3WitnessChain` -- witness chain for Phase 3 (witness logging stage) of the gate

**Attestation:**

- `AttestationChain` -- chain of attestation reports for platform verification
- `AttestationReport` -- a single attestation measurement
- `verify_attestation()` -- verify an attestation chain

**Resource control:**

- `DmaBudget` -- limits on DMA transfers per partition
- `ResourceQuota` -- general resource quotas (memory, CPU time, I/O bandwidth)

**Modules:**

- `gate` -- the unified security gate implementation
- `validation` -- input validation for security-critical parameters
- `attestation` -- attestation chain and report generation
- `budget` -- DMA and resource budget enforcement

**Feature flags:** `std`, `alloc`, `crypto-sha256` (on by default)

**Workspace dependencies:** `rvm-types`, `rvm-witness`, `subtle`, optionally `sha2`

**See also:** [Architecture](03-architecture.md) for the hypercall data flow
through the gate, [Security](10-security.md) for security hardening guidance,
[Capabilities and Proofs](05-capabilities-proofs.md) for the capability and
proof models that the gate enforces.

---

## 13. rvm-kernel

**Top-level integration crate.**

`rvm-kernel` wires all 12 subsystem crates together into a single API surface.
It re-exports every subsystem under a short module name (e.g.,
`rvm_kernel::cap`, `rvm_kernel::witness`), defines the `VERSION` constant, and
provides the signer bridge (ADR-142) that connects the 64-byte proof-crate
signer to the 8-byte witness-crate signer.

**Key public items:**

- `VERSION` -- the current RVM version string (from `Cargo.toml`)
- `CRATE_COUNT` -- the number of subsystem crates (13)
- Module re-exports: `boot`, `cap`, `coherence`, `hal`, `memory`, `partition`, `proof`, `sched`, `security`, `types`, `wasm`, `witness`

**Signer bridge (ADR-142):**

- `signer_bridge::CryptoSignerAdapter<S>` -- wraps a 64-byte proof-crate `WitnessSigner` and adapts it to the 8-byte witness-crate `WitnessSigner` interface by computing a SHA-256 digest and truncating the signature

**Feature flags:** `std`, `alloc`, `wasm`, `coherence`, `coherence-sched`,
`crypto-sha256` (on by default). All `std` and `alloc` flags propagate to
every subsystem crate.

**Workspace dependencies:** All 12 subsystem crates.

**See also:** [Architecture](03-architecture.md) for how `rvm-kernel` sits
atop the dependency tree, [Quickstart](01-quickstart.md) for building and
running RVM, [README](README.md) for the project overview.

---

## Dependency Summary

The table below shows which RVM crates each crate depends on. External
dependencies (`bitflags`, `spin`, `sha2`, `hmac`, `subtle`, `ed25519-dalek`,
`lz4_flex`) are not listed.

| Crate          | Depends on                                              |
|----------------|---------------------------------------------------------|
| rvm-types      | *(none)*                                                |
| rvm-hal        | rvm-types                                               |
| rvm-cap        | rvm-types                                               |
| rvm-witness    | rvm-types                                               |
| rvm-proof      | rvm-types, rvm-cap, rvm-witness                         |
| rvm-partition  | rvm-types, rvm-cap, rvm-witness                         |
| rvm-sched      | rvm-types, rvm-partition, rvm-witness                   |
| rvm-memory     | rvm-types                                               |
| rvm-coherence  | rvm-types, rvm-partition, optionally rvm-sched          |
| rvm-boot       | rvm-types, rvm-hal, rvm-partition, rvm-witness, rvm-sched, rvm-memory |
| rvm-wasm       | rvm-types, rvm-partition, rvm-cap, rvm-witness          |
| rvm-security   | rvm-types, rvm-witness                                  |
| rvm-kernel     | *all 12 above*                                          |

---

## Where to Go Next

- **How the crates fit together:** [Architecture](03-architecture.md)
- **Capabilities and proof tiers:** [Capabilities and Proofs](05-capabilities-proofs.md)
- **Witness trail in depth:** [Witness and Audit](06-witness-audit.md)
- **Partition lifecycle:** [Partitions and Scheduling](07-partitions-scheduling.md)
- **Memory regions and allocation:** [Memory Model](08-memory-model.md)
- **WebAssembly agents:** [WASM Agents](09-wasm-agents.md)
- **Security hardening:** [Security](10-security.md)
- **Performance tuning:** [Performance](11-performance.md)
- **Running on bare metal:** [Bare-Metal Deployment](12-bare-metal.md)
- **Exotic features and Phi:** [Advanced and Exotic Features](13-advanced-exotic.md)
- **Troubleshooting:** [Troubleshooting](14-troubleshooting.md)
- **Term definitions:** [Glossary](15-glossary.md)
- **Full cross-reference:** [Cross-Reference](cross-reference.md)
