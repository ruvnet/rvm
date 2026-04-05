# Glossary: Terms and Definitions

This glossary defines every key term used in the RVM user guide. Entries are
alphabetical. Cross-references point to the chapter where the term is
discussed in depth.

---

**ADR** (Architecture Decision Record) -- A numbered document in `docs/adr/`
that records a design decision, its context, and its consequences. ADRs are
the authoritative specification for RVM's behavior. See
[Architecture](03-architecture.md).

**Agent** -- A WASM module running inside a partition. Agents execute in a
sandboxed interpreter and interact with the kernel through host functions
gated by capabilities. See [WASM Agents](09-wasm-agents.md).

**BuddyAllocator** -- A power-of-two physical page allocator used to manage
the host's physical memory. Allocations and frees are O(log N) in the number
of orders. Implemented in `rvm-memory::allocator`. See [Memory
Model](08-memory-model.md) and [Performance](11-performance.md).

**Capability** -- An unforgeable, kernel-managed token that grants specific
rights over a specific kernel object. Capabilities cannot be fabricated by
user code; they can only be derived from existing capabilities via
delegation. See [Capabilities and Proofs](05-capabilities-proofs.md).

**CapRights** -- A bitflag type representing the rights held by a capability:
`READ`, `WRITE`, `EXECUTE`, `GRANT`, `REVOKE`, `PROVE`. Rights can only be
attenuated (reduced) during delegation, never amplified. See [Capabilities
and Proofs](05-capabilities-proofs.md).

**CapToken** -- A lightweight value type that carries a capability's type,
rights, epoch, and owner. Used in security gate requests and policy
evaluation. Defined in `rvm-types::capability`. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**CapType** -- The kind of kernel object a capability authorizes access to:
`Partition`, `Region`, `Device`, `CommEdge`, `Witness`. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**Coherence** -- A measure of how tightly coupled a partition is to its
communication neighbors. Derived from the weighted communication graph.
Higher coherence means the partition is more self-contained. See [Core
Concepts](02-core-concepts.md) and [Architecture](03-architecture.md).

**CoherenceScore** -- A fixed-point value in basis points (0..10,000) that
quantifies a partition's coherence. Computed as the ratio of internal weight
to total weight. Defined in `rvm-types::coherence`. See [Partitions and
Scheduling](07-partitions-scheduling.md).

**CommEdge** -- A weighted, directed edge in the coherence graph representing
a communication channel between two partitions. Edge weight increases with
IPC traffic. Defined in `rvm-types::coherence`. See [Partitions and
Scheduling](07-partitions-scheduling.md).

**CutPressure** -- A graph-derived signal indicating that a partition sits on
a weak boundary in the coherence graph. High cut pressure suggests the
partition should be migrated or split. Fixed-point, defined in
`rvm-types::coherence`. See [Advanced and Exotic](13-advanced-exotic.md).

**DC** (Design Constraint) -- A numbered requirement in the ADR documents
(e.g., DC-1: "Coherence engine is optional"). DCs constrain the
implementation. See [Architecture](03-architecture.md).

**Delegation Depth** -- The number of times a capability has been derived
from its root. Maximum depth is 8 (`MAX_DELEGATION_DEPTH`). Prevents
unbounded delegation chains. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**Derivation Tree** -- The parent-child hierarchy of capabilities.
Revoking a parent capability propagates revocation to all descendants.
Implemented in `rvm-cap::derivation`. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**EMA Filter** (Exponential Moving Average) -- A fixed-point smoothing filter
applied to coherence scores. Prevents scheduling jitter from noisy sensor
readings. Alpha is expressed in basis points. Implemented in
`rvm-coherence::EmaFilter`. See [Performance](11-performance.md).

**Epoch** -- A numbered time interval used for capability revocation and
scheduler accounting. Capabilities from a prior epoch are stale. Epochs
advance during bulk revocation events. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**Failure Class (F1--F4)** -- A severity classification for faults. F1
(Transient): agent restart. F2 (Recoverable): partition reconstruct. F3
(Permanent): partition destroy. F4 (Catastrophic): kernel reboot. Defined
in `rvm-types::recovery::FailureClass`. See [Advanced and
Exotic](13-advanced-exotic.md).

**FNV-1a** -- Fowler-Noll-Vo hash function, variant 1a. Used for witness
chain hashing and proof commitments. Fast, non-cryptographic. Implemented in
`rvm-witness::hash`. See [Witness and Audit](06-witness-audit.md).

**GuestPhysAddr** -- A guest physical address within a partition's stage-2
address space. Must be page-aligned for mapping operations. Defined in
`rvm-types::addr`. See [Memory Model](08-memory-model.md).

**GRANT_ONCE** -- A capability flag that allows a single delegation. After
the grant, the capability is consumed and cannot be granted again. Prevents
transitive delegation. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**HAL** (Hardware Abstraction Layer) -- Platform-agnostic traits for hardware
access: `Platform`, `MmuOps`, `TimerOps`, `InterruptOps`. Concrete
implementations exist for AArch64 (QEMU virt). Implemented in `rvm-hal`. See
[Architecture](03-architecture.md) and [Bare-Metal
Deployment](12-bare-metal.md).

**Hash Chain** -- A sequence of values where each element includes the hash
of the previous element. Used in the witness trail (`prev_hash` /
`record_hash`) and measured boot (`MeasuredBootState`). See [Witness and
Audit](06-witness-audit.md).

**HMAC-SHA256** -- Hash-based Message Authentication Code using SHA-256. Used
by `HmacSha256WitnessSigner` for cryptographic witness signatures. Requires
the `crypto-sha256` feature. See [Security](10-security.md).

**Hot** (Memory Tier 0) -- Per-core SRAM or L1-adjacent memory. Always
resident during execution. Lowest latency. See [Memory
Model](08-memory-model.md).

**IIT** (Integrated Information Theory) -- A theoretical framework from
neuroscience that quantifies consciousness as integrated information (Phi).
RVM uses IIT-inspired metrics to measure partition coherence. See [Core
Concepts](02-core-concepts.md).

**IPC** (Inter-Partition Communication) -- Message passing between partitions
via `IpcManager` and `MessageQueue`. IPC traffic updates CommEdge weights in
the coherence graph. Implemented in `rvm-partition::ipc`. See [Partitions and
Scheduling](07-partitions-scheduling.md).

**Kernel Object** -- Any entity managed by the RVM kernel: partitions,
capabilities, witness records, memory regions, communication edges, device
leases, coherence scores, cut pressures, and recovery checkpoints. See [Core
Concepts](02-core-concepts.md).

**Memory Tier** -- One of four storage levels: Hot (0), Warm (1), Dormant
(2), Cold (3). Tier placement is driven by coherence scores. See [Memory
Model](08-memory-model.md).

**MinCut** -- The minimum weight set of edges whose removal disconnects two
parts of the coherence graph. Used to identify optimal partition split
boundaries. Implemented in `rvm-coherence::mincut` as a budgeted Stoer-Wagner
heuristic. See [Advanced and Exotic](13-advanced-exotic.md).

**Monotonic Attenuation** -- The principle that capability rights can only
decrease (never increase) through delegation. A child capability always has
equal or fewer rights than its parent. See [Capabilities and
Proofs](05-capabilities-proofs.md).

**no_std** -- A Rust attribute indicating that a crate does not link against
the standard library. All RVM crates are `#![no_std]` to support bare-metal
deployment. See [Architecture](03-architecture.md).

**NullSigner** -- A test-only witness signer that accepts all records without
cryptographic verification. Deprecated. Gated behind the `null-signer`
feature flag. Never use in production. See [Security](10-security.md) and
[Troubleshooting](14-troubleshooting.md).

**Partition** -- The fundamental isolation and scheduling unit in RVM. Not a
VM: no emulated hardware, no guest BIOS, no virtual device model. A container
for a capability table, communication edges, coherence metrics, and CPU
affinity. See [Partitions and Scheduling](07-partitions-scheduling.md).

**PartitionId** -- A 32-bit identifier for a partition. Unique within an RVM
instance. Defined in `rvm-types::ids`. See [Partitions and
Scheduling](07-partitions-scheduling.md).

**PhiValue** -- A fixed-point value representing integrated information (Phi)
derived from IIT. Inputs to the coherence scoring pipeline. Defined in
`rvm-types::coherence`. See [Core Concepts](02-core-concepts.md).

**PhysAddr** -- A host physical address. Must be page-aligned for memory
region operations. Defined in `rvm-types::addr`. See [Memory
Model](08-memory-model.md).

**Proof** -- A data payload submitted alongside a state-transition request.
Verified by the proof engine before the mutation proceeds. Contains a tier,
commitment hash, and raw data (up to 64 bytes). Defined in `rvm-proof`. See
[Capabilities and Proofs](05-capabilities-proofs.md).

**ProofTier** -- The tier of proof required for an operation: `Hash` (P1),
`Witness` (P2), `Zk` (P3). Higher tiers provide stronger guarantees at
higher cost. See [Capabilities and Proofs](05-capabilities-proofs.md).

**QEMU** -- An open-source machine emulator. RVM uses the `virt` machine
type with `cortex-a72` CPU for development and testing. See [Bare-Metal
Deployment](12-bare-metal.md).

**Quota** -- A per-partition resource budget enforced per epoch. Covers CPU
time, memory pages, IPC messages, and WASM instruction counts. Implemented
in `rvm-wasm::quota`. See [WASM Agents](09-wasm-agents.md).

**Recovery Checkpoint** -- A snapshot of partition state at a known-good
point. Used for F2 (recoverable) fault recovery. Contains the partition ID,
witness sequence number, timestamp, and epoch. Defined in
`rvm-types::recovery`. See [Advanced and Exotic](13-advanced-exotic.md).

**Reflex Mode** -- A scheduling mode for hard real-time workloads. Disables
cross-partition IPC and coherence recomputation. Guarantees bounded latency.
See [Partitions and Scheduling](07-partitions-scheduling.md) and [Advanced
and Exotic](13-advanced-exotic.md).

**Ring Buffer** -- A fixed-size circular buffer used by `WitnessLog` to store
witness records. When full, new records overwrite the oldest. Capacity is a
compile-time const generic. See [Witness and Audit](06-witness-audit.md).

**Root Partition** -- Partition 0, created during boot phase 5. Holds full
capability rights over all resources. All other partitions are created by
the root partition delegating subsets of its authority. See [Bare-Metal
Deployment](12-bare-metal.md).

**RVM** (RuVix Virtual Machine) -- The coherence-native bare-metal
microhypervisor. 13 crates, 648 tests, 11 benchmarks.

**RuVector** -- An optional library providing production-grade graph
algorithms: MinCut, sparsification, spectral solvers, and IIT-inspired
coherence computation. Behind the `ruvector` feature flag. See [Advanced and
Exotic](13-advanced-exotic.md).

**Scheduler** -- The coherence-aware scheduler in `rvm-sched`. Uses a
2-signal priority: `deadline_urgency + cut_pressure_boost`. Supports three
modes: Reflex, Flow, Recovery. See [Partitions and
Scheduling](07-partitions-scheduling.md).

**SecurityGate** -- The unified security policy enforcement point. Every
hypercall passes through the gate: capability check, proof verification,
witness logging. Implemented in `rvm-security::gate`. See
[Security](10-security.md).

**Seed Profile** -- A hardware deployment profile targeting 64 KB to 1 MB
RAM. Provides capability + proof + witness security on microcontroller-class
hardware. See [Bare-Metal Deployment](12-bare-metal.md) and [Advanced and
Exotic](13-advanced-exotic.md).

**SensorReading** -- A raw data point fed into the coherence pipeline.
Contains a partition ID, timestamp, and Phi value. Defined in
`rvm-coherence`. See [Architecture](03-architecture.md).

**Split** -- A partition operation that divides one partition into two along a
graph-theoretic cut boundary. Regions are assigned using
`scored_region_assignment()`. See [Advanced and
Exotic](13-advanced-exotic.md).

**StrictSigner** -- The production witness signer. Rejects any record that
fails integrity checks. Use this (or `HmacSha256WitnessSigner`) in all
non-test deployments. Implemented in `rvm-witness::signer`. See
[Security](10-security.md).

**SwitchContext** -- The minimal state saved and restored during a partition
context switch. The switch path is the hottest path in RVM (~6 ns). See
[Partitions and Scheduling](07-partitions-scheduling.md) and
[Performance](11-performance.md).

**TEE** (Trusted Execution Environment) -- Hardware-backed isolated execution.
RVM's `rvm-proof` crate defines `TeeQuoteProvider` and `TeeQuoteVerifier`
traits for attestation. Software implementations are provided for testing.
See [Security](10-security.md).

**Tier** -- See *Memory Tier*.

**VMID** (Virtual Machine Identifier) -- An 8-bit ARM hardware identifier
used for stage-2 address translation. Limits RVM to 256 partitions. See
[Partitions and Scheduling](07-partitions-scheduling.md).

**WASM** (WebAssembly) -- A portable bytecode format. RVM partitions can
optionally host WASM modules as agents. Validated and executed in a sandboxed
interpreter. Implemented in `rvm-wasm`. See [WASM
Agents](09-wasm-agents.md).

**Warm** (Memory Tier 1) -- Shared DRAM. Resident if residency rules are
met. Medium latency. See [Memory Model](08-memory-model.md).

**Witness** -- See *WitnessRecord*.

**WitnessEmitter** -- The API for emitting witness records into the witness
log. Provides typed methods for each action kind (e.g.,
`emit_partition_create`). Implemented in `rvm-witness::emit`. See [Witness
and Audit](06-witness-audit.md).

**WitnessHash** -- A 32-byte hash value used for proof commitments and
attestation digests. Defined in `rvm-types::witness`. See [Witness and
Audit](06-witness-audit.md).

**WitnessLog** -- A fixed-size ring buffer of `WitnessRecord` entries.
Capacity is a compile-time const generic. The default is 262,144 records
(16 MB). Implemented in `rvm-witness::log`. See [Witness and
Audit](06-witness-audit.md).

**WitnessRecord** -- A 64-byte audit record emitted by every privileged
action. Contains sequence number, timestamp, action kind, proof tier, actor
partition, target object, capability hash, payload, and hash chain links.
Cache-line aligned. See [Witness and Audit](06-witness-audit.md).

**ZK** (Zero-Knowledge) -- A proof system where the verifier learns nothing
beyond the validity of the statement. RVM's P3 (Zk) proof tier is defined
but deferred to post-v1, pending TEE integration. See [Capabilities and
Proofs](05-capabilities-proofs.md).

---

## Further Reading

- [Core Concepts](02-core-concepts.md) -- narrative explanations of the key ideas
- [Crate Reference](04-crate-reference.md) -- API-level documentation for each crate
- [Cross-Reference Index](cross-reference.md) -- find every chapter where a term appears
