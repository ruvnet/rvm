# Architecture: How RVM Is Built

RVM is composed of 13 Rust crates organized into well-defined layers. Each layer
has a single responsibility, and dependencies flow strictly downward. This
chapter explains the layer structure, shows how data flows through the system
during a hypercall, walks through the seven-phase boot sequence, and catalogues
the feature flags and platform targets that shape a build.

If you are new to RVM, start with the [Quickstart](01-quickstart.md) and
[Core Concepts](02-core-concepts.md) chapters first. For a per-crate API
reference, see [Crate Reference](04-crate-reference.md).

---

## Layer Diagram

The ASCII diagram below shows the crate dependency tree from top to bottom.
Arrows point from a crate to its dependencies.

```text
 +-------------------------------------------------------------+
 |                        rvm-kernel                            |
 |       (integration crate -- re-exports all 12 subsystems)    |
 +----+-------------------+-------------------+---------+-------+
      |                   |                   |         |
      v                   v                   v         |
 +----------+       +----------+       +-----------+    |
 | rvm-boot |       | rvm-sched|       | rvm-memory|    |
 +----+-----+       +----+-----+       +-----+-----+    |
      |                   |                   |         |
      +-------------------+-------------------+         |
                          |                             |
                          v                             |
              +-----------------------+                 |
              |    rvm-partition      |                 |
              | (central hub crate)   |                 |
              +--+------+------+--+--+                 |
                 |      |      |  |                    |
      +----------+      |      +----------+            |
      |          +------+------+          |            |
      v          v      v      v          v            v
 +--------+ +--------+ +--------+ +-----------+ +-----------+
 |rvm-cap | |rvm-wit.| |rvm-prf.| |rvm-secur. | |rvm-coher. |
 +---+----+ +---+----+ +---+----+ +-----+-----+ +-----+-----+
     |          |           |            |             |
     +----------+-----------+------------+-------------+
                            |
                            v
                   +------------------+
                   |    rvm-types     |
                   | (foundation --   |
                   |  zero deps*)     |
                   +------------------+

 * rvm-types depends only on the bitflags crate.

 Standalone / edge crates (depend on rvm-types only):

 +--------+     +----------+
 |rvm-hal |     | rvm-wasm |  (optional)
 +--------+     +----------+
```

**Reading the diagram:**

- **rvm-kernel** sits at the top. It depends on every other crate and
  re-exports them as `rvm_kernel::boot`, `rvm_kernel::cap`, and so on.
- **rvm-boot**, **rvm-sched**, and **rvm-memory** form the mid-layer. They
  orchestrate initialization, scheduling, and address-space management.
- **rvm-partition** is the central hub. It defines the partition object that
  nearly every other crate references.
- **rvm-cap**, **rvm-witness**, **rvm-proof**, and **rvm-security** form the
  security layer. Together they enforce capability-based access control,
  generate audit trails, and gate state transitions with proofs.
- **rvm-types** is the foundation. It defines shared types such as
  `PartitionId`, `CapToken`, `WitnessHash`, and `RvmError`. Every crate in
  the workspace depends on it.
- **rvm-hal** abstracts platform hardware behind traits. It depends only on
  `rvm-types` and is used by crates that touch timers, MMU, or interrupts.
- **rvm-wasm** and **rvm-coherence** are optional. They activate with feature
  flags and provide WebAssembly guest support and coherence monitoring,
  respectively.

For details on every exported type in each crate, see
[Crate Reference](04-crate-reference.md).

---

## Data Flow: Anatomy of a Hypercall

When a guest partition makes a hypercall, the request passes through several
subsystems before any state mutation occurs. Understanding this pipeline is
essential for reasoning about security and auditability.

```text
  Caller (guest partition)
      |
      v
  +-----------------+
  |  SecurityGate   |  (rvm-security)
  |  Stage 1: Cap   |----> Does the caller hold a valid CapToken
  |  Stage 2: Proof |----> Is the proof commitment correct?
  |  Stage 3: Wit.  |----> Log the decision to the witness ring
  +-----------------+
      |
      | (only if all three stages pass)
      v
  +-----------------+
  |   Partition     |  (rvm-partition)
  |   Apply the     |
  |   requested     |
  |   mutation      |
  +-----------------+
      |
      v
  State updated
```

### Stage 1 -- Capability Check

The `SecurityGate` inspects the caller's `CapToken`. A token encodes a
`CapType` (what resource it grants access to), `CapRights` (which operations
are allowed), and a delegation depth. The gate verifies that the token has not
been revoked and that the requested operation falls within the granted rights.
See [Capabilities and Proofs](05-capabilities-proofs.md) for the full
capability model.

### Stage 2 -- Proof Verification

State-mutating operations require a `ProofToken` that commits to the
before-and-after state of the affected resource. The proof engine
(`rvm-proof`) verifies this commitment at one of three tiers: `Hash` (a
SHA-256 digest), `Witness` (a signed witness chain), or `Zk` (a
zero-knowledge proof, reserved for future use). See
[Capabilities and Proofs](05-capabilities-proofs.md) for proof tiers.

### Stage 3 -- Witness Logging

Regardless of whether the hypercall is allowed or denied, the decision is
appended to the witness ring buffer (`rvm-witness`). Each `WitnessRecord`
captures the partition ID, the action kind, a timestamp, and a cryptographic
signature. This creates a tamper-evident audit trail that can be queried later
by time range, partition, or action kind. See
[Witness and Audit](06-witness-audit.md) for querying the log.

### After the Gate

If all three stages pass, the request reaches the target `Partition` in
`rvm-partition`. The partition manager applies the mutation -- for example,
mapping a memory region, sending an IPC message, or adjusting a device lease.
The mutation itself may trigger further witness records.

---

## Boot Sequence: Seven Phases

RVM boots through a deterministic, phased sequence. Each phase is gated: it
must complete successfully before the next phase begins, and every transition
is recorded in the witness trail. The `BootTracker` struct in `rvm-boot`
enforces this ordering at the type level.

| Phase | Name               | What Happens                                          |
|-------|--------------------|-------------------------------------------------------|
| 0     | HAL Init           | Initialize the hardware abstraction layer: timer, MMU, and interrupt controller. |
| 1     | Memory Init        | Bring up the physical page allocator and the buddy allocator. Enumerate available RAM. |
| 2     | Capability Init    | Create the root capability table with `DEFAULT_CAP_TABLE_CAPACITY` (256) slots. |
| 3     | Witness Init       | Initialize the witness ring buffer (`DEFAULT_RING_CAPACITY` = 262,144 entries) and emit the genesis record. |
| 4     | Scheduler Init     | Set up per-CPU run queues and the SMP coordinator. Choose the initial `SchedulerMode`. |
| 5     | Root Partition     | Create the root partition with full capabilities. This is the first partition and the parent of all others. |
| 6     | Handoff            | Transfer control to the root partition's entry point. Boot is complete. |

```text
  Phase 0      Phase 1      Phase 2       Phase 3      Phase 4      Phase 5       Phase 6
  HAL Init --> Memory   --> Capability --> Witness  --> Scheduler --> Root Part --> Handoff
               Init         Init           Init         Init         Creation
     |            |            |              |            |             |            |
     +--- witness record ---  witness record  --- witness record ---  witness record -+
```

Each phase transition produces a witness record. If the `crypto-sha256`
feature is enabled, the `MeasuredBootState` accumulates a hash chain over all
phase measurements, providing a boot attestation similar to a TPM PCR extend
operation. See [Bare-Metal Deployment](12-bare-metal.md) for how to verify
measured boot on real hardware.

---

## Feature Flags

RVM uses Cargo feature flags to control binary size and functionality. All
features propagate from `rvm-kernel` down to the relevant subsystem crate.

| Flag               | Default | Effect                                                    |
|--------------------|---------|-----------------------------------------------------------|
| `std`              | off     | Enables `std` across all 12 subsystem crates. Only needed for hosted testing or user-space mode. |
| `alloc`            | off     | Enables `alloc` across all 12 subsystem crates. Permits heap allocation in crates that support it. |
| `wasm`             | off     | Activates the WebAssembly guest runtime in `rvm-wasm`. See [WASM Agents](09-wasm-agents.md). |
| `coherence`        | off     | Activates the coherence monitoring engine in `rvm-coherence`. See [Core Concepts](02-core-concepts.md). |
| `coherence-sched`  | off     | Enables the feedback loop between `rvm-coherence` and `rvm-sched`, so coherence scores influence scheduling priority. |
| `crypto-sha256`    | **on**  | Enables SHA-256 hashing and HMAC signing in `rvm-witness` and `rvm-proof`. Pulls in `sha2` and `hmac`. |
| `ed25519`          | off     | Enables Ed25519 signature verification in `rvm-proof`. Pulls in `ed25519-dalek`. Implies `crypto-sha256`. |
| `strict-signing`   | **on**  | Enforces that every witness record must be signed. Disabling this (with `null-signer`) is only appropriate for testing. |
| `null-signer`      | off     | Allows unsigned witness records. **Do not use in production.** |

To build with no optional features:

```bash
cargo build --no-default-features
```

To build with the coherence engine and Ed25519 proofs:

```bash
cargo build --features coherence,ed25519
```

See [Performance](11-performance.md) for how feature flags affect binary size
and runtime overhead, and [Security](10-security.md) for guidance on which
flags are safe to disable.

---

## Design Principles

Five principles guide every design decision in RVM.

### 1. `#![no_std]` Everywhere

Every crate in the workspace is `no_std` by default. This means RVM can run on
bare metal without an operating system, on microcontrollers with no heap, and
inside firmware environments. The `std` and `alloc` feature flags opt in to
hosted functionality when needed for testing or user-space deployment.

### 2. `#![forbid(unsafe_code)]`

No crate in the workspace contains `unsafe` blocks. All hardware interaction
is abstracted behind safe trait boundaries in `rvm-hal`. When RVM runs on real
hardware, the platform-specific HAL implementation (outside this workspace)
provides the necessary `unsafe` implementations. Inside the hypervisor itself,
the type system enforces correctness.

### 3. `#![deny(missing_docs)]`

Every public item must have a documentation comment. This is enforced by the
compiler. If you add a public type or function without a doc comment, the build
fails.

### 4. Zero Heap by Default

When built without the `alloc` feature, RVM uses only stack and static
allocations. All core data structures -- capability tables, witness ring
buffers, partition arrays, scheduler queues -- use fixed-capacity arrays. This
makes memory usage predictable and eliminates allocation failure as a failure
mode.

### 5. `Copy + Clone + Eq` Types

The foundation types in `rvm-types` are designed to be small, copyable value
types. A `PartitionId` is a `u16`. A `CapToken` is a fixed-size struct.
Passing these types around never involves heap allocation, reference counting,
or lifetime complexity. This keeps the API surface simple and the generated
code efficient.

---

## Platform Targets

RVM targets three deployment profiles, each with different resource budgets and
use cases.

### Seed (64 KB -- 1 MB RAM)

The Seed profile targets microcontrollers and deeply embedded systems. At this
scale, RVM runs with `no_std` and no allocator. All data structures use their
default fixed capacities: 256 capability slots, 256 partitions, and a witness
ring sized to fit available memory.

Typical use cases: sensor hubs, secure enclaves, IoT gateways.

See [Bare-Metal Deployment](12-bare-metal.md) for flashing instructions.

### Appliance (1 -- 32 GB RAM)

The Appliance profile targets edge servers, single-board computers, and
embedded PCs. At this scale, RVM can enable the `alloc` feature for dynamic
partition creation and the `coherence` feature for live system monitoring. The
`wasm` feature enables hosting WebAssembly agents as lightweight guests.

Typical use cases: edge inference nodes, network appliances, multi-agent
orchestrators.

See [WASM Agents](09-wasm-agents.md) for running agents on the Appliance
profile.

### Chip (Future Silicon)

The Chip profile is a forward-looking target for hardware implementations of
RVM concepts. It envisions coherence monitoring, capability checking, and
witness logging implemented in silicon, with RVM as the reference software
model. This profile is not yet available.

---

## Where to Go Next

- **Per-crate API details:** [Crate Reference](04-crate-reference.md)
- **Capabilities and proofs in depth:** [Capabilities and Proofs](05-capabilities-proofs.md)
- **Witness trail queries:** [Witness and Audit](06-witness-audit.md)
- **Partition lifecycle and scheduling:** [Partitions and Scheduling](07-partitions-scheduling.md)
- **Memory regions and tiers:** [Memory Model](08-memory-model.md)
- **Security hardening guidance:** [Security](10-security.md)
- **Performance tuning:** [Performance](11-performance.md)
- **Bare-metal deployment:** [Bare-Metal Deployment](12-bare-metal.md)
- **Full cross-reference index:** [Cross-Reference](cross-reference.md)
