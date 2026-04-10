# Cross-Reference Index

This index maps every major concept, API type, and task to the chapters where
it is covered. Use it to navigate between related topics and to find the
authoritative discussion of any subject.

---

## Concept Index

Each row lists the primary chapter (where the concept is defined and
explained in depth) and every other chapter that references it.

| Concept | Primary Chapter | Also Mentioned In |
|---|---|---|
| Capabilities | [05-capabilities-proofs.md](05-capabilities-proofs.md) | [02-core-concepts.md](02-core-concepts.md), [04-crate-reference.md](04-crate-reference.md), [07-partitions-scheduling.md](07-partitions-scheduling.md), [10-security.md](10-security.md), [13-advanced-exotic.md](13-advanced-exotic.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| Witness Trail | [06-witness-audit.md](06-witness-audit.md) | [02-core-concepts.md](02-core-concepts.md), [04-crate-reference.md](04-crate-reference.md), [08-memory-model.md](08-memory-model.md), [10-security.md](10-security.md), [11-performance.md](11-performance.md), [13-advanced-exotic.md](13-advanced-exotic.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| Proof System (P1/P2/P3) | [05-capabilities-proofs.md](05-capabilities-proofs.md) | [02-core-concepts.md](02-core-concepts.md), [04-crate-reference.md](04-crate-reference.md), [10-security.md](10-security.md), [11-performance.md](11-performance.md), [13-advanced-exotic.md](13-advanced-exotic.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| Partitions | [07-partitions-scheduling.md](07-partitions-scheduling.md) | [02-core-concepts.md](02-core-concepts.md), [03-architecture.md](03-architecture.md), [04-crate-reference.md](04-crate-reference.md), [05-capabilities-proofs.md](05-capabilities-proofs.md), [08-memory-model.md](08-memory-model.md), [12-bare-metal.md](12-bare-metal.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Coherence Engine | [03-architecture.md](03-architecture.md) | [02-core-concepts.md](02-core-concepts.md), [04-crate-reference.md](04-crate-reference.md), [07-partitions-scheduling.md](07-partitions-scheduling.md), [11-performance.md](11-performance.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Scheduler (2-signal) | [07-partitions-scheduling.md](07-partitions-scheduling.md) | [03-architecture.md](03-architecture.md), [04-crate-reference.md](04-crate-reference.md), [11-performance.md](11-performance.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Memory Model (4-tier) | [08-memory-model.md](08-memory-model.md) | [02-core-concepts.md](02-core-concepts.md), [04-crate-reference.md](04-crate-reference.md), [12-bare-metal.md](12-bare-metal.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Security Gate | [10-security.md](10-security.md) | [04-crate-reference.md](04-crate-reference.md), [05-capabilities-proofs.md](05-capabilities-proofs.md), [11-performance.md](11-performance.md), [13-advanced-exotic.md](13-advanced-exotic.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| Boot Sequence (7-phase) | [12-bare-metal.md](12-bare-metal.md) | [03-architecture.md](03-architecture.md), [04-crate-reference.md](04-crate-reference.md), [10-security.md](10-security.md), [15-glossary.md](15-glossary.md) |
| Measured Boot | [12-bare-metal.md](12-bare-metal.md) | [10-security.md](10-security.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| WASM Agents | [09-wasm-agents.md](09-wasm-agents.md) | [02-core-concepts.md](02-core-concepts.md), [04-crate-reference.md](04-crate-reference.md), [12-bare-metal.md](12-bare-metal.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Split / Merge | [13-advanced-exotic.md](13-advanced-exotic.md) | [07-partitions-scheduling.md](07-partitions-scheduling.md), [04-crate-reference.md](04-crate-reference.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| MinCut | [13-advanced-exotic.md](13-advanced-exotic.md) | [04-crate-reference.md](04-crate-reference.md), [11-performance.md](11-performance.md), [15-glossary.md](15-glossary.md) |
| CutPressure | [13-advanced-exotic.md](13-advanced-exotic.md) | [07-partitions-scheduling.md](07-partitions-scheduling.md), [11-performance.md](11-performance.md), [15-glossary.md](15-glossary.md) |
| EMA Filter | [11-performance.md](11-performance.md) | [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Buddy Allocator | [08-memory-model.md](08-memory-model.md) | [04-crate-reference.md](04-crate-reference.md), [11-performance.md](11-performance.md), [12-bare-metal.md](12-bare-metal.md), [15-glossary.md](15-glossary.md) |
| Reconstruction Pipeline | [08-memory-model.md](08-memory-model.md) | [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Failure Classes (F1--F4) | [13-advanced-exotic.md](13-advanced-exotic.md) | [02-core-concepts.md](02-core-concepts.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| Delegation / Derivation Tree | [05-capabilities-proofs.md](05-capabilities-proofs.md) | [04-crate-reference.md](04-crate-reference.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| TEE / Attestation | [10-security.md](10-security.md) | [04-crate-reference.md](04-crate-reference.md), [05-capabilities-proofs.md](05-capabilities-proofs.md), [12-bare-metal.md](12-bare-metal.md), [15-glossary.md](15-glossary.md) |
| IPC | [07-partitions-scheduling.md](07-partitions-scheduling.md) | [04-crate-reference.md](04-crate-reference.md), [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Scheduling Modes (Reflex/Flow/Recovery) | [07-partitions-scheduling.md](07-partitions-scheduling.md) | [13-advanced-exotic.md](13-advanced-exotic.md), [15-glossary.md](15-glossary.md) |
| Epoch-Based Revocation | [05-capabilities-proofs.md](05-capabilities-proofs.md) | [07-partitions-scheduling.md](07-partitions-scheduling.md), [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| RuVector | [13-advanced-exotic.md](13-advanced-exotic.md) | [11-performance.md](11-performance.md), [15-glossary.md](15-glossary.md) |
| Seed / Appliance Profiles | [12-bare-metal.md](12-bare-metal.md) | [13-advanced-exotic.md](13-advanced-exotic.md), [11-performance.md](11-performance.md), [15-glossary.md](15-glossary.md) |
| Benchmarks | [11-performance.md](11-performance.md) | [01-quickstart.md](01-quickstart.md), [04-crate-reference.md](04-crate-reference.md) |
| Build Profiles | [11-performance.md](11-performance.md) | [01-quickstart.md](01-quickstart.md), [12-bare-metal.md](12-bare-metal.md), [14-troubleshooting.md](14-troubleshooting.md) |
| Linker Script (rvm.ld) | [12-bare-metal.md](12-bare-metal.md) | [01-quickstart.md](01-quickstart.md), [14-troubleshooting.md](14-troubleshooting.md) |
| FNV-1a | [06-witness-audit.md](06-witness-audit.md) | [11-performance.md](11-performance.md), [15-glossary.md](15-glossary.md) |
| NullSigner (deprecated) | [10-security.md](10-security.md) | [14-troubleshooting.md](14-troubleshooting.md), [15-glossary.md](15-glossary.md) |
| Device Leases | [04-crate-reference.md](04-crate-reference.md) | [02-core-concepts.md](02-core-concepts.md), [07-partitions-scheduling.md](07-partitions-scheduling.md), [15-glossary.md](15-glossary.md) |

---

## API Quick Finder

This table maps key public types and functions to the crate where they are
defined and the chapter that explains their usage.

| Type / Function | Crate | Chapter |
|---|---|---|
| `CapToken` | rvm-types | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `CapRights` | rvm-types | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `CapType` | rvm-types | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `Capability` | rvm-types | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `CapabilityManager` | rvm-cap | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `CapabilityTable` | rvm-cap | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `DerivationTree` | rvm-cap | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `GrantPolicy` | rvm-cap | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `ProofVerifier` | rvm-cap | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `verify_p1()` | rvm-cap | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `Proof` | rvm-proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `ProofTier` | rvm-proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `ProofEngine` | rvm-proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `ProofContextBuilder` | rvm-proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `verify()` | rvm-proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `compute_data_hash()` | rvm-proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| `WitnessSigner` (proof) | rvm-proof | [10-security.md](10-security.md) |
| `HmacSha256WitnessSigner` | rvm-proof | [10-security.md](10-security.md) |
| `TeeQuoteProvider` | rvm-proof | [10-security.md](10-security.md) |
| `TeeQuoteVerifier` | rvm-proof | [10-security.md](10-security.md) |
| `SoftwareTeeProvider` | rvm-proof | [10-security.md](10-security.md) |
| `WitnessRecord` | rvm-types | [06-witness-audit.md](06-witness-audit.md) |
| `WitnessHash` | rvm-types | [06-witness-audit.md](06-witness-audit.md) |
| `ActionKind` | rvm-types | [06-witness-audit.md](06-witness-audit.md) |
| `WitnessLog` | rvm-witness | [06-witness-audit.md](06-witness-audit.md) |
| `WitnessEmitter` | rvm-witness | [06-witness-audit.md](06-witness-audit.md) |
| `verify_chain()` | rvm-witness | [06-witness-audit.md](06-witness-audit.md) |
| `fnv1a_64()` | rvm-witness | [06-witness-audit.md](06-witness-audit.md) |
| `StrictSigner` | rvm-witness | [10-security.md](10-security.md) |
| `NullSigner` | rvm-witness | [10-security.md](10-security.md) |
| `PartitionId` | rvm-types | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `PartitionState` | rvm-partition | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `PartitionManager` | rvm-partition | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `Partition` | rvm-partition | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `scored_region_assignment()` | rvm-partition | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `merge_preconditions_full()` | rvm-partition | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `IpcManager` | rvm-partition | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `MessageQueue` | rvm-partition | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `Scheduler` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `PerCpuScheduler` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `SwitchContext` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `SwitchResult` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `SchedulerMode` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `EpochTracker` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `SmpCoordinator` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `compute_priority()` | rvm-sched | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `CoherenceGraph` | rvm-coherence | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `CoherenceScore` | rvm-types | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `CutPressure` | rvm-types | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `EmaFilter` | rvm-coherence | [11-performance.md](11-performance.md) |
| `AdaptiveCoherenceEngine` | rvm-coherence | [11-performance.md](11-performance.md) |
| `MinCutBridge` | rvm-coherence | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `compute_coherence_score()` | rvm-coherence | [11-performance.md](11-performance.md) |
| `compute_cut_pressure()` | rvm-coherence | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `DefaultCoherenceEngine` | rvm-coherence | [03-architecture.md](03-architecture.md) |
| `BuddyAllocator` | rvm-memory | [08-memory-model.md](08-memory-model.md) |
| `RegionManager` | rvm-memory | [08-memory-model.md](08-memory-model.md) |
| `TierManager` | rvm-memory | [08-memory-model.md](08-memory-model.md) |
| `ReconstructionPipeline` | rvm-memory | [08-memory-model.md](08-memory-model.md) |
| `CompressedCheckpoint` | rvm-memory | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `WitnessDelta` | rvm-memory | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `MemoryRegion` | rvm-memory | [08-memory-model.md](08-memory-model.md) |
| `MemoryTier` | rvm-types | [08-memory-model.md](08-memory-model.md) |
| `SecurityGate` | rvm-security | [10-security.md](10-security.md) |
| `GateRequest` | rvm-security | [10-security.md](10-security.md) |
| `GateResponse` | rvm-security | [10-security.md](10-security.md) |
| `PolicyDecision` | rvm-security | [10-security.md](10-security.md) |
| `AttestationChain` | rvm-security | [10-security.md](10-security.md) |
| `DmaBudget` | rvm-security | [10-security.md](10-security.md) |
| `BootSequence` | rvm-boot | [12-bare-metal.md](12-bare-metal.md) |
| `BootPhase` | rvm-boot | [12-bare-metal.md](12-bare-metal.md) |
| `BootTracker` | rvm-boot | [12-bare-metal.md](12-bare-metal.md) |
| `MeasuredBootState` | rvm-boot | [12-bare-metal.md](12-bare-metal.md) |
| `BootContext` | rvm-boot | [12-bare-metal.md](12-bare-metal.md) |
| `run_boot_sequence()` | rvm-boot | [12-bare-metal.md](12-bare-metal.md) |
| `Platform` (trait) | rvm-hal | [03-architecture.md](03-architecture.md) |
| `MmuOps` (trait) | rvm-hal | [03-architecture.md](03-architecture.md) |
| `TimerOps` (trait) | rvm-hal | [03-architecture.md](03-architecture.md) |
| `InterruptOps` (trait) | rvm-hal | [03-architecture.md](03-architecture.md) |
| `validate_module()` | rvm-wasm | [09-wasm-agents.md](09-wasm-agents.md) |
| `WasmModuleInfo` | rvm-wasm | [09-wasm-agents.md](09-wasm-agents.md) |
| `FailureClass` | rvm-types | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `RecoveryCheckpoint` | rvm-types | [13-advanced-exotic.md](13-advanced-exotic.md) |
| `PhiValue` | rvm-types | [02-core-concepts.md](02-core-concepts.md) |
| `RvmError` | rvm-types | [14-troubleshooting.md](14-troubleshooting.md) |
| `CommEdge` | rvm-types | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| `DeviceLease` | rvm-types | [04-crate-reference.md](04-crate-reference.md) |

---

## "I Want To..." Task Index

| I Want To... | Read |
|---|---|
| Build and run RVM for the first time | [01-quickstart.md](01-quickstart.md) |
| Understand RVM's key ideas before diving into code | [02-core-concepts.md](02-core-concepts.md) |
| See how the 14 crates fit together | [03-architecture.md](03-architecture.md) |
| Find the API for a specific crate | [04-crate-reference.md](04-crate-reference.md) |
| Add capability checks to an operation | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| Submit and verify a proof | [05-capabilities-proofs.md](05-capabilities-proofs.md) |
| Emit and query witness records | [06-witness-audit.md](06-witness-audit.md) |
| Debug a broken witness chain | [06-witness-audit.md](06-witness-audit.md), [14-troubleshooting.md](14-troubleshooting.md) |
| Understand how partitions are scheduled | [07-partitions-scheduling.md](07-partitions-scheduling.md) |
| Learn about the four memory tiers | [08-memory-model.md](08-memory-model.md) |
| Run WASM agents inside partitions | [09-wasm-agents.md](09-wasm-agents.md) |
| Harden a deployment for production | [10-security.md](10-security.md) |
| Run benchmarks and tune performance | [11-performance.md](11-performance.md) |
| Boot RVM on QEMU or real hardware | [12-bare-metal.md](12-bare-metal.md) |
| Understand what makes RVM novel | [13-advanced-exotic.md](13-advanced-exotic.md) |
| Split or merge partitions at runtime | [13-advanced-exotic.md](13-advanced-exotic.md) |
| Fix a build or runtime error | [14-troubleshooting.md](14-troubleshooting.md) |
| Look up a term I do not recognize | [15-glossary.md](15-glossary.md) |
| Find every chapter that covers a concept | [cross-reference.md](cross-reference.md) (this page) |
| Deploy on a 64 KB microcontroller | [12-bare-metal.md](12-bare-metal.md), [13-advanced-exotic.md](13-advanced-exotic.md) |
| Set up CI for an RVM fork | [12-bare-metal.md](12-bare-metal.md) |
| Choose the right witness signer for production | [10-security.md](10-security.md) |
| Reconstruct dormant memory from checkpoints | [08-memory-model.md](08-memory-model.md), [13-advanced-exotic.md](13-advanced-exotic.md) |

---

## Chapter List

For convenience, here is the complete table of contents for the user guide.

| # | Title | Focus |
|---|---|---|
| -- | [README.md](README.md) | User guide overview and navigation |
| 01 | [Quick Start](01-quickstart.md) | Five-minute build, test, boot |
| 02 | [Core Concepts](02-core-concepts.md) | Foundational theory and design philosophy |
| 03 | [Architecture](03-architecture.md) | Crate layers, data flow, boot sequence |
| 04 | [Crate Reference](04-crate-reference.md) | Per-crate API documentation |
| 05 | [Capabilities and Proofs](05-capabilities-proofs.md) | Three-tier proof system |
| 06 | [Witness and Audit](06-witness-audit.md) | Witness trail, hash chain, record format |
| 07 | [Partitions and Scheduling](07-partitions-scheduling.md) | Partition lifecycle, scheduler, IPC |
| 08 | [Memory Model](08-memory-model.md) | Four-tier memory, buddy allocator, reconstruction |
| 09 | [WASM Agents](09-wasm-agents.md) | WebAssembly runtime, quotas, migration |
| 10 | [Security](10-security.md) | Security gate, TEE, signers, attestation |
| 11 | [Performance](11-performance.md) | Benchmarks, build profiles, tuning |
| 12 | [Bare-Metal Deployment](12-bare-metal.md) | QEMU boot, linker script, hardware profiles |
| 13 | [Advanced and Exotic](13-advanced-exotic.md) | Six novel capabilities, fault classes, RuVector |
| 14 | [Troubleshooting](14-troubleshooting.md) | Common errors and solutions |
| 15 | [Glossary](15-glossary.md) | Alphabetical term definitions |
| -- | [Cross-Reference Index](cross-reference.md) | This page |
