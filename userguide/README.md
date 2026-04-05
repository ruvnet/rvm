# RVM User Guide -- The Virtual Machine for the Agentic Age

Traditional hypervisors were designed for static server workloads: long-running VMs with predictable resource needs. AI agents are different -- they spawn in milliseconds, communicate in dense shifting graphs, share context across trust boundaries, and die without warning. RVM replaces VMs with **coherence domains**: lightweight, graph-structured partitions whose isolation, scheduling, and memory placement are driven by how agents actually communicate. When two agents start talking more, RVM moves them closer. When trust drops, RVM splits them apart. Every mutation is proof-gated. Every action is witnessed. The system understands its own structure.

---

## How to Use This Guide

Choose a path based on your goals:

| Path | Start Here | You Will Learn |
|------|-----------|----------------|
| **Quick Start** | [01 -- Quick Start](01-quickstart.md) | Clone, build, boot in QEMU, and run your first partition in 5 minutes |
| **Deep Dive** | [02 -- Core Concepts](02-core-concepts.md) then [03 -- Architecture](03-architecture.md) | How RVM thinks, why it exists, and how the pieces fit together |
| **Reference** | [04 -- Crate Reference](04-crate-reference.md) then [15 -- Glossary](15-glossary.md) | API surface, type catalog, and precise definitions |

Every chapter ends with cross-reference links to related sections. If you prefer to navigate by topic rather than chapter order, use the [Cross-Reference Index](cross-reference.md).

---

## Table of Contents

| # | Chapter | Description |
|---|---------|-------------|
| -- | **[README](README.md)** | This page: guide overview, paths, prerequisites |
| 01 | [Quick Start](01-quickstart.md) | Clone, build, boot in QEMU, and explore the API in 5 minutes |
| 02 | [Core Concepts](02-core-concepts.md) | Partitions, capabilities, witnesses, proofs, coherence, and memory tiers explained in plain language |
| 03 | [Architecture](03-architecture.md) | Crate layering, dependency graph, four-layer stack, and first-class kernel objects |
| 04 | [Crate Reference](04-crate-reference.md) | Per-crate API surface: public types, traits, constants, and feature flags |
| 05 | [Capabilities and Proofs](05-capabilities-proofs.md) | The three-tier proof system (P1/P2/P3), capability derivation trees, and delegation rules |
| 06 | [Witness and Audit](06-witness-audit.md) | 64-byte witness records, hash chains, HMAC signing, replay, and forensic queries |
| 07 | [Partitions and Scheduling](07-partitions-scheduling.md) | Partition lifecycle, split/merge semantics, 2-signal scheduler, and scheduling modes |
| 08 | [Memory Model](08-memory-model.md) | Four-tier memory (Hot/Warm/Dormant/Cold), buddy allocator, reconstruction pipeline |
| 09 | [WASM Agents](09-wasm-agents.md) | WebAssembly guest runtime, 7-state agent lifecycle, HostContext trait |
| 10 | [Security](10-security.md) | Unified security gate, attestation chains, DMA budgets, and threat model |
| 11 | [Performance](11-performance.md) | Benchmark results, criterion setup, profiling, and optimization strategies |
| 12 | [Bare Metal](12-bare-metal.md) | AArch64 boot, EL2 entry, PL011 UART, GICv2, stage-2 page tables, linker script |
| 13 | [Advanced and Exotic](13-advanced-exotic.md) | Seed profile (64 KB), Appliance deployment, Chip targets, RuVector integration |
| 14 | [Troubleshooting](14-troubleshooting.md) | Common build errors, QEMU issues, debugging tips, and FAQ |
| 15 | [Glossary](15-glossary.md) | Precise definitions for every RVM-specific term |
| -- | [Cross-Reference Index](cross-reference.md) | Topic-to-chapter mapping for quick navigation |

---

## Key Concepts at a Glance

> **Six ideas that make RVM different from every other hypervisor.**

- **Coherence Domains** -- Partitions are not VMs. They have no emulated hardware. A partition is a graph-structured container whose boundaries shift dynamically based on agent communication patterns. See [Core Concepts](02-core-concepts.md).

- **Capabilities** -- Every access right is represented by an unforgeable kernel-resident token with 7 possible rights (READ, WRITE, GRANT, REVOKE, EXECUTE, PROVE, GRANT_ONCE). Rights can only be attenuated, never amplified. Delegation depth is bounded at 8 levels. See [Capabilities and Proofs](05-capabilities-proofs.md).

- **Witness Trail** -- Every privileged action emits a fixed 64-byte, hash-chained audit record before the mutation commits. If witness emission fails, the mutation does not proceed. The entire history is tamper-evident and deterministically replayable. See [Witness and Audit](06-witness-audit.md).

- **Proof Gates** -- No state mutation happens without a valid proof token. Three tiers trade off speed for assurance: P1 capability check (<1 us), P2 policy validation (<100 us), P3 deep derivation chain / deferred ZK. See [Capabilities and Proofs](05-capabilities-proofs.md).

- **Memory Tiers** -- Memory lives in four explicit tiers (Hot, Warm, Dormant, Cold) instead of a demand-paging black box. Dormant memory is stored as a checkpoint plus delta-compressed witness trail and can be reconstructed days later. See [Memory Model](08-memory-model.md).

- **Partitions** -- The unit of scheduling, isolation, migration, and fault containment. Partitions can split along graph-theoretic mincut boundaries when coupling drops, and merge when coherence rises. Every lifecycle transition is witnessed. See [Partitions and Scheduling](07-partitions-scheduling.md).

---

## Cross-Reference Index

For a topic-based lookup across all chapters, see the [Cross-Reference Index](cross-reference.md).

---

## MCP Documentation Tools

The `mcp/` directory contains tooling for programmatic documentation access via the Model Context Protocol. See [mcp/](mcp/) for available tools and integration instructions.

---

## Prerequisites

Before building or running RVM, make sure you have the following installed:

| Requirement | Minimum Version | Purpose |
|-------------|----------------|---------|
| **Rust** | 1.77+ | Compiler toolchain (`rustup` recommended) |
| **AArch64 target** | -- | `rustup target add aarch64-unknown-none` |
| **cargo-binutils** | -- | `cargo install cargo-binutils` + `rustup component add llvm-tools` |
| **QEMU** | 8.0+ | `qemu-system-aarch64` for bare-metal emulation |

Optional but recommended:

| Tool | Purpose |
|------|---------|
| `criterion` | Already a dev-dependency; used by `cargo bench` |
| `proptest` | Already a dev-dependency; used in property-based tests |
| `rust-analyzer` | IDE support for navigating `no_std` crate graph |

All RVM crates are `#![no_std]` and `#![forbid(unsafe_code)]` by default. No C toolchain, no Linux headers, no external libraries are required for host builds or tests.

---

## Quick Links

- **Repository**: <https://github.com/ruvnet/rvm>
- **License**: MIT OR Apache-2.0
- **ADR References**: ADR-132 through ADR-142
- **Start building**: [Quick Start](01-quickstart.md)
