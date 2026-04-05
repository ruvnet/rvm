# RuVector Integration Map

RVM integrates with the [RuVector](https://github.com/ruvnet/RuVector) ecosystem
via the `ruvector/` submodule. This document maps RuVector components to their
RVM usage.

## Submodule

```
ruvector/    → https://github.com/ruvnet/RuVector (submodule)
```

## Core Crates Used by RVM

| RuVector Crate | Path | RVM Usage |
|----------------|------|-----------|
| **ruvector-mincut** | `ruvector/crates/ruvector-mincut/` | Partition placement, isolation decisions, coherence graph mincut |
| **ruvector-sparsifier** | `ruvector/crates/ruvector-sparsifier/` | Compressed shadow graph for Laplacian operations |
| **ruvector-solver** | `ruvector/crates/ruvector-solver/` | Effective resistance → coherence scores |
| **ruvector-coherence** | `ruvector/crates/ruvector-coherence/` | Spectral coherence tracking, engine backend |

## RVF Package Format

| RVF Crate | Path | Purpose |
|-----------|------|---------|
| **rvf-types** | `ruvector/crates/rvf/rvf-types/` | Core RVF types: manifest, vectors, metadata |
| **rvf-crypto** | `ruvector/crates/rvf/rvf-crypto/` | Cryptographic signing and verification |
| **rvf-manifest** | `ruvector/crates/rvf/rvf-manifest/` | Package manifest parsing and generation |
| **rvf-index** | `ruvector/crates/rvf/rvf-index/` | HNSW vector indexing |
| **rvf-runtime** | `ruvector/crates/rvf/rvf-runtime/` | Runtime execution environment |
| **rvf-kernel** | `ruvector/crates/rvf/rvf-kernel/` | Kernel-level RVF integration |
| **rvf-quant** | `ruvector/crates/rvf/rvf-quant/` | Quantization for memory reduction |
| **rvf-wasm** | `ruvector/crates/rvf/rvf-wasm/` | WASM runtime for RVF containers |
| **rvf-cli** | `ruvector/crates/rvf/rvf-cli/` | CLI for RVF operations |
| **rvf-wire** | `ruvector/crates/rvf/rvf-wire/` | Wire protocol for RVF transfer |
| **rvf-federation** | `ruvector/crates/rvf/rvf-federation/` | Federated RVF distribution |
| **rvf-adapters** | `ruvector/crates/rvf/rvf-adapters/` | Adapter layer for external formats |

## RuVix Kernel Primitives

| Component | Path | Purpose |
|-----------|------|---------|
| **ruvix** | `ruvector/crates/ruvix/` | Kernel primitives (Task, Capability, Region, Queue, Timer, Proof) |
| **aarch64-boot** | `ruvector/crates/ruvix/aarch64-boot/` | AArch64 bare-metal boot |

## Architecture Decision Records

| ADR | Path | Relevance |
|-----|------|-----------|
| ADR-001 | `ruvector/docs/adr/ADR-001-ruvector-core-architecture.md` | Core architecture that RVM builds upon |
| ADR-006 | `ruvector/docs/adr/ADR-006-memory-management.md` | Memory model informing RVM's 4-tier system |
| ADR-007 | `ruvector/docs/adr/ADR-007-security-review-technical-debt.md` | Security patterns adopted by RVM |
| ADR-012 | `ruvector/docs/adr/ADR-012-security-remediation.md` | Security remediation patterns |
| ADR-014 | `ruvector/docs/adr/ADR-014-coherence-engine.md` | Coherence engine design inherited by RVM |
| ADR-015 | `ruvector/docs/adr/ADR-015-coherence-gated-transformer.md` | Gated transformer architecture |

## Research & Documentation

| Resource | Path | Content |
|----------|------|---------|
| Architecture overview | `ruvector/docs/architecture/` | System architecture documents |
| Benchmarks | `ruvector/docs/benchmarks/` | Performance benchmark results |
| Analysis | `ruvector/docs/analysis/` | Code and performance analysis |
| API docs | `ruvector/docs/api/` | API reference documentation |
| Cloud architecture | `ruvector/docs/cloud-architecture/` | Cloud deployment patterns |

## Quick Access

```bash
# Browse RVF crates
ls ruvector/crates/rvf/

# Browse RuVix kernel primitives
ls ruvector/crates/ruvix/crates/

# Browse mincut algorithm
ls ruvector/crates/ruvector-mincut/src/

# Read coherence ADR
cat ruvector/docs/adr/ADR-014-coherence-engine.md

# Read core architecture
cat ruvector/docs/adr/ADR-001-ruvector-core-architecture.md
```

## Updating the Submodule

```bash
# Pull latest RuVector
cd ruvector && git pull origin main && cd ..
git add ruvector && git commit -m "chore: update ruvector submodule"
```
