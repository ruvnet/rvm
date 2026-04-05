# ADR-144: GPU Compute Support via cuda-rust-wasm

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core), ADR-134 (Witness Schema), ADR-135 (Proof Verifier)

---

## Context

RVM's coherence engine is compute-bound at scale. The mincut algorithm (ADR-132 DC-2, 50us budget, 32-node max) and coherence scoring operate on adjacency matrices and weighted sums that map directly to GPU workgroup parallelism. As partition counts grow toward the DC-12 logical limit of 4096, the CPU-only path becomes a scheduling bottleneck.

WASM agents running inside RVM partitions increasingly require GPU access for ML inference, rendering, and signal processing. No existing hypervisor provides proof-gated, capability-secured GPU access with per-partition isolation and DMA budget enforcement.

The `cuda-rust-wasm` crate (crates.io v0.1.7) provides a CUDA-to-Rust transpiler with multiple backends: WebGPU, CUDA, OpenCL, Vulkan, and WASM-SIMD. This allows a single kernel source to compile across all hardware tiers without separate shader toolchains.

### Problem Statement

1. **Coherence compute bottleneck**: MinCut on 32 nodes requires O(N^3) adjacency matrix operations per epoch. Batch scoring across hundreds of partitions is a parallel reduction. Both map to GPU workgroups but currently run single-threaded.
2. **No GPU isolation model**: Traditional hypervisors either pass through the entire GPU (SR-IOV) or provide no GPU access. Neither approach fits RVM's capability-gated, per-partition isolation model.
3. **Agent ML workloads**: WASM agents need GPU compute for inference but have no host function path to GPU hardware.
4. **Hardware tier mismatch**: RVM targets hardware from 64KB MCUs (Seed) to multi-GB appliances. GPU support must degrade gracefully across tiers without code-path divergence.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| cuda-rust-wasm | CUDA transpiler with WebGPU/WASM backends | Direct dependency; provides cross-tier GPU abstraction |
| NVIDIA vGPU | SR-IOV GPU partitioning | Baseline for GPU isolation; RVM adds capability gating |
| Intel GVT-g | Mediated GPU pass-through | Informs MMIO mediation approach |
| Firecracker | No GPU support | Gap that RVM fills |
| seL4 device capabilities | Capability-gated device access | Informs capability model for GPU |

---

## Decision

Add `rvm-gpu` as the 14th RVM crate, providing an optional GPU compute subsystem feature-gated at compile time (like `rvm-wasm`). GPU operations are capability-gated, budget-enforced, and witness-logged.

### Architecture (3 Layers)

```
+---------------------------------------------------------------------+
|                        Layer 3: Acceleration                         |
|  mincut_gpu   scoring_gpu   wasm_host_dispatch   custom_kernels     |
+---------------------------------------------------------------------+
         |              |              |               |
+---------------------------------------------------------------------+
|                    Layer 2: GpuManager                               |
|  GpuContext (per-partition)  |  GpuQueue  |  GpuBudget  | GpuKernel |
|  capability gate             |  command    |  quota      | lifecycle |
|  IOMMU isolation             |  submit     |  enforce    | compile   |
+---------------------------------------------------------------------+
         |              |              |               |
+---------------------------------------------------------------------+
|                     Layer 1: GpuOps (HAL)                            |
|  GpuDevice   GpuDeviceInfo   GpuCapabilities   GpuBuffer            |
|  discover()  enumerate()     query()            alloc/free           |
+---------------------------------------------------------------------+
         |              |              |               |
+---------------------------------------------------------------------+
|                   Hardware / Backend                                  |
|  WASM-SIMD (Seed)  |  WebGPU  |  CUDA  |  OpenCL  |  Vulkan        |
|  cpu fallback       |  browser |  NVIDIA|  cross   |  cross         |
+---------------------------------------------------------------------+
```

### Integration Points

```
rvm-types          rvm-gpu             rvm-coherence
+------------+     +---------------+   +---------------+
| DeviceClass|---->| GpuDevice     |   | MinCutBridge  |
| ::Graphics |     | GpuDeviceInfo |   | (50us budget) |
+------------+     +------+--------+   +-------+-------+
                          |                     |
rvm-cap            +------v--------+   +--------v------+
+------------+     | GpuContext    |   | mincut_gpu()  |
| CapRights  |---->| cap gate      |   | scoring_gpu() |
| EXECUTE    |     | budget check  |   | (GPU accel)   |
| WRITE      |     +------+--------+   +---------------+
+------------+            |
                          |
rvm-security       +------v--------+
+------------+     | GpuBudget    |
| DmaBudget  |<--->| compute_ns   |
| (DMA bytes)|     | memory_bytes |
+------------+     | transfer_bytes|
                   +------+--------+
rvm-witness               |
+------------+     +------v--------+
| WitnessRec |<----| GpuQueue     |
| (audit)    |     | kernel_launch |
+------------+     | mem_transfer  |
                   +---------------+

rvm-wasm
+------------+
| HostFunc   |     HostFunction::GpuSubmit (variant 8)
| (8 today)  |---> HostFunction::GpuAlloc  (variant 9)
+------------+     HostFunction::GpuQuery  (variant 10)

rvm-sched
+------------+
| SwitchCtx  |---> +gpu_state: Option<GpuContext> (lazy save)
+------------+
```

---

## Design Constraints

### DC-GPU-1: Capability-Gated Access

GPU access requires a valid capability token with `CapRights::EXECUTE | CapRights::WRITE` on a `CapType::Device` capability targeting the GPU device. Read-only queries (device info, budget remaining) require `CapRights::READ` only.

### DC-GPU-2: GPU Memory Isolation via IOMMU

Each partition's GPU memory is isolated through IOMMU page tables. The `GpuContext` maintains per-partition GPU address space mappings. A `regions_overlap_host` check runs before every buffer allocation to prevent guest GPU memory from aliasing host physical memory.

### DC-GPU-3: DMA Budget Enforcement

GPU DMA transfers count against the partition's existing `DmaBudget` (from `rvm-security/src/budget.rs`). Additionally, the `GpuBudget` tracks GPU-specific quotas: compute time (nanoseconds), GPU memory (bytes), and transfer bandwidth (bytes per epoch). Both budgets must pass before any GPU operation proceeds.

### DC-GPU-4: Lazy GPU Context Save/Restore

GPU context is saved/restored on partition switch only if the partition has active GPU state. The `SwitchContext` in `rvm-sched` gains an `Option<GpuContext>` field. Partitions that never touch the GPU pay zero save/restore cost.

### DC-GPU-5: All GPU Operations Witnessed

Every kernel launch, memory transfer, buffer allocation, and context switch involving GPU state emits a `WitnessRecord` with `ActionKind` variants for GPU operations. The witness record includes the partition ID, kernel ID, buffer sizes, and compute duration.

### DC-GPU-6: Feature-Gated, Zero Cost When Off

The `rvm-gpu` crate is not a default workspace member. It is included only when explicitly enabled. When disabled, no GPU code is compiled and no runtime cost is incurred. Feature gates: `webgpu`, `cuda`, `opencl`, `vulkan`, `wasm-simd`.

### DC-GPU-7: Tiered Backend Selection

| Hardware Profile | GPU Tier | Backend | Feature Flag |
|-----------------|----------|---------|-------------|
| Seed (64KB-1MB) | WasmSimd | CPU SIMD fallback | `wasm-simd` |
| Appliance (1-32GB) | WebGpu / Cuda | Real GPU hardware | `webgpu` / `cuda` |
| Chip (future) | Vulkan | Hardware GPU tiles | `vulkan` |

Backend selection is compile-time (feature flags) and runtime (device discovery). If a compiled backend finds no hardware, it returns `GpuError::DeviceNotFound` and the caller falls back to CPU.

---

## Components

### GpuDevice (Layer 1 — HAL)

Device discovery and capability query. Wraps MMIO-mapped GPU registers. Reports compute units, memory size, workgroup limits, and floating-point support.

### GpuContext (Layer 2 — per-partition)

Per-partition GPU state container. Holds the command queue, memory maps, active kernel list, and budget tracker. Created lazily on first GPU access. Destroyed on partition teardown.

### GpuKernel (Layer 2 — kernel lifecycle)

Compiled compute kernel handle. Kernels are compiled from `cuda-rust-wasm` source, assigned a `KernelId`, and bound to a partition. Launch configuration specifies workgroup dimensions and timeout.

### GpuBuffer (Layer 1 — memory)

Typed GPU memory buffer with usage flags (storage, uniform, vertex, index, indirect, copy-src, copy-dst). Validated against the partition's GPU memory budget before allocation.

### GpuQueue (Layer 2 — command submission)

Fixed-depth command queue for GPU operations. Commands include kernel launches, buffer copies, fills, barriers, and timestamp queries. Queue depth is bounded to prevent unbounded resource consumption.

### GpuBudget (Layer 2 — quota enforcement)

GPU-specific resource quota extending the existing `ResourceQuota` model. Tracks:
- `compute_ns`: total GPU compute time per epoch
- `memory_bytes`: total GPU memory allocated
- `transfer_bytes`: total bytes transferred between host and GPU per epoch
- `kernel_launches`: total kernel launches per epoch

All checked before allocation, recorded after completion. Reset per epoch.

### Acceleration Backends (Layer 3)

#### MinCut GPU Acceleration

The mincut adjacency matrix (`MINCUT_MAX_NODES=32`, so 32x32 = 1024 entries) fits in a single GPU workgroup's shared memory. The Stoer-Wagner merge step becomes a parallel maximum scan across one matrix row, reducing O(N) sequential scans to O(log N) parallel reductions.

```
CPU path:  O(N^2) iterations, each scanning N nodes = O(N^3)
GPU path:  O(N^2) iterations, each scanning log(N) = O(N^2 * log N)
           with 32 threads per workgroup
```

For 32 nodes, this reduces 32768 sequential operations to ~5120 parallel steps.

#### Scoring GPU Acceleration

Batch coherence scoring across P partitions is an embarrassingly parallel workload. Each partition's score is an independent ratio computation (internal_weight / total_weight). A single GPU dispatch scores all partitions in one launch.

```
CPU path:  P sequential score computations
GPU path:  1 dispatch, P workgroup invocations in parallel
```

---

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Malicious partition reads another's GPU memory | IOMMU page tables isolate per-partition GPU address spaces |
| GPU kernel runs indefinitely, starving scheduler | Kernel execution deadline (100ms default, DC-7 compatible) |
| Partition exhausts GPU memory | GpuBudget memory_bytes quota enforced before allocation |
| DMA transfer exfiltrates host memory | regions_overlap_host check + DmaBudget enforcement |
| Capability forgery grants unauthorized GPU access | CapToken with EXECUTE+WRITE required; checked before every operation |
| GPU driver vulnerability escalation | MMIO mediation; no direct hardware register access from partitions |

### Capability Requirements

| Operation | Required Rights | CapType |
|-----------|----------------|---------|
| Device discovery | READ | Device |
| Buffer allocate | WRITE | Device |
| Kernel launch | EXECUTE + WRITE | Device |
| Memory transfer | WRITE | Device |
| Context save/restore | READ + WRITE | Device |
| Budget query | READ | Device |

---

## Failure Modes

| Failure | Detection | Recovery | Witness |
|---------|-----------|----------|---------|
| Device not found | `enumerate()` returns empty | Fall back to CPU path | `GPU_DEVICE_NOT_FOUND` |
| Kernel timeout (>100ms) | Deadline timer fires | Kill kernel, mark context Error | `GPU_KERNEL_TIMEOUT` |
| GPU OOM | Allocation returns error | Return `GpuError::OutOfMemory` | `GPU_OOM` |
| Budget exceeded | Pre-check fails | Return `GpuError::BudgetExceeded` | `GPU_BUDGET_EXCEEDED` |
| IOMMU violation | Hardware fault | Kill partition, log forensics | `GPU_IOMMU_VIOLATION` |
| Queue full | Depth check fails | Return `GpuError::QueueFull` | `GPU_QUEUE_FULL` |
| Compilation failure | Compiler error | Return `GpuError::KernelCompilationFailed` | `GPU_COMPILE_FAIL` |
| Transfer failure | DMA error | Retry once, then fail partition | `GPU_TRANSFER_FAIL` |

---

## Benchmark Targets

| Metric | CPU Baseline | GPU Target | Speedup |
|--------|-------------|------------|---------|
| MinCut (32 nodes) | 45us | 8us | 5.6x |
| MinCut (16 nodes) | 12us | 4us | 3x |
| Batch scoring (256 partitions) | 200us | 15us | 13x |
| Batch scoring (1024 partitions) | 800us | 25us | 32x |
| Buffer alloc (4KB) | 500ns | 2us | 0.25x (overhead) |
| Kernel launch overhead | N/A | 10us | N/A |
| Context save (active) | N/A | 5us | N/A |
| Context save (inactive) | N/A | 0ns | N/A (skipped) |

Note: Buffer allocation is slower on GPU due to IOMMU setup. GPU acceleration is only beneficial for compute-heavy paths, not memory management.

---

## Consequences

### Positive

1. **Coherence engine scales**: MinCut and scoring gain 3-32x speedup on GPU-equipped hardware, allowing larger partition graphs within the 50us DC-2 budget.
2. **Agent ML workloads**: WASM agents gain a capability-secured path to GPU compute for inference and rendering.
3. **Unified kernel source**: `cuda-rust-wasm` transpilation means one kernel source compiles across all tiers.
4. **Zero cost when off**: Feature-gated design means Seed-profile builds pay nothing for GPU support they cannot use.
5. **Security model extends naturally**: Existing capability, budget, and witness infrastructure applies to GPU operations without new security primitives.

### Negative

1. **New dependency**: `cuda-rust-wasm` (0.1.7) is pre-1.0 and may have breaking changes.
2. **IOMMU complexity**: Per-partition GPU page tables add complexity to the memory subsystem.
3. **Testing surface**: GPU code paths require hardware or emulation for integration testing.
4. **Context switch cost**: Active GPU partitions pay a save/restore penalty (mitigated by lazy save).

### Neutral

1. **Crate count**: RVM grows from 13 to 14 crates.
2. **HostFunction enum**: Grows from 8 to 11 variants (GpuSubmit, GpuAlloc, GpuQuery).
3. **SwitchContext size**: Grows by `Option<GpuContext>` (0 bytes when None on most platforms).

---

## Implementation Plan

### Phase 1: Foundation (rvm-gpu crate)

1. Create `rvm-gpu` crate with types: `GpuDevice`, `GpuContext`, `GpuKernel`, `GpuBuffer`, `GpuQueue`, `GpuBudget`, `GpuError`.
2. Implement budget enforcement matching `DmaBudget` patterns from `rvm-security`.
3. Add `GpuTier` enum with compile-time feature selection.

### Phase 2: Coherence Acceleration

1. Implement `mincut_gpu()` — GPU-accelerated mincut with CPU fallback.
2. Implement `scoring_gpu()` — batch parallel scoring.
3. Benchmark against CPU baselines on CUDA and WebGPU backends.

### Phase 3: WASM Integration

1. Add `HostFunction::GpuSubmit`, `GpuAlloc`, `GpuQuery` variants (8, 9, 10).
2. Implement `GpuHostContext` trait extending `HostContext`.
3. Wire capability checks for GPU host functions.

### Phase 4: Scheduler Integration

1. Add `gpu_state: Option<GpuContext>` to `SwitchContext`.
2. Implement lazy save/restore on partition switch.
3. Add GPU budget to `ResourceQuota` epoch reset.

---

## References

- ADR-132: RVM Hypervisor Core (coherence domains, DC-1 through DC-14)
- ADR-134: Witness Schema and Log Format
- ADR-135: Proof Verifier Design
- `cuda-rust-wasm` crate: https://crates.io/crates/cuda-rust-wasm
- `rvm-security/src/budget.rs`: DmaBudget and ResourceQuota patterns
- `rvm-coherence/src/mincut.rs`: MinCutBridge, MINCUT_MAX_NODES=32
- `rvm-coherence/src/scoring.rs`: compute_coherence_score
- `rvm-wasm/src/host_functions.rs`: HostFunction enum (variants 0-7)
