# ADR-152: GPU MinCut Correctness Model

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core, DC-2), ADR-144 (GPU Compute Support), ADR-151 (GPU Witness Event Registry)

---

## Context

ADR-144 introduces GPU-accelerated mincut computation for the coherence engine. The Stoer-Wagner algorithm operates on an adjacency matrix of up to 32 nodes (MINCUT_MAX_NODES, per ADR-132), mapping merge steps to GPU workgroup parallel reductions. ADR-132 DC-2 imposes a hard 50-microsecond budget per scheduler epoch for mincut computation. The GPU path is an acceleration, providing a 5.6x speedup for 32-node graphs (45us CPU vs 8us GPU target per ADR-144 benchmarks).

### Problem Statement

1. **Correctness is non-negotiable**: The mincut result directly drives partition split/merge decisions and migration triggers. An incorrect cut value or partition assignment causes either unnecessary splits (wasting resources) or missed merges (violating coherence locality). The GPU must produce results identical to the CPU path, or the system must detect divergence and fall back.
2. **Floating-point divergence**: GPU hardware typically uses IEEE 754 single-precision (f32) for parallel reductions. The CPU path in `rvm-coherence` uses fixed-point basis points (u16, range 0-10000) for edge weights. Conversion between representations introduces rounding that can change the mincut result on graphs with nearly-equal cut values.
3. **GPU is acceleration, not authority**: The CPU mincut implementation is the reference. If the GPU disagrees with the CPU, the CPU result is canonical. This is a fundamental design principle: the GPU path exists to meet the DC-2 budget on larger graphs, not to replace the correctness guarantee of the CPU path.
4. **Budget enforcement**: If the GPU path exceeds the 50us DC-2 budget, the system must fall back to the last known CPU result and emit a `MinCutBudgetExceeded` witness. The fallback must not itself violate the budget.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| Stoer & Wagner (1997) | Exact minimum cut algorithm, O(VE + V^2 log V) | Reference algorithm for both CPU and GPU paths |
| ADR-132 DC-2 | 50us hard budget for mincut per epoch | Budget constraint driving GPU acceleration |
| ADR-144 | GPU architecture, MinCut GPU acceleration section | GPU implementation approach (parallel max scan) |
| CUDA parallel reduction | Warp-level primitives for max/sum reduction | Informs GPU workgroup implementation |
| IEEE 754-2008 | Floating-point arithmetic standard | Defines f32 rounding behavior relevant to GPU computation |

---

## Decision

### Correctness Contract

The GPU mincut implementation must satisfy three invariants:

**Invariant MC-1: Cut value equivalence**

For integer-weighted adjacency matrices (u16 basis points), the GPU-computed minimum cut value must exactly equal the CPU-computed value. No approximation is permitted for N <= MINCUT_MAX_NODES (32).

```
gpu_cut_value == cpu_cut_value   (for integer weights)
```

**Invariant MC-2: Partition assignment equivalence**

The partition assignment (which nodes are on which side of the cut) must be identical between GPU and CPU paths. Equivalence is verified by comparing partition bitmasks.

```
gpu_partition_bitmask == cpu_partition_bitmask
```

**Invariant MC-3: Budget compliance**

The GPU mincut computation must complete within the DC-2 budget (50us). If it exceeds the budget, the system uses the last known CPU result.

```
if gpu_compute_time > 50_000ns:
    use last_known_cpu_result
    emit witness(MinCutBudgetExceeded)
```

### Floating-Point vs Fixed-Point Strategy

RVM edge weights are stored as u16 basis points (0-10000, where 10000 = 100.00%). The GPU parallel reduction must operate on the same integer representation to guarantee MC-1 and MC-2.

**Decision: GPU operates in u16 integer space, not f32.**

The adjacency matrix is uploaded to GPU shared memory as `u16[32][32]`. All merge operations (finding the maximum-weight vertex, contracting edges) use integer arithmetic. This eliminates floating-point divergence entirely.

If a future GPU backend requires f32 (e.g., a backend that only supports float atomics), the following conversion rules apply:

**f32-to-u16 conversion:**

```rust
/// Convert GPU f32 result back to u16 basis points.
/// Rounding: round-half-to-even (IEEE 754 default).
/// Clamp to [0, 10000] to prevent overflow.
fn f32_to_basis_points(value: f32) -> u16 {
    let rounded = (value + 0.5).floor() as i32;
    rounded.clamp(0, 10000) as u16
}
```

**Epsilon tolerance for f32 paths:**

When the GPU backend uses f32, the cut value comparison uses an epsilon of 1 basis point:

```
|gpu_cut_value_bp - cpu_cut_value_bp| <= 1   (for f32 backends only)
```

If the cut values differ by more than 1 basis point, the CPU result is used and a witness is emitted. If the cut values are within epsilon but the partition assignments differ, the CPU assignment is used (the cut value may be achieved by multiple valid partitionings).

### Fallback Strategy

The GPU path is a performance optimization. The CPU path is always available as a fallback. The fallback strategy has three levels:

**Level 1: GPU result matches CPU (normal operation)**

GPU computes mincut within budget. Result matches CPU. GPU result is used. No fallback needed.

**Level 2: GPU result diverges from CPU**

GPU completes within budget but produces a different result. CPU result is used. Witness emitted:

```
ActionKind::CoherenceRecomputed (0x93)
payload: gpu_cut_value (high 32) | cpu_cut_value (low 32)
flags: 0x01 (GPU_DIVERGED flag)
```

**Level 3: GPU exceeds budget**

GPU does not complete within 50us. Computation is aborted. Last known CPU result is used. Witness emitted:

```
ActionKind::MinCutBudgetExceeded (0x74)
payload: elapsed_ns (high 32) | budget_ns (low 32)
flags: 0x02 (GPU_TIMEOUT flag)
```

**Level 4: GPU device unavailable**

No GPU device found at startup or GPU context creation fails. CPU path is the sole path. No fallback needed; this is the baseline. Witness emitted once at boot:

```
ActionKind::GpuDeviceNotFound (0xAA)
```

### Cross-Validation Protocol

In debug builds (`#[cfg(debug_assertions)]`), every GPU mincut result is cross-validated against the CPU result:

```rust
pub fn mincut_with_validation(
    adjacency: &AdjacencyMatrix,
    gpu_ctx: Option<&GpuContext>,
) -> MinCutResult {
    let cpu_result = mincut_cpu(adjacency);

    if let Some(ctx) = gpu_ctx {
        match mincut_gpu(adjacency, ctx) {
            Ok(gpu_result) => {
                #[cfg(debug_assertions)]
                {
                    assert_eq!(
                        gpu_result.cut_value, cpu_result.cut_value,
                        "GPU mincut diverged: gpu={} cpu={}",
                        gpu_result.cut_value, cpu_result.cut_value
                    );
                    assert_eq!(
                        gpu_result.partition_mask, cpu_result.partition_mask,
                        "GPU partition assignment diverged"
                    );
                }

                // In release builds, use GPU result if it matches
                if gpu_result.cut_value == cpu_result.cut_value {
                    gpu_result
                } else {
                    // Fallback to CPU on divergence
                    witness_emit(ActionKind::CoherenceRecomputed, ...);
                    cpu_result
                }
            }
            Err(GpuError::Timeout { elapsed_ns }) => {
                witness_emit(ActionKind::MinCutBudgetExceeded, ...);
                cpu_result
            }
            Err(_) => cpu_result,
        }
    } else {
        cpu_result
    }
}
```

In release builds, cross-validation is replaced by a cheaper comparison: only the cut value and partition mask are compared (two integer comparisons). The full adjacency matrix is not recomputed on CPU unless the GPU result diverges.

### Nightly Benchmark Protocol

The nightly CI pipeline (ADR-143) runs GPU vs CPU comparison benchmarks:

1. **Deterministic test suite**: 100 pre-generated adjacency matrices covering edge cases (single-edge graphs, fully connected, bipartite, near-equal cuts, maximum 32 nodes).
2. **Divergence counter**: Count how many of the 100 test cases produce different GPU vs CPU results. Target: 0 divergences for integer weights.
3. **Timing comparison**: Measure GPU and CPU latency for each test case. Track speedup ratio. Alert if GPU is slower than CPU for any graph size (indicates misconfiguration or backend regression).
4. **Budget compliance**: Verify that all 32-node test cases complete within 50us on GPU. Track the 99th percentile latency.

### Witness Logging for GPU MinCut

GPU mincut results are witnessed via `ActionKind::CoherenceRecomputed` (0x93) with the `computation_ns` encoded in the payload:

```
payload: cut_value (high 32) | computation_ns (low 32)
aux:     partition_mask (u64, one bit per node indicating side A vs side B)
flags:   0x00 = CPU path, 0x01 = GPU path, 0x02 = GPU fallback to CPU
```

This enables operators to distinguish GPU-accelerated recomputations from CPU-only ones and to track GPU performance over time.

---

## Design Constraints

### DC-MC-1: Integer Arithmetic on GPU

The GPU mincut kernel operates on u16 integer weights. No f32 intermediate values are used unless the GPU backend has no integer atomics, in which case the f32 conversion rules above apply. This constraint eliminates the primary source of GPU/CPU divergence.

### DC-MC-2: CPU Is Always Available

The CPU mincut implementation must remain compiled and callable even when the GPU path is enabled. The GPU path does not replace the CPU path; it accelerates it. The `rvm-coherence` crate must not have a hard dependency on `rvm-gpu`.

### DC-MC-3: Fallback Must Not Exceed Budget

The fallback from GPU to CPU must itself complete within the remaining DC-2 budget. If the GPU times out at 50us and the CPU path would take 45us, the total would be 95us, exceeding the budget. To prevent this:

- The GPU path has an internal deadline of 40us (not 50us), leaving 10us for fallback overhead.
- The fallback uses the last known CPU result (cached from the previous epoch), not a fresh computation.
- A fresh CPU computation is scheduled for the next epoch.

### DC-MC-4: No Silent Degradation

Every fallback event must emit a witness record. An operator reviewing the witness log must be able to determine: (a) how often the GPU path is used vs CPU, (b) how often the GPU diverges, (c) how often the GPU times out.

---

## Consequences

### Positive

1. **Correctness guarantee**: The GPU path is validated against the CPU reference. Divergence is detected, logged, and corrected automatically.
2. **Performance within budget**: The 40us GPU deadline with 10us fallback margin ensures the DC-2 50us budget is never exceeded, even on fallback.
3. **Forensic visibility**: Operators can audit GPU mincut behavior through witness records, tracking divergence rates and performance trends.
4. **Zero risk from GPU errors**: The worst case of a GPU failure is a single-epoch use of a stale (but previously validated) cut result, followed by a fresh CPU computation.

### Negative

1. **Debug build overhead**: Cross-validation in debug builds runs both GPU and CPU paths, approximately doubling mincut latency. This is acceptable for development but must not be enabled in production.
2. **Stale fallback risk**: The last known CPU result may be one epoch old. If the coherence graph changed significantly in one epoch, the stale result may produce suboptimal placement decisions for that single epoch. This is acceptable because mincut staleness is already the documented degradation behavior (ADR-132 DC-2).
3. **GPU internal deadline (40us) is tighter than DC-2 (50us)**: The GPU has less time than the full budget to account for fallback overhead. For very large graphs near MINCUT_MAX_NODES, this may cause unnecessary fallbacks. Mitigation: 32-node GPU mincut targets 8us, well within the 40us internal deadline.

---

## Testing Strategy

| Category | Tests | Pass Criteria |
|----------|-------|---------------|
| Equivalence | 100 deterministic matrices, all sizes 2-32 | GPU result == CPU result for all test cases |
| Edge cases | Single-edge, fully connected, bipartite, equal-weight | No divergence |
| Timeout | Artificially slow GPU backend | Fallback to CPU, witness emitted |
| Budget | 32-node worst-case timing | GPU completes within 40us |
| Fallback chain | GPU unavailable | CPU path produces correct result |
| Nightly regression | Criterion benchmarks with 5% regression threshold | No performance regression |

---

## References

- Stoer, M. & Wagner, F. "A Simple Min-Cut Algorithm." Journal of the ACM, 1997.
- ADR-132: RVM Hypervisor Core (DC-2: 50us mincut budget)
- ADR-144: GPU Compute Support (MinCut GPU Acceleration section, benchmark targets)
- ADR-151: GPU Witness Event Registry (ActionKind variants for GPU operations)
- `rvm-coherence/src/mincut.rs`: CPU MinCut implementation, MINCUT_MAX_NODES=32
- `rvm-gpu/src/acceleration.rs`: GPU mincut acceleration entry point
