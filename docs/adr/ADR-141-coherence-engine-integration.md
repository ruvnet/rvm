# ADR-141: Coherence Engine Integration

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

ADR-132 introduces coherence domains as RVM's primary abstraction. The coherence engine is the subsystem that maintains the runtime graph, computes scores and cut pressures, and recommends split/merge actions. However, ADR-132 also mandates that the coherence engine is optional (DC-1): the kernel must boot and run without it.

This creates a dual requirement: the engine must be powerful enough to drive intelligent partition placement, but cleanly separable so the kernel degrades gracefully when the engine is absent, over-budget, or failed.

## Decision

### Architecture

The coherence engine is implemented as Layer 2 in the RVM stack (above the kernel, below execution adapters). It consists of five collaborating modules:

```
CoherenceEngine (unified entry point)
  |
  +-- CoherenceGraph    (fixed-size adjacency structure)
  +-- MinCutBackend     (pluggable: Stoer-Wagner builtin or RuVector)
  +-- CoherenceBackend  (pluggable: ratio-based builtin or spectral)
  +-- PressureModule    (cut pressure and merge signal computation)
  +-- AdaptiveEngine    (recomputation frequency control)
```

### CoherenceGraph

A fixed-size directed weighted graph with compile-time capacity bounds:
- `MAX_NODES = 32` partitions tracked by the engine.
- `MAX_EDGES = 128` directed communication edges.
- Nodes map to `PartitionId` values; edges carry `u64` weights representing communication volume.
- Adjacency-matrix-backed `find_directed_edge()` provides O(1) existence check.
- Edge weights decay by 5% (500 basis points) per epoch to prevent stale communication patterns from dominating.

The graph uses `NodeIdx` and `EdgeIdx` (both `u16`) for internal indexing, with linked-list adjacency for edge traversal. Zero heap allocation; fully stack-allocated.

### EmaFilter

Coherence scores are smoothed using an exponential moving average (EMA) filter:

```
new_score = alpha * sample + (1 - alpha) * old_score
```

Alpha is expressed in basis points (0-10000) to avoid floating-point in `no_std`. The `EmaFilter` operates entirely in fixed-point arithmetic. This smooths out transient communication spikes that would otherwise cause premature split/merge decisions.

### Scoring

The `compute_coherence_score()` function computes a ratio-based score:

```
score = internal_weight / total_weight
```

Where `internal_weight` is the sum of edge weights between nodes within the same partition's neighborhood, and `total_weight` includes all edges touching the partition. A score of 10000 basis points means fully internal (no cross-partition traffic); 0 means fully external.

The `recompute_all_scores()` function batch-recomputes scores for all active partitions.

### Cut Pressure

Cut pressure measures how much a partition's communication pattern suggests it should be split:

```
pressure = external_weight / total_weight * 10000  (basis points)
```

- If pressure exceeds `SPLIT_THRESHOLD_BP` (7500 default), the engine recommends splitting.
- If mutual coherence between two partitions exceeds `MERGE_COHERENCE_THRESHOLD_BP` (7000 default), the engine recommends merging.

The `evaluate_merge()` function checks bidirectional edge weights to compute mutual coherence.

### MinCut

The builtin MinCut uses a budgeted Stoer-Wagner heuristic (`MinCutBridge`). DC-2 constrains mincut computation to 50 microseconds per scheduler epoch. If the budget is exceeded:

1. The last known cut is used.
2. A `degraded_flag` is set.
3. A `MINCUT_BUDGET_EXCEEDED` witness is emitted.

The `MinCutResult` reports the two partition sets (left/right), the cut weight, and whether the computation completed within budget.

### Adaptive Recomputation

The `AdaptiveCoherenceEngine` adjusts recomputation frequency based on CPU load:

| CPU Load | Recomputation Interval |
|----------|----------------------|
| < 50% | Every epoch |
| 50-80% | Every 2 epochs |
| > 80% | Every 4 epochs |

This prevents the coherence engine from consuming excessive CPU during high-load periods. The adaptive engine always computes on the first epoch after creation.

### Pluggable Backends

Two trait abstractions enable backend swapping:

**`MinCutBackend`**: Pluggable minimum cut computation.
- `BuiltinMinCut`: Self-contained Stoer-Wagner (always available).
- `RuVectorMinCut` (feature `ruvector`): Delegates to ruvector-mincut's subpolynomial dynamic mincut. Currently stubs to builtin until ruvector gains `no_std` support.

**`CoherenceBackend`**: Pluggable coherence scoring.
- `BuiltinCoherence`: Ratio-based `internal_weight / total_weight`.
- `SpectralCoherence` (feature `ruvector`): Will use Fiedler vector / algebraic connectivity from ruvector-coherence. Currently stubs to builtin.

Type aliases provide convenience:
- `DefaultCoherenceEngine` = builtin Stoer-Wagner + ratio scoring.
- `RuVectorCoherenceEngine` = ruvector mincut + spectral scoring.

### Engine Lifecycle

```rust
engine.add_partition(id)              // Register partition in graph
engine.record_communication(a, b, w)  // Record directed edge or increment weight
engine.tick(cpu_load)                 // Advance epoch, maybe recompute
engine.score(id)                      // Read latest coherence score
engine.pressure(id)                   // Read latest cut pressure
engine.recommend()                    // Get split/merge recommendation
```

Each `tick()` returns a `CoherenceDecision`:
- `NoAction` -- no split or merge warranted.
- `SplitRecommended { partition, pressure }` -- partition should be split.
- `MergeRecommended { a, b, mutual_coherence }` -- two partitions should merge.

### DC-1 Degraded Mode

When the coherence engine is not present:
- Split/merge operations are disabled.
- Scheduler uses `deadline_urgency` only (`cut_pressure_boost = 0`).
- Memory tiers use static thresholds (see ADR-136).
- A `DEGRADED_MODE_ENTERED` witness is emitted once.

This is the **guaranteed baseline**: RVM is always functional without intelligence.

### RuVector Integration

The ruvector ecosystem provides three crates relevant to the coherence engine:

| Crate | Usage | Status |
|-------|-------|--------|
| `ruvector-mincut` | Subpolynomial dynamic MinCut | Stub (pending `no_std`) |
| `ruvector-sparsifier` | Sparse graph representation | Planned |
| `ruvector-solver` | Spectral analysis, coherence scoring | Stub (pending `no_std`) |

The `bridge.rs` module implements the translation layer: it exports the RVM `CoherenceGraph` adjacency structure to the ruvector API format and converts results back. The backend trait abstraction ensures that switching from builtin to ruvector requires no changes to the engine core.

## Consequences

### Positive

- **Clean separation** (DC-1, DC-5): The coherence engine is a pure optimization layer. The kernel never calls into it on the critical scheduling path; it reads cached scores/pressures that the engine computed asynchronously.
- **Pluggable backends** enable gradual migration from builtin algorithms to ruvector's more sophisticated implementations without modifying the engine core.
- **Adaptive recomputation** prevents the engine from becoming a scheduling bottleneck under high CPU load.
- **Fixed-point arithmetic** throughout (basis points, no floating-point) ensures deterministic behavior on all targets.

### Negative

- **32-partition engine limit** is lower than the 256-partition hardware limit. The engine tracks the hottest partitions; the rest use stale or default scores.
- **Stoer-Wagner is O(V^3)**: For 32 nodes this is acceptable, but scaling beyond requires the ruvector subpolynomial algorithm.
- **5% per-epoch edge decay** is a heuristic. Too aggressive and communication patterns are forgotten; too conservative and stale edges dominate. The decay rate is a constant, not tunable at runtime.

### Neutral

- The ruvector stubs currently delegate to builtin implementations, so `DefaultCoherenceEngine` and `RuVectorCoherenceEngine` produce identical results. This will diverge when ruvector gains `no_std` support.

## References

- ADR-132: RVM Hypervisor Core (DC-1, DC-2, DC-4, DC-5, DC-6)
- ADR-133: Partition Object Model (split/merge preconditions)
- ADR-136: Memory Hierarchy (coherence-driven tier placement)
- `crates/rvm-coherence/src/lib.rs` -- Module root, EmaFilter, SensorReading
- `crates/rvm-coherence/src/graph.rs` -- CoherenceGraph
- `crates/rvm-coherence/src/engine.rs` -- CoherenceEngine, DefaultCoherenceEngine
- `crates/rvm-coherence/src/bridge.rs` -- MinCutBackend, CoherenceBackend traits
- `crates/rvm-coherence/src/scoring.rs` -- Ratio-based coherence scoring
- `crates/rvm-coherence/src/pressure.rs` -- Cut pressure and merge signals
- `crates/rvm-coherence/src/mincut.rs` -- Stoer-Wagner MinCutBridge
- `crates/rvm-coherence/src/adaptive.rs` -- Adaptive recomputation engine
