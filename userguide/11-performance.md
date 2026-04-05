# Performance: Benchmarks and Tuning

RVM is designed for predictable, low-latency operation on bare-metal hardware.
Every hot-path operation has an ADR-specified time budget, and the benchmark
suite proves that the implementation meets or exceeds those budgets -- often by
orders of magnitude. This chapter walks through the benchmark suite, explains
the build profiles that enable peak throughput, and provides tuning guidance.

For the overall architecture that makes this performance possible, see
[Architecture](03-architecture.md). For the partition switch hot path in
particular, see [Partitions and Scheduling](07-partitions-scheduling.md).

---

## 1. Benchmark Suite

RVM ships 11 Criterion benchmarks in `benches/benches/rvm_bench.rs`. Each
benchmark targets a specific hot-path operation called out in the ADR
documents (ADR-132, ADR-134, ADR-135).

| Benchmark | What It Measures | ADR Target | Measured | Headroom |
|---|---|---|---|---|
| `bench_witness_emit` | Single witness record emission into the ring buffer | < 500 ns | ~17 ns | 29x faster |
| `bench_p1_verify` | P1 capability check (`verify_p1` on a `CapabilityManager`) | < 1 us | < 1 ns | 1000x faster |
| `bench_p2_verify` | P2 proof engine pipeline (P1 + P2 + witness emission) | < 100 us | ~996 ns | 100x faster |
| `bench_partition_switch` | Partition context switch (enqueue + dequeue cycle) | < 10 us | ~6 ns | 1600x faster |
| `bench_coherence_score` | Coherence score computation on a 16-node graph | budgeted | ~84 ns | -- |
| `bench_mincut` | MinCut on a 16-node chain graph | < 50 us | ~331 ns | 150x faster |
| `bench_buddy_alloc` | Buddy allocator alloc/free cycle | fast | ~184 ns | -- |
| `bench_fnv1a_hash` | FNV-1a hash of 64 bytes | fast | ~28 ns | -- |
| `bench_security_gate` | P1 security gate pass (`check_and_execute`) | fast | ~17 ns | -- |
| `bench_witness_verify_chain` | Verification of a 64-record witness chain | fast | ~892 ns | -- |
| `bench_cut_pressure` | Cut pressure computation across 16 nodes | fast | -- | -- |

Every benchmark with an explicit ADR target exceeds its budget by at least one
order of magnitude. The "fast" targets are internal design goals rather than
hard ADR requirements.

### Sub-benchmarks

Several top-level benchmarks include sub-benchmarks for bulk and stress
scenarios:

- `witness_emit_10000` -- 10,000 witness emissions in a single burst.
- `p1_verify_10000` -- 10,000 consecutive P1 checks on the same capability.
- `partition_switch_with_pressure` -- 8 partitions with varying cut pressure.
- `coherence_recompute_all_16node` -- Recompute scores for all 16 nodes at once.
- `mincut_4node` / `mincut_16node` -- MinCut at two different graph sizes.
- `buddy_alloc_order0_256` / `buddy_alloc_free_cycle_1000` / `buddy_alloc_mixed_orders` -- Various allocation patterns.
- `fnv1a_64_bytes_x10000` / `fnv1a_256_bytes` -- Hash throughput at different data sizes.
- `security_gate_check_p1` / `security_gate_check_p2` -- Gate with and without proof commitment.

---

## 2. Running Benchmarks

**Run the full suite:**

```bash
cargo bench
```

**Run only the RVM benchmarks (skip any other workspace members):**

```bash
cargo bench -p rvm-benches
```

**Run a single benchmark by name:**

```bash
cargo bench -- "p1_verify"
```

Criterion generates HTML reports under `target/criterion/`. Open
`target/criterion/report/index.html` in a browser to view graphs, regressions,
and statistical comparisons against previous runs.

**Comparing against a baseline:**

```bash
cargo bench -- --save-baseline before-change
# ... make your change ...
cargo bench -- --baseline before-change
```

Criterion will report whether each benchmark got faster, slower, or stayed
within noise.

---

## 3. Build Profiles

The workspace `Cargo.toml` defines three profiles that control compilation
behavior.

### Release (production and benchmarks)

```toml
[profile.release]
opt-level = 3       # Maximum optimization
lto = "fat"         # Full link-time optimization across all crates
codegen-units = 1   # Single codegen unit -- slower compile, better code
strip = true        # Remove debug symbols from the binary
panic = "abort"     # No unwinding -- smaller binary, faster panics
```

This profile produces the smallest, fastest binary. It is the default for
`make build` and `make run`. Fat LTO with a single codegen unit enables the
compiler to inline across crate boundaries -- critical for operations like
`verify_p1` where the entire call chain collapses to a few instructions.

### Bench (criterion benchmarks)

```toml
[profile.bench]
inherits = "release"
debug = true         # Keep debug info for profiling (perf, Instruments)
```

Identical optimization level to release, but retains debug symbols so that
profilers can map instruction addresses back to source lines.

### Dev (development and testing)

```toml
[profile.dev]
opt-level = 0       # No optimization -- fast compile
debug = true        # Full debug info
```

Used by `cargo test` and `cargo check`. Compile times are fast but runtime
performance is not representative. Never benchmark in dev profile.

---

## 4. Hot Path Optimization

The partition switch is the most performance-critical operation in RVM. It
runs on every scheduling tick, potentially millions of times per second. The
implementation follows a strict discipline:

**No allocation.** The switch path touches only pre-allocated per-CPU run
queues. No buddy allocator calls, no ring buffer resizing.

**No graph work.** Coherence scores and cut pressures are computed
asynchronously during epoch boundaries, not during the switch itself. The
scheduler reads pre-computed values.

**No policy evaluation.** Security gate checks happen when a partition is
*created* or when a capability is *exercised*, not on every context switch.
The switch path only reads the priority value.

**Constant-time priority comparison.** The 2-signal priority
(`deadline_urgency + cut_pressure_boost`) is computed as a single `u32`
addition. No loops, no branches beyond the run queue scan.

The result: ~6 ns per switch on a modern x86-64 host, or roughly 1600x under
the 10 us ADR budget.

For contrast, the P2 proof engine pipeline *intentionally* does more work. It
chains a P1 capability check, policy evaluation, and witness emission into a
single call. At ~996 ns, it is still 100x under its 100 us budget, but it is
not on the per-switch hot path.

---

## 5. Design for Performance

The following architectural decisions contribute to RVM's performance across
all subsystems. For the full design rationale, see [Core
Concepts](02-core-concepts.md) and [Architecture](03-architecture.md).

### Constant-time operations

Capability lookup (`verify_p1`) is an array index plus generation check --
O(1). Witness emission is a ring buffer write -- O(1). Priority computation
is arithmetic on two integers -- O(1). The only non-constant-time operations
in the hot path are the coherence graph algorithms (MinCut, score
recomputation), and those are gated by the adaptive engine to run at reduced
frequency under load.

### Fixed-point arithmetic

RVM uses no floating-point math anywhere. Coherence scores, cut pressures,
EMA filter weights, and Phi values are all represented in basis points
(hundredths of a percent, where 10,000 = 100%). This avoids FPU context
save/restore during partition switches and guarantees bitwise determinism
across platforms. See [Glossary: EMA Filter](15-glossary.md).

### Cache-line alignment

Witness records are exactly 64 bytes -- one cache line on most architectures.
This means each record fits in a single cache-line fetch with no
false-sharing between adjacent records. The `WitnessRecord` layout is
documented in [Witness and Audit](06-witness-audit.md).

### `no_std` / no heap

Every RVM crate is `#![no_std]` and `#![forbid(unsafe_code)]` (except
`rvm-hal`, which needs `unsafe` for hardware access). No crate allocates from
the heap in its default configuration. All data structures use compile-time
const generics for capacity:

```rust
// 256-slot capability manager, 16-node coherence graph
let cap_mgr = CapabilityManager::<256>::with_defaults();
let graph = CoherenceGraph::<16, 128>::new();
let sched = Scheduler::<4, 256>::new();
```

This eliminates allocator overhead, prevents fragmentation, and makes worst-
case memory usage fully predictable at compile time.

---

## 6. Tuning Tips

### Feature flags

Each crate exposes feature flags that control optional subsystems. Disabling
unused features removes dead code and can improve instruction cache behavior.

| Flag | Crate | Effect |
|---|---|---|
| `ruvector` | rvm-coherence | Enables RuVector coherence engine backend |
| `sched` | rvm-coherence | Direct scheduler feedback integration |
| `crypto-sha256` | rvm-proof, rvm-boot | Uses real SHA-256 instead of FNV-1a |
| `ed25519` | rvm-proof | Enables Ed25519 witness signatures |
| `null-signer` | rvm-proof, rvm-witness | Enables NullSigner for testing (never use in production) |
| `alloc` | all crates | Enables APIs that require an allocator |
| `std` | all crates | Enables std-dependent features |

For the smallest possible kernel image (Seed hardware profile), disable
`ruvector`, `alloc`, and `std`.

### Ring buffer capacity

The witness log uses a compile-time ring buffer:

```rust
let log = WitnessLog::<4096>::new();  // 4096 records = 256 KB
```

The default capacity is 262,144 records (16 MB). For memory-constrained
deployments, reduce this. The trade-off is that a smaller ring overwrites
older records sooner. If you need complete audit trails, drain the ring to
persistent storage before it wraps. See [Witness and
Audit](06-witness-audit.md) for the ring buffer semantics.

### EMA alpha

The `EmaFilter` smoothing factor controls how quickly coherence scores react
to changes. The alpha is expressed in basis points:

| Alpha | Behavior |
|---|---|
| 1000 (10%) | Slow, very smooth -- good for stable workloads |
| 3000 (30%) | Moderate -- recommended default |
| 5000 (50%) | Responsive -- good for bursty workloads |
| 8000 (80%) | Very responsive -- tracks rapid changes, more noise |

Higher alpha values make the scheduler react faster to coherence shifts but
amplify measurement noise. Lower values produce smoother scheduling behavior
but delay reaction to genuine changes.

### Adaptive coherence engine

The `AdaptiveCoherenceEngine` throttles coherence recomputation under CPU
pressure:

| CPU Load | Recomputation Frequency |
|---|---|
| < 60% | Every epoch |
| 60 -- 80% | Every 2nd epoch |
| > 80% | Every 4th epoch |

This is automatic. You do not need to tune it unless you are running on
hardware where the coherence computation itself is a significant fraction of
the epoch budget. In that case, the `budget_exceeded_count` field tells you
how often the system is dropping computations. See
[Advanced and Exotic](13-advanced-exotic.md) for details on the adaptive
engine.

### MinCut budget

The `MinCutBridge` accepts a budget parameter (maximum iterations):

```rust
let mut bridge = MinCutBridge::<16>::new(200);  // up to 200 iterations
```

A smaller budget means faster (but less accurate) cut computations. For
production use, start with the default and reduce only if
`MinCutBudgetExceeded` errors appear in the witness log.

---

## Further Reading

- [Architecture](03-architecture.md) -- crate layer diagram and data flow
- [Partitions and Scheduling](07-partitions-scheduling.md) -- the switch hot path in detail
- [Witness and Audit](06-witness-audit.md) -- ring buffer design and chain integrity
- [Advanced and Exotic](13-advanced-exotic.md) -- adaptive coherence and RuVector integration
- [Troubleshooting](14-troubleshooting.md) -- what to do when performance is not as expected
- [Cross-Reference Index](cross-reference.md) -- find every mention of a concept
