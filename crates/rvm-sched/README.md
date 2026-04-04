# rvm-sched

Coherence-weighted 2-signal scheduler for the RVM microhypervisor.

Combines deadline urgency and cut-pressure boost into a single priority
signal: `priority = deadline_urgency + cut_pressure_boost`. The scheduler
operates in three modes (Reflex, Flow, Recovery) and degrades gracefully
when the coherence engine is unavailable, falling back to deadline-only
scheduling. Partition switches are the hot path -- no allocation, no graph
work, no policy evaluation during a switch.

## Key Types

- `Scheduler` -- top-level scheduler managing all per-CPU schedulers
- `PerCpuScheduler` -- per-CPU run queue and priority computation
- `SchedulerMode` -- `Reflex` (hard RT), `Flow` (normal), `Recovery` (stabilization)
- `EpochTracker`, `EpochSummary` -- epoch-based accounting (DC-10)
- `DegradedState`, `DegradedReason` -- degraded-mode tracking when coherence unavailable
- `compute_priority` -- the 2-signal priority function

## Example

```rust
use rvm_sched::compute_priority;
use rvm_types::{CoherenceScore, CutPressure};

let deadline_urgency: u32 = 800;
let cut_boost: u32 = 200;
let priority = compute_priority(deadline_urgency, cut_boost);
assert_eq!(priority, 1000);
```

## Design Constraints

- **DC-1 / DC-6**: Coherence engine optional; degraded mode uses deadline only
- **DC-4**: 2-signal priority: `deadline_urgency + cut_pressure_boost`
- **DC-10**: Switches are NOT individually witnessed; epoch summaries instead
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-137: partition switch target < 10 us

## Workspace Dependencies

- `rvm-types`
- `rvm-partition`
- `rvm-witness`
- `spin`
