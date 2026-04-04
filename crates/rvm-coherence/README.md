# rvm-coherence

Real-time coherence scoring and Phi computation for the RVM microhypervisor.

Coherence is the first-class resource-allocation signal: partitions with
higher coherence receive more CPU time and memory grants. Raw Phi values
from IIT (Integrated Information Theory) sensors are fed through an EMA
(Exponential Moving Average) filter using fixed-point arithmetic to produce
smoothed coherence scores. The optional `sched` feature enables direct
feedback to the coherence-weighted scheduler.

## Pipeline

```
Sensor data --> Phi computation --> EMA filter --> Score update --> Scheduler feedback
```

## Key Types and Functions

- `EmaFilter` -- fixed-point EMA filter (basis points, no floating-point)
- `SensorReading` -- raw Phi reading with partition ID and timestamp
- `phi_to_coherence_bp(phi)` -- convert raw Phi to basis-point coherence (stub mapping)

## Example

```rust
use rvm_coherence::{EmaFilter, phi_to_coherence_bp};
use rvm_types::PhiValue;

let mut filter = EmaFilter::new(2000); // 20% alpha
let score = filter.update(8000);       // feed 80% sample
assert_eq!(score.as_basis_points(), 8000); // first sample = raw value

let score2 = filter.update(4000);      // feed 40% sample
// EMA: 0.2 * 4000 + 0.8 * 8000 = 7200
assert_eq!(score2.as_basis_points(), 7200);
```

## Design Constraints

- **DC-1 / DC-6**: Coherence engine is optional; system degrades gracefully
- **DC-2**: MinCut budget: 50 us per epoch (stub)
- **DC-9**: Coherence score range [0.0, 1.0] as fixed-point basis points
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-139: EMA filter operates without floating-point

## Features

- `sched` -- enables `rvm-sched` integration for coherence-weighted scheduling

## Workspace Dependencies

- `rvm-types`
- `rvm-partition`
- `rvm-sched` (optional, via `sched` feature)
