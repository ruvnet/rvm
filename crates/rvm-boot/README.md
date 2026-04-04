# rvm-boot

Deterministic 7-phase boot sequence for the RVM microhypervisor.

Implements ADR-140: each boot phase is gated by a witness entry and must
complete before the next phase begins. Out-of-order phase completion is
rejected. The `BootTracker` provides a simple state machine that enforces
the required sequencing.

## Boot Phases

```
Phase 0: HAL init       (timer, MMU, interrupts)
Phase 1: Memory init    (physical page allocator)
Phase 2: Capability init
Phase 3: Witness init
Phase 4: Scheduler init
Phase 5: Root partition creation
Phase 6: Hand-off to root partition
```

## Key Types

- `BootPhase` -- enum of 7 phases (`HalInit` through `Handoff`)
- `BootTracker` -- state machine enforcing sequential phase completion
  - `new()` -- starts at `HalInit`
  - `complete_phase(phase)` -- marks current phase done, advances to next
  - `is_complete()` -- true when all 7 phases have completed
  - `current_phase()` -- returns the current phase, or `None` if complete

## Example

```rust
use rvm_boot::{BootTracker, BootPhase};

let mut tracker = BootTracker::new();
assert_eq!(tracker.current_phase(), Some(BootPhase::HalInit));

tracker.complete_phase(BootPhase::HalInit).unwrap();
assert_eq!(tracker.current_phase(), Some(BootPhase::MemoryInit));

// Out-of-order is rejected:
assert!(tracker.complete_phase(BootPhase::WitnessInit).is_err());
```

## Design Constraints

- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-140: deterministic, witness-gated boot sequence

## Workspace Dependencies

- `rvm-types`
- `rvm-hal`
- `rvm-partition`
- `rvm-witness`
- `rvm-sched`
- `rvm-memory`
