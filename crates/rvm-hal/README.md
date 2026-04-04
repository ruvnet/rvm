# rvm-hal

Platform-agnostic hardware abstraction traits for the RVM microhypervisor.

Defines the trait interfaces that concrete platform implementations (AArch64,
RISC-V, x86-64) must satisfy. All trait methods return `RvmResult` and pass
borrowed slices rather than owned buffers. The trait definitions themselves
contain no `unsafe` code.

## Key Traits

- `Platform` -- CPU discovery, total memory query, halt
- `MmuOps` -- stage-2 page table management (map, unmap, translate, TLB flush)
- `TimerOps` -- monotonic nanosecond timer with one-shot deadline support
- `InterruptOps` -- interrupt enable/disable, acknowledge, end-of-interrupt

## Example

```rust
use rvm_hal::{Platform, MmuOps, TimerOps, InterruptOps};
use rvm_types::{GuestPhysAddr, PhysAddr};

fn map_guest_page(mmu: &mut impl MmuOps) {
    let guest = GuestPhysAddr::new(0x8000_0000);
    let host = PhysAddr::new(0x4000_0000);
    mmu.map_page(guest, host).expect("map failed");
}
```

## Design Constraints

- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-133: all trait methods return `RvmResult`; zero-copy semantics

## Workspace Dependencies

- `rvm-types`
