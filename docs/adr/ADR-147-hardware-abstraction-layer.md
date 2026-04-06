# ADR-147: Hardware Abstraction Layer Contract

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core), ADR-133 (HAL Design -- referenced in rvm-hal docs)

---

## Context

The `rvm-hal` crate defines the hardware abstraction boundary between RVM's
portable kernel logic and architecture-specific implementations. The deep review
identified that while the four HAL traits (`Platform`, `MmuOps`, `TimerOps`,
`InterruptOps`) are implemented and tested, the contract they establish --
safety invariants, zero-copy requirements, multi-architecture extensibility,
and the `unsafe` code policy -- is not formally specified.

### Problem Statement

1. **Unsafe boundary is implicit**: `rvm-hal/src/lib.rs` uses `#![deny(unsafe_code)]` at the crate level but `#[allow(unsafe_code)]` on the `aarch64` module. The rationale and invariant documentation requirements are not specified.
2. **Stage-2 MMU contract is incomplete**: `MmuOps` methods accept `GuestPhysAddr` and `PhysAddr` but do not specify alignment requirements, page size, or double-mapping behaviour.
3. **Zero-copy principle is stated but not enforced**: the module doc says "pass borrowed slices, never owned buffers" but no trait method accepts slices.
4. **Timer precision and monotonicity are not guaranteed**: `now_ns()` returns `u64` but there is no specification of resolution, monotonicity, or overflow behaviour.
5. **Interrupt semantics vary by architecture**: `acknowledge()` returns `Option<u32>` (spurious handling) but the protocol for nested interrupts and priority is unspecified.

---

## Decision

### 1. The Four-Trait Contract

The HAL is organized as four independent traits (`Platform`, `MmuOps`,
`TimerOps`, `InterruptOps`), each responsible for one hardware subsystem.
Implementations must satisfy all four traits to constitute a complete platform
port. All fallible methods return `RvmResult<T>` (aliased to
`Result<T, RvmError>`) for portable error handling across architectures.

### 2. Stage-2 Page Table Management

`MmuOps` manages the stage-2 translation from guest physical addresses
(`GuestPhysAddr`) to host physical addresses (`PhysAddr`). The contract:

- **Page granularity**: all operations work on 4KB-aligned pages. Both `guest`
  and `host` must be 4KB-aligned; misaligned addresses return
  `Err(RvmError::AlignmentError)`.
- **map_page**: creates a new mapping. Returns `Err(RvmError::MemoryOverlap)`
  if the guest page is already mapped. Does not support remap-in-place; the
  caller must `unmap_page()` first.
- **unmap_page**: removes an existing mapping. Returns an error if the page is
  not currently mapped.
- **translate**: returns the host physical address for a mapped guest page.
  Returns an error if unmapped. This is a software table walk, not a TLB lookup.
- **flush_tlb**: invalidates TLB entries for `page_count` pages starting at
  `guest`. On AArch64, this issues `TLBI IPAS2E1IS` for each page followed by
  `DSB ISH` + `ISB`.

On AArch64, the stage-2 page table root is stored in VTTBR_EL2, which is
written during `partition_switch()` (see ADR-146). The MMU operates at EL2,
translating IPA (Intermediate Physical Address) to PA.

### 3. AArch64 Implementation: EL2, PL011, GICv2, Generic Timer

The `rvm-hal::aarch64` module provides the reference implementation:

| Component | Hardware | Key Registers |
|-----------|----------|--------------|
| MMU | ARMv8-A Stage-2 | VTTBR_EL2, VTCR_EL2 |
| UART | PL011 | UARTDR, UARTFR, UARTCR |
| Interrupt Controller | GICv2 | GICD_*, GICC_* |
| Timer | ARM Generic Timer | CNTPCT_EL0, CNTHP_TVAL_EL2, CNTHP_CTL_EL2 |

The implementation targets QEMU `virt` machine (Cortex-A72 profile). Timer
resolution matches the physical counter frequency (typically 62.5 MHz on QEMU,
giving ~16ns resolution). `now_ns()` reads `CNTPCT_EL0` and converts via the
counter frequency from `CNTFRQ_EL0`.

### 4. Future Architecture Targets

| Target | Privilege Level | MMU | Timer | Interrupt |
|--------|----------------|-----|-------|-----------|
| RISC-V | HS-mode (hypervisor extension) | Sv48x4 (stage-2) | CLINT mtime/mtimecmp | PLIC |
| x86-64 | VMX root mode | EPT (Extended Page Tables) | PIT/HPET/TSC | APIC (Local + I/O) |

New ports implement the same four traits. Architecture-specific details
(register names, TLB flush instructions, timer resolution) are encapsulated
within the module. Portable kernel code only interacts through the trait
interface.

### 5. Unsafe Code Policy

The crate-level lint configuration establishes a two-layer safety model:

```rust
// rvm-hal/src/lib.rs (crate root)
#![deny(unsafe_code)]    // Trait definitions are safe

// rvm-hal/src/aarch64/mod.rs (arch module)
#[allow(unsafe_code)]    // Hardware access requires unsafe
```

**Rationale**: trait definitions contain no `unsafe` because the contract is
expressed through Rust's type system and `RvmResult` error handling. Architecture
implementations require `unsafe` for:

- Inline assembly (`asm!` for MRS/MSR, TLBI, DSB, ISB).
- MMIO register access (volatile reads/writes to device memory).
- Raw pointer dereference for page table manipulation.

**Invariant documentation requirement**: every `unsafe` block in an architecture
module must include a `// SAFETY:` comment documenting:

1. What invariant the unsafe code relies on.
2. Why the invariant holds at this call site.
3. What could go wrong if the invariant is violated.

The crate uses `#![deny(unsafe_code)]` rather than `#![forbid(unsafe_code)]`
precisely because architecture modules need the ability to `#[allow(unsafe_code)]`
locally. `forbid` would prevent this.

### 6. Zero-Copy Principle

The module documentation states: "pass borrowed slices, never owned buffers."
While the current trait methods do not accept slices (they operate on scalar
addresses and IDs), the principle applies to:

- **MmuOps**: addresses are passed by value (`GuestPhysAddr`, `PhysAddr`), not
  by reference to owned memory buffers. Page table memory is managed internally.
- **InterruptOps**: IRQ IDs are passed by value. No interrupt descriptor
  allocation is exposed through the trait.
- **Future extensions**: any method that needs to transfer bulk data (e.g., DMA
  descriptor lists, firmware blobs) must accept `&[u8]` or `&mut [u8]`, never
  `Vec<u8>` or `Box<[u8]>`. This keeps the HAL `no_std`-compatible and
  allocation-free.

---

## Consequences

### Positive

- Four clean trait boundaries enable independent porting of each hardware subsystem.
- `deny(unsafe_code)` at the crate level with local `allow` provides defense-in-depth.
- `RvmResult` return types give portable error handling across all architectures.
- 4KB page granularity matches all three target architectures' minimum page size.
- Zero-copy principle keeps the HAL compatible with `#![no_std]` and zero-heap environments.

### Negative

- No support for large pages (2MB, 1GB) in the current `MmuOps` contract.
- Timer resolution is architecture-dependent and not queryable through the trait.
- `InterruptOps` does not model interrupt priorities or nesting.
- Only one architecture (AArch64) is implemented; RISC-V and x86-64 are future work.

### Risks

- Without a timer resolution query method, portable code cannot accurately reason
  about deadline precision on different platforms.
- The `acknowledge()` -> `end_of_interrupt()` protocol assumes level-triggered
  semantics; edge-triggered interrupts may require a different flow.

---

## References

- `rvm-hal/src/lib.rs` -- Trait definitions: `Platform`, `MmuOps`, `TimerOps`, `InterruptOps`
- `rvm-hal/src/aarch64/` -- AArch64 implementation (EL2, PL011, GICv2, ARM generic timer)
- `rvm-types/src/lib.rs` -- `GuestPhysAddr`, `PhysAddr`, `RvmResult`, `RvmError`
- ADR-132 -- RVM hypervisor core design constraints
- ADR-146 -- SMP scheduling model (VTTBR_EL2 usage in partition_switch)
