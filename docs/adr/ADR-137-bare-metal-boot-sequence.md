# ADR-137: Bare-Metal Boot Sequence

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

RVM boots bare-metal without KVM or Linux. The boot sequence must initialize hardware, establish the capability discipline, create the witness trail, and hand off to the scheduler -- all in a deterministic, witness-gated sequence. A non-deterministic boot makes debugging impossible and prevents measured boot attestation.

The boot sequence has evolved through two iterations:

1. **ADR-137 original (7-phase hardware-centric)**: Reset vector, hardware detect, MMU setup, EL2 entry, kernel object init, first witness, scheduler entry. This maps to the AArch64 hardware bring-up path.
2. **ADR-140 revision (7-phase logical)**: HAL init, memory pool init, capability table init, witness trail init, scheduler init, root partition creation, hand-off. This is the currently implemented sequence.

Both share the principle: each phase is gated by a witness entry and must complete before the next begins.

## Decision

### Boot Phases

The implemented boot sequence uses 7 phases, executed in strict order:

| Phase | Name | What It Does |
|-------|------|-------------|
| 0 | HalInit | Initialize hardware abstraction: timer, MMU, interrupts, UART |
| 1 | MemoryInit | Initialize physical page allocator (BuddyAllocator) |
| 2 | CapabilityInit | Create the root capability table |
| 3 | WitnessInit | Initialize the witness log ring buffer; emit genesis attestation |
| 4 | SchedulerInit | Initialize the scheduler with deadline-based priority |
| 5 | RootPartition | Create the root partition with bootstrap authority |
| 6 | Handoff | Transfer control to the root partition's entry point |

### BootTracker

The `BootTracker` enforces phase ordering. It maintains:

- `current: Option<BootPhase>` -- the phase that must complete next, or `None` if boot is complete.
- `completed: [bool; 7]` -- which phases have finished.

Calling `complete_phase(phase)` succeeds only if `phase` matches `current`. Out-of-order completion returns `RvmError::InternalError`. Attempting to complete a phase after boot is done returns `RvmError::Unsupported`.

### MeasuredBootState

For TPM-style measured boot, `MeasuredBootState` accumulates a hash chain during boot. Each phase extends the measurement with its completion data, producing a boot attestation hash that can be included in the genesis witness record. This enables remote attestation: a verifier can confirm that the boot sequence executed all phases in order with expected firmware and configuration.

### BootSequence

The `BootSequence` type wraps the full boot flow with timing. Each `BootStage` records a `PhaseTiming` (start/end timestamps in nanoseconds) so that boot performance can be profiled. The target is cold boot to first witness in under 250ms on Appliance hardware.

### HAL Abstraction

The `HalInit` trait abstracts hardware initialization behind three configuration structures:

- `MmuConfig` -- page table base, granularity, address space size.
- `InterruptConfig` -- GIC distributor and redistributor addresses.
- `UartConfig` -- serial console base address and baud rate.

A `StubHal` implementation satisfies the trait for testing without real hardware. On AArch64, the real HAL performs EL2 entry, stage-2 page table setup, and GIC initialization.

### Witness Gating

Every phase transition emits a `BootAttestation` witness record before advancing. If witness emission fails (ring buffer unavailable during WitnessInit itself), the boot sequence records the failure in the measured boot state and continues -- witness infrastructure is not yet available in phases 0-2. From phase 3 onward, witness emission failure is fatal.

### AArch64 Entry

On AArch64, the reset vector (assembly, <100 LoC) performs:

1. Disable interrupts, set SCTLR to known state.
2. Read MPIDR to determine core ID; park non-primary cores.
3. Zero BSS, set up initial stack pointer.
4. Branch to Rust `_start` which calls `run_boot_sequence()`.

The entry module (`crates/rvm-boot/src/entry.rs`) provides `BootContext` and `run_boot_sequence()` as the Rust-side entry point.

## Consequences

### Positive

- **Deterministic ordering** via `BootTracker` prevents initialization races and ensures every phase completes before its dependents start.
- **Measured boot** enables remote attestation for high-assurance deployments.
- **Phased witness gating** catches boot-time failures early with auditable records.
- **HAL abstraction** allows the same boot sequence to run on QEMU, real AArch64, and future RISC-V targets.

### Negative

- **Strict phase ordering** means phases cannot be parallelized. On multi-core hardware, phases 0-4 run on the primary core only; secondary cores are parked until phase 6 (Handoff).
- **250ms boot target** is aggressive for bare-metal without firmware fast-path optimizations. Phase 1 (memory init) dominates on systems with large physical memory.

### Neutral

- The dual 7-phase numbering (hardware-centric vs. logical) may cause confusion. The implemented logical sequence is canonical; the hardware-centric numbering in the module doc-comments is retained for reference.

## References

- ADR-132: RVM Hypervisor Core (success criterion 1: cold boot < 250ms)
- ADR-134: Witness Schema and Log Format (BootAttestation witness kind)
- `crates/rvm-boot/src/lib.rs` -- Module root, BootPhase enum, BootTracker
- `crates/rvm-boot/src/sequence.rs` -- BootSequence with timing
- `crates/rvm-boot/src/measured.rs` -- MeasuredBootState hash chain
- `crates/rvm-boot/src/hal_init.rs` -- HalInit trait and StubHal
- `crates/rvm-boot/src/entry.rs` -- AArch64 entry point
