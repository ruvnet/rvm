# ADR-138: Seed Hardware Profile

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

ADR-132 defines three target platforms: Seed, Appliance, and Chip. Seed is the most constrained: hardware-limited MCU-class devices with 64 KB to 1 MB of RAM, no MMU (or a very simple one), and no coherence engine. RVM must run on Seed targets to demonstrate that its core abstractions (partitions, capabilities, proofs, witnesses) are viable on deeply embedded hardware.

The challenge is that most hypervisor features assume abundant memory, multi-core processors, and hardware virtualization extensions. Seed has none of these. This ADR defines what RVM looks like when stripped to the bone.

## Decision

### Hardware Constraints

| Resource | Seed Range | Implication |
|----------|-----------|-------------|
| RAM | 64 KB - 1 MB | All structures must be statically sized; no heap allocation |
| Cores | 1 (typically) | No SMP scheduler needed; cooperative or timer-preemptive scheduling |
| MMU | None or MPU | No stage-2 page tables; isolation via MPU regions or software checks |
| Persistent storage | Flash (128 KB - 4 MB) | Witness log overflow to flash; checkpoint storage |
| Network | None, UART, or SPI | No network-based migration; local operation only |
| Power | Battery or energy harvesting | Deep sleep between events; witness log survives wake cycles |

### What Works on Seed

The entire RVM core (Layer 1) is `#![no_std]` with `#![forbid(unsafe_code)]` and zero heap allocation. On Seed, this means:

1. **Capability + Proof + Witness**: The full P1+P2 proof system, capability derivation tree, and witness log work on Seed. These are bitmap operations and fixed-size ring buffers -- no allocator needed.
2. **Partitions (limited)**: 1-4 partitions, statically configured. No dynamic split/merge (requires coherence engine, which is absent per DC-1).
3. **Memory tiers (simplified)**: Only Hot and Cold tiers. Warm tier requires shared DRAM (not available on most MCUs). Dormant tier requires compression (too expensive for 64 KB RAM). Static threshold fallback per DC-1.
4. **Witness log (small ring buffer)**: Ring buffer sized to available RAM. On a 64 KB device, a 4 KB ring buffer holds 64 witness records. Overflow drains to flash.
5. **IPC**: Fixed-size message queues between the few partitions. Zero-copy where MPU regions allow.

### What Does Not Work on Seed

1. **Coherence engine (DC-1)**: Absent. No graph, no mincut, no cut pressure. Partitions use static affinity.
2. **Dynamic split/merge**: Requires coherence engine and sufficient memory for two partitions' state.
3. **WASM runtime**: Too expensive. Seed runs native code only (DC-13).
4. **Multi-core scheduling**: Single core; the scheduler degenerates to a priority queue with timer preemption.
5. **GPU compute**: Not applicable.
6. **Migration**: No network, no target to migrate to. State survives only via checkpoint-to-flash.

### Feature Gating

Seed builds use minimal Cargo features:

```toml
[features]
default = []
# Seed profile: no alloc, no coherence, no wasm, no gpu
seed = []
# Enables alloc (required for Appliance+)
alloc = []
# Enables coherence engine
coherence = ["alloc"]
# Enables WASM runtime
wasm = ["alloc"]
```

The `no_std` + no `alloc` combination compiles only the core kernel objects. All coherence, WASM, and GPU code is excluded.

### Memory Layout (64 KB Example)

| Region | Size | Contents |
|--------|------|----------|
| Code + rodata | 24 KB | RVM kernel image |
| Stack | 4 KB | Single execution stack |
| Partition state | 4 KB | 1-2 partition structures, capability tables |
| Witness log | 4 KB | 64-record ring buffer |
| Application data | 28 KB | Available to the root partition |

### Boot on Seed

The boot sequence (ADR-137) runs all 7 phases but with simplified HAL init:
- No MMU setup (skip or configure MPU).
- No GIC (direct NVIC interrupt controller on Cortex-M).
- Memory init configures the buddy allocator over the available SRAM.
- Witness init creates a small ring buffer.
- Root partition is the only partition created.

## Consequences

### Positive

- **Proves core abstractions are viable on MCU**: If capabilities, proofs, and witnesses work on 64 KB, they work everywhere.
- **Zero-allocation guarantee** is enforced by the Seed profile, ensuring no hidden `alloc` dependencies creep into the core.
- **Minimal attack surface**: No WASM interpreter, no coherence graph, no network stack. The TCB on Seed is extremely small.

### Negative

- **No dynamic partitioning**: Seed targets cannot split, merge, or migrate. The coherence-native features that differentiate RVM are absent on Seed.
- **Limited witness capacity**: 64 records in a 4 KB ring buffer means the drain-to-flash path must be reliable or witness records will be lost.
- **Single-core only**: Cannot demonstrate SMP scheduling on Seed.

### Neutral

- Seed is primarily a validation target, not a deployment target. Its purpose is to prove that the core kernel is truly minimal and allocation-free.

## References

- ADR-132: RVM Hypervisor Core (DC-1, DC-13, Seed platform profile)
- ADR-136: Memory Hierarchy and Reconstruction (DC-1 fallback thresholds)
- ADR-137: Bare-Metal Boot Sequence
- `crates/rvm-memory/src/lib.rs` -- `MemoryRegion` with ADR-138 compatibility note
