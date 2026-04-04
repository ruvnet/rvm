# ADR-138: Seed Hardware Bring-Up

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-137 (Bare-Metal Boot Sequence), ADR-136 (Memory Hierarchy and Reconstruction)

---

## Context

ADR-132 defines three target platform profiles for RVM: Seed (tiny, persistent, event-driven), Appliance (edge hub, deterministic orchestration), and Chip (future Cognitum silicon). The Seed profile represents the smallest viable RVM target -- a hardware-constrained device with 64KB-1MB RAM that may run only one or two partitions. Seed validates that the RVM kernel works at the smallest scale and forces the "kernel without coherence engine" configuration (DC-1) to be a real, tested deployment, not a theoretical fallback.

No existing hypervisor targets this class of hardware. Traditional hypervisors (KVM, Xen, Firecracker) assume gigabytes of RAM and multi-core processors. Embedded Rust operating systems (Tock, Hubris) target this hardware class but are not hypervisors and do not provide coherence domains. Seed fills the gap: a capability-based, witness-native microkernel that runs on hardware as small as a Cortex-M/R or small Cortex-A.

### Problem Statement

1. **Kernel size must be bounded**: If the RVM kernel grows to require megabytes of RAM, Seed becomes impossible. The Seed target acts as a size constraint on kernel design.
2. **No MMU on many embedded targets**: Cortex-M class processors have an MPU (Memory Protection Unit) but no MMU. Stage-2 translation is not available. The kernel must degrade gracefully.
3. **Real-time requirements**: Seed targets (sensor nodes, secure anchors) have hard real-time constraints. Scheduling must be deterministic with bounded worst-case latency.
4. **Power management**: Seed devices are often battery-powered or energy-harvesting. Deep sleep with fast wake and state persistence is mandatory.
5. **Witness integrity on constrained hardware**: The 64-byte witness format may be too expensive for devices with 64KB RAM. A compact variant is needed.
6. **Coherence engine is absent**: Seed devices have neither the RAM nor the CPU budget for graph partitioning. DC-1 must be enforced as a hard constraint, not a fallback.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| Tock OS | Capability-based embedded Rust OS, MPU isolation | Closest existing system to Seed's design goals |
| Hubris (Oxide Computer) | Task-isolated embedded Rust OS, deterministic scheduling | Informs Reflex-mode scheduling and fault isolation |
| Zephyr RTOS | Widely deployed embedded RTOS, extensive driver ecosystem | Baseline comparison for embedded OS capabilities |
| FreeRTOS | Dominant embedded RTOS, minimal footprint | Lower bound on kernel size (~10KB) |
| ARM Cortex-M Architecture | MPU, low-power modes (WFI/WFE, STOP, STANDBY) | Primary Seed hardware target |
| ARM TrustZone-M | Hardware security partitioning for Cortex-M | Potential Seed isolation enhancement (post-v1) |
| nRF52840 (Nordic) | Cortex-M4F, 256KB RAM, 1MB flash, BLE | Reference Seed dev board |
| STM32H7 | Cortex-M7, 1MB RAM, dual-core | Upper-end Seed target |

---

## Decision

Define the Seed platform profile as the minimum viable RVM deployment and specify its hardware constraints, boot sequence, kernel configuration, and bring-up plan.

### Hardware Profile

| Parameter | Minimum | Typical | Maximum |
|-----------|---------|---------|---------|
| RAM | 64 KB | 256 KB | 1 MB |
| Flash / NVM | 256 KB | 1 MB | 4 MB |
| Cores | 1 | 1 | 2 |
| Clock | 16 MHz | 64 MHz | 480 MHz |
| MMU | No (MPU only) | No (MPU only) | Optional |
| FPU | Optional | Yes (single) | Yes (double) |
| Power | Microwatts (sleep) | Milliwatts (active) | < 1W peak |

### Kernel Configuration for Seed

The RVM kernel must compile with a `seed` feature flag that constrains its resource usage:

| Subsystem | Appliance | Seed | Rationale |
|-----------|-----------|------|-----------|
| Coherence engine (Layer 2) | Optional | **Absent** | No RAM or CPU budget for graph operations |
| Agent runtime (WASM) | Available | **Limited** | At most 1 WASM module, or native code only |
| Memory tiers | Hot/Warm/Dormant/Cold | **Hot + Cold only** | No Warm/Dormant -- too constrained for compression tiers |
| Partition count | Unbounded | **1-2** | RAM limits partition table size |
| Witness format | 64-byte standard | **32-byte compact** | Halves per-record cost |
| Capability table | 4096 entries | **64-256 entries** | Proportional to partition count |
| Queue pool | 256 queues | **8-16 queues** | Minimal IPC surface |
| Scheduler mode | Flow + Reflex + Recovery | **Reflex primary** | Hard RT; Flow available but simplified |
| Proof layers | P1 + P2 (+ P3 post-v1) | **P1 only** | P2 policy validation deferred to save cycles |
| CommEdge count | 64 per partition | **4 per partition** | Minimal inter-partition traffic |

### Boot Sequence (Seed-Specific)

Seed boot follows the same seven-stage structure as ADR-137 but with platform-specific adaptations:

| Stage | Seed Adaptation |
|-------|----------------|
| 0: Reset vector | Cortex-M: vector table at 0x0, `Reset_Handler` in assembly. No EL2 -- there is no hypervisor privilege level on Cortex-M. |
| 1: Hardware detection | Minimal: read chip ID register, determine RAM size from linker symbols (no DTB on Cortex-M). |
| 2: UART init | Configure SWO (Serial Wire Output) or UART peripheral. May use semihosting on dev boards. |
| 3: MMU/MPU bring-up | **MPU-only mode**: Configure MPU regions for kernel code (RO+X), kernel data (RW), peripheral MMIO (device), and partition regions (unprivileged). No page tables, no stage-2 translation. |
| 4: Privilege mode | Cortex-M: Handler mode (privileged) for kernel, Thread mode (unprivileged) for partitions. `CONTROL` register configures privilege. |
| 5: Kernel objects | Reduced allocation: 64-entry capability table, 8 queues, compact witness log in flash-backed RAM section. |
| 6: First witness | 32-byte compact `BOOT_COMPLETE` witness. Target: < 50ms from reset on Cortex-M4 @ 64MHz. |
| 7: First partition | Single partition with direct peripheral access via capability-gated MMIO. |

### MPU-Only Isolation Mode

On targets without an MMU, RVM uses the MPU (Memory Protection Unit) for isolation:

```
MPU Region Layout (Seed, 2 partitions):

Region 0: Kernel code        [Flash, RO+X, Privileged]
Region 1: Kernel data        [RAM, RW, Privileged]
Region 2: Kernel stack       [RAM, RW, Privileged]
Region 3: Partition 0 code   [Flash, RO+X, Unprivileged]
Region 4: Partition 0 data   [RAM, RW, Unprivileged]
Region 5: Partition 1 code   [Flash, RO+X, Unprivileged]
Region 6: Partition 1 data   [RAM, RW, Unprivileged]
Region 7: Peripheral MMIO    [Device, RW, per-capability]
```

The ARMv7-M MPU supports 8 regions; ARMv8-M supports 8-16. Seed with 2 partitions fits within 8 regions. Partition switches reconfigure MPU regions 3-6 (or use the ARMv8-M MPU's sub-region disable feature for finer granularity).

**Limitation**: MPU isolation is coarser than stage-2 page tables. Regions must be power-of-2 aligned and sized (ARMv7-M) or 32-byte aligned (ARMv8-M). This is acceptable for 1-2 partitions.

### Compact Witness Format (32-byte)

The standard 64-byte witness from ADR-134 is halved for Seed:

| Field | Standard (64B) | Compact (32B) | Notes |
|-------|---------------|---------------|-------|
| Witness type | 2 bytes | 1 byte | 256 types sufficient for Seed |
| Flags | 2 bytes | 1 byte | Reduced flag set |
| Timestamp | 8 bytes | 4 bytes | 32-bit relative timestamp (wraps at ~4.2 billion ticks) |
| Previous hash | 32 bytes | 16 bytes | Truncated SHA-256 or SipHash-128 |
| Payload | 20 bytes | 10 bytes | Reduced context per record |

Compact witnesses are interoperable: they can be expanded to 64-byte format when uploaded to an Appliance or cloud for aggregation. The truncated hash provides 128-bit collision resistance, sufficient for embedded attestation chains.

### Device Model: Capability-Gated MMIO

Seed does not virtualize peripherals. Instead, partitions access hardware directly through capability-gated MMIO:

1. The kernel maps peripheral address ranges as MPU regions
2. A partition must hold a `DeviceLease` capability with `LEASE` rights to access a peripheral
3. On partition switch, MPU regions are reconfigured to grant/revoke MMIO access
4. No trap-and-emulate: direct register access for zero-overhead I/O
5. Interrupt routing: the NVIC (Nested Vectored Interrupt Controller) routes peripheral interrupts to the active partition's handler via the kernel's dispatch table

This is simpler and faster than the Appliance model (which uses stage-2 faults to trap MMIO). The trade-off is that only one partition can hold a device lease at a time.

### Scheduling: Reflex Mode Primary

Seed scheduling is dominated by Reflex mode (hard real-time, bounded latency):

- **Tick source**: SysTick timer (Cortex-M) or platform timer
- **Scheduling algorithm**: Static priority with deadline enforcement
- **No cut-pressure signal**: Coherence engine is absent; `cut_pressure_boost = 0` always
- **Worst-case switch time**: < 5 microseconds on Cortex-M4 @ 64MHz (MPU reconfiguration + context restore)
- **Flow mode**: Available but simplified -- uses static priority only, no coherence-aware placement
- **Recovery mode**: Supported via witness log replay and flash-backed state

### Power Management

Seed devices require aggressive power management:

| State | Implementation | Wake Source | State Preserved |
|-------|---------------|-------------|-----------------|
| Active | Full-speed execution | N/A | All |
| Idle | WFI (Wait For Interrupt) | Any interrupt | All |
| Deep sleep | STOP mode (clocks off, RAM retained) | RTC, GPIO, LPUART | RAM (witness log intact) |
| Hibernate | STANDBY (RAM lost, only backup registers) | RTC, WKUP pin | Flash only (witness log + checkpoint) |

**Witness-preserved wake**: Before entering deep sleep or hibernate, the kernel:
1. Emits a `SLEEP_ENTER` witness with current state hash
2. Flushes the witness log to flash (if not already persistent)
3. Stores a minimal recovery checkpoint (partition state, capability table) to flash
4. On wake, emits `SLEEP_EXIT` witness and validates state integrity via checkpoint hash

### Agent Support

Seed agent support is intentionally limited:

| Option | RAM Required | Description |
|--------|-------------|-------------|
| **Native code only** | 0 overhead | Partition runs compiled Rust/C directly in Thread mode. No runtime. |
| **Single WASM module** | ~32-64KB | One WASM interpreter (e.g., wasm3 or a minimal Rust interpreter) in a single partition. |
| **No agents** | 0 overhead | Seed runs bare partitions with kernel-managed tasks only. |

The choice is a compile-time feature flag. Most Seed deployments will use native code partitions.

### Coherence Engine: Not Present (DC-1 Enforced)

This is not a degradation -- it is the intended configuration. Seed proves that DC-1 is not just a fallback path but a first-class deployment mode:

- No `ruvix-pressure` crate linked
- No `ruvix-vecgraph` crate linked
- No `mincut` computation
- No `sparsifier` or `solver` integration
- Partition placement is static (assigned at compile time or boot configuration)
- Scheduling uses deadline priority only (`priority = deadline_urgency`)

---

## Bring-Up Plan

### Phase 1: QEMU Cortex-M Emulation

| Step | Deliverable | Gate |
|------|------------|------|
| 1.1 | Boot RVM on `qemu-system-arm -machine lm3s6965evb` (Cortex-M3) | Serial output from Rust |
| 1.2 | MPU-based partition isolation (2 partitions) | Unprivileged code faults on kernel memory access |
| 1.3 | Compact witness emission | 32-byte witness chain from boot to partition start |
| 1.4 | Reflex scheduler with SysTick | Deterministic task switching at configured tick rate |
| 1.5 | Deep sleep / wake cycle | Sleep, wake on timer, validate witness chain continuity |

**QEMU invocation:**

```bash
qemu-system-arm \
    -machine lm3s6965evb \
    -cpu cortex-m3 \
    -nographic \
    -semihosting-config enable=on,target=native \
    -kernel target/thumbv7m-none-eabi/release/ruvix-seed
```

### Phase 2: Dev Board (nRF52840 or STM32H7)

| Step | Deliverable | Gate |
|------|------------|------|
| 2.1 | Flash RVM to nRF52840-DK or Nucleo-H743ZI | Boot on real silicon, UART output |
| 2.2 | GPIO-driven partition: blink LED from partition, not kernel | Capability-gated MMIO verified |
| 2.3 | BLE or Ethernet peripheral lease | Device lease acquired, used, revoked with witnesses |
| 2.4 | Power measurement: active, idle, deep sleep | Validate power budget targets |
| 2.5 | 72-hour soak test | Continuous operation with witness log integrity |

### Phase 3: Seed Production Hardware

| Step | Deliverable | Gate |
|------|------------|------|
| 3.1 | Define Seed reference hardware specification | BOM, schematic review |
| 3.2 | Port RVM to production target | Boot, isolate, witness, schedule |
| 3.3 | Environmental qualification | Temperature, vibration, power cycling |
| 3.4 | Security review: MPU bypass analysis | No known escalation from partition to kernel |

---

## Use Cases

| Use Case | Configuration | Why Seed |
|----------|--------------|----------|
| **Sensor node** | 1 partition, native code, deep sleep, periodic wake | Minimal RAM, years of battery life, witness log for audit |
| **Persistent edge monitor** | 1-2 partitions, always-on, flash-backed state | Survives power loss, reconstructs from checkpoint |
| **Secure anchor** | 1 partition, capability-gated crypto peripheral | Hardware-isolated key storage with witness attestation |
| **IoT gateway** | 2 partitions (network + application), BLE/UART | Isolates network stack from application logic |
| **Real-time controller** | 1 partition, Reflex mode, GPIO/ADC leases | Deterministic sub-microsecond response |

---

## Success Criteria

| # | Criterion | Target |
|---|-----------|--------|
| 1 | Kernel binary size (Seed profile) | < 64 KB flash |
| 2 | Kernel RAM usage (Seed profile) | < 16 KB static + stack |
| 3 | Boot to first witness (Cortex-M4 @ 64MHz) | < 50 ms |
| 4 | Partition switch latency (MPU reconfiguration) | < 5 microseconds |
| 5 | Deep sleep current draw | < 10 microamps (hardware dependent) |
| 6 | Witness chain integrity after power cycle | Validated on wake via flash checkpoint |
| 7 | 72-hour continuous operation | No witness gap, no memory leak, no crash |

---

## Consequences

### Positive

- **Validates DC-1 for real**: Seed is a production deployment where the coherence engine is absent by design, not by failure. This forces the kernel to be truly independent of Layer 2.
- **Constrains kernel size**: The 64KB flash target prevents kernel bloat. If a change breaks Seed, it means the kernel is growing too large.
- **Proves minimal viability**: If RVM works on 64KB RAM, it works everywhere. The Seed target is the existence proof that RVM is not "just another heavy hypervisor."
- **Enables IoT and edge security**: Capability-based isolation with witness attestation on microcontroller-class hardware is a novel capability. No existing embedded OS provides this combination.
- **Shared kernel code**: The Seed kernel is the same `ruvix-nucleus` crate compiled with `--features seed`. No separate kernel for embedded.

### Negative

- **MPU isolation is weaker than MMU**: MPU regions are coarse (power-of-2 size on ARMv7-M), limited in number (8-16), and do not provide address translation. A compromised partition that can control the MPU configuration registers can break isolation. Mitigation: kernel runs in Handler mode with exclusive MPU write access.
- **Compact witnesses sacrifice hash strength**: 128-bit truncated hashes provide less collision resistance than 256-bit. Acceptable for embedded chains of bounded length; unacceptable for long-lived archival. Compact witnesses should be expanded when aggregated off-device.
- **Limited agent support**: Most Seed deployments run native code, not WASM. This reduces the "agent runtime" value proposition to near-zero on Seed.
- **Hardware fragmentation**: Every Cortex-M variant has different peripheral addresses, clock trees, and MPU configurations. The HAL trait helps, but board-specific bring-up effort is non-trivial.
- **No stage-2 translation**: Without an MMU, there is no intermediate physical address space. Partitions share the physical address map, separated only by MPU regions. This is fundamentally less isolated than the Appliance model.

---

## Rejected Alternatives

| Alternative | Reason for Rejection |
|-------------|---------------------|
| **Skip Seed entirely** | Leaves DC-1 untested in production. Kernel size grows unchecked. Misses IoT/edge market. |
| **Use Tock OS directly** | Tock is not a hypervisor, does not support coherence domains, does not have a witness system. Would require forking and rewriting, losing the shared-kernel advantage. |
| **Use Hubris directly** | Hubris is task-isolated but not capability-based in the RVM sense. No witness system, no coherence domain abstraction. Same fork-and-rewrite problem. |
| **Cortex-A only (skip Cortex-M)** | Cortex-A has an MMU, which makes Seed easier but misses the hardest constraint: MPU-only operation. If Seed works on Cortex-M, it trivially works on small Cortex-A. |
| **Separate embedded kernel** | Maintaining two kernels (one for Appliance, one for Seed) doubles testing and diverges the codebase. Feature flags on a single `ruvix-nucleus` are strongly preferred. |
| **Full 64-byte witnesses on Seed** | At 64 bytes per witness with 64KB total RAM, the witness log would consume a disproportionate fraction of memory. The 32-byte compact format halves this cost while maintaining chain integrity. |

---

## References

- Levy, A., et al. "Multiprogramming a 64kB Computer Safely and Efficiently." SOSP 2017. (Tock OS)
- Clitherow, B., et al. "Hubris: A Lightweight, Memory-Safe, Message-Passing Kernel for Deeply Embedded Systems." (Oxide Computer)
- ARM Cortex-M Architecture Reference Manual (MPU, Handler/Thread mode, NVIC, SysTick)
- ARMv8-M Architecture Reference Manual (Enhanced MPU, TrustZone-M)
- Nordic Semiconductor nRF52840 Product Specification
- STMicroelectronics STM32H743 Reference Manual
- ADR-132: RVM Hypervisor Core
- ADR-137: Bare-Metal Boot Sequence
