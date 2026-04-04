# ADR-137: Bare-Metal Boot Sequence

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-136 (Memory Hierarchy and Reconstruction)

---

## Context

ADR-132 establishes that RVM boots bare-metal with no KVM or Linux dependency, targeting a cold-boot-to-first-witness time of less than 250ms. The architecture document (`docs/research/ruvm/architecture.md`) defines the boot sequence at a high level: assembly reset vector, Rust entry, MMU bring-up, hypervisor mode configuration, kernel object initialization, and scheduler entry. Existing code in `crates/ruvix/crates/aarch64/` provides `boot.rs` and `mmu.rs` stubs that demonstrate EL1-level initialization with identity mapping.

This ADR specifies the complete boot sequence in detail, including the assembly budget, the HAL trait contract, the per-architecture requirements, the witness instrumentation of each boot stage, and the constraint that boot must succeed without the coherence engine (DC-1).

### Problem Statement

1. **No bootloader dependency**: RVM cannot rely on GRUB, U-Boot, or any Linux-based bootloader chain. The reset vector must be self-contained and architecture-specific.
2. **Hypervisor-level entry**: Unlike a traditional kernel that boots at EL1/Ring 0, RVM must enter hypervisor mode (EL2, HS-mode, or VMX root) from the earliest possible point. On QEMU AArch64 virt, firmware drops execution at EL2 directly; on other platforms, elevation is required.
3. **Measured boot**: Every boot stage must emit a witness record with a monotonic timestamp, enabling post-hoc timing analysis and attestation of the boot chain.
4. **Multi-architecture support**: The boot sequence must be structurally identical across AArch64, RISC-V, and x86-64, differing only in the assembly stubs and HAL implementations.
5. **Boot without coherence engine**: Per DC-1, the kernel must reach a running state (scheduling partitions, emitting witnesses) without any Layer 2 involvement.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| Firecracker (AWS) | ~125ms microVM boot on KVM | Performance comparison; RVM targets <250ms without KVM |
| RustyHermit | Bare-metal Rust unikernel boot | Proves Rust reset-vector-to-main viability |
| Theseus OS | Intralingual Rust OS boot | Demonstrates minimal assembly stub pattern |
| ARM Architecture Reference Manual | EL2/EL3 entry, HCR_EL2, VTTBR_EL2 | Authoritative AArch64 hypervisor boot reference |
| RISC-V Privileged Specification | HS-mode, hgatp, hstatus | Authoritative RISC-V hypervisor extension reference |
| Intel SDM Vol. 3 | VMX root mode, VMXON, EPT | Authoritative x86-64 virtualization reference |
| Tock OS | Minimal Cortex-M/Cortex-A boot in Rust | Informs constrained-boot patterns |

---

## Decision

Implement the RVM bare-metal boot sequence as a seven-stage pipeline that is structurally identical across all target architectures, with platform-specific assembly stubs confined to Stage 0. QEMU AArch64 virt is the reference platform for initial development.

### Stage 0: Reset Vector (Assembly)

The CPU begins execution at the platform-defined reset vector. A minimal assembly stub performs operations that cannot be expressed in Rust.

**Operations (all architectures):**

1. Verify execution level (EL2 / HS-mode / VMX root)
2. Disable MMU and caches (clean slate)
3. Set up exception vector table for the hypervisor level
4. Initialize stack pointer to `_stack_top`
5. Clear BSS (`__bss_start` to `__bss_end`)
6. Preserve platform info pointer (DTB address or multiboot2 info) in first argument register
7. Branch to `ruvix_entry` (Rust)

**AArch64 specifics:**
- Entry at EL2 on QEMU virt (firmware provides this directly)
- Configure `sctlr_el2`: M=0, C=0, I=0 (MMU/caches off)
- Set `vbar_el2` to the hypervisor exception vector table
- `x0` carries the DTB address through to Rust

**RISC-V specifics:**
- Entry via OpenSBI at S-mode; must verify H-extension (`misa` bit 7) for HS-mode
- Park non-boot harts immediately
- `a0` = hart ID, `a1` = DTB address

**x86-64 specifics:**
- Entry in long mode from a multiboot2-compliant loader
- Verify VMX support via `IA32_FEATURE_CONTROL` MSR
- `rdi` = multiboot2 info pointer

**Assembly budget**: < 500 lines per architecture, covering reset vector, exception/interrupt trap entry stubs, and context switch stub. All other logic is Rust.

### Stage 1: Rust Entry and Hardware Detection

The assembly stub calls `ruvix_entry`, the single `#[no_mangle] extern "C"` entry point defined in `ruvix-nucleus`.

```rust
#[no_mangle]
pub extern "C" fn ruvix_entry(platform_info: usize) -> ! {
    // Stage 1: Hardware detection via DTB/multiboot2 parsing
    let hw = HardwareInfo::detect(platform_info);

    // Stage 2: Early serial
    let mut console = hw.early_console();
    console.write_str("RVM v0.1.0 booting\n");

    // ... stages 3-7 follow
}
```

`HardwareInfo::detect` parses the device tree blob (AArch64/RISC-V) or multiboot2 info (x86-64) to discover: core count, RAM regions, UART base address, interrupt controller type, and timer frequency.

### Stage 2: UART Init and Early Serial Output

Initialize the platform UART (PL011 on QEMU AArch64 virt) for diagnostic output. This is the first externally observable sign of life. All subsequent boot stages log their entry and completion to the serial console.

### Stage 3: MMU Bring-Up

Configure the memory management unit for the hypervisor level:

- **AArch64**: Configure `MAIR_EL2`, `TCR_EL2` (4KB granule, 48-bit VA), and stage-1 page tables for the hypervisor's own address space. Enable two-stage translation by configuring `VTCR_EL2` for stage-2 tables used by partitions.
- **RISC-V**: Configure `hgatp` for guest physical address translation (G-stage).
- **x86-64**: Set up host page tables and prepare EPT (Extended Page Table) structures.

The existing `crates/ruvix/crates/aarch64/src/mmu.rs` stub operates at EL1 with `TTBR0_EL1`/`TTBR1_EL1`. The boot sequence must be upgraded to use EL2 registers (`TTBR0_EL2`, `VTCR_EL2`, `VTTBR_EL2`).

### Stage 4: Hypervisor Mode Configuration

Enter and configure the hypervisor execution level. This is the point where RVM takes ownership of the hardware.

| Architecture | Level | Key Registers | Configuration |
|-------------|-------|---------------|---------------|
| AArch64 | EL2 | `HCR_EL2` | VM=1 (enable stage-2), SWIO=1, FMO/IMO=1 (trap FIQ/IRQ) |
| RISC-V | HS-mode | `hstatus`, `hedeleg`, `hideleg` | Configure trap delegation, enable VS-mode for partitions |
| x86-64 | VMX root | `VMXON`, `VMCS` | Enter VMX root mode, configure VM-execution controls |

After this stage, RVM controls all hardware traps and address translation for partitions.

### Stage 5: Kernel Object Initialization

Allocate and initialize the core kernel object tables:

1. **Capability manager** — root capability, slab allocator
2. **Region manager** — backed by physical allocator from Stage 3
3. **Queue manager** — pre-allocated ring buffer pool (256 queues)
4. **Proof engine** — P1 (capability check) + P2 (policy validation) layers
5. **Witness log** — append-only, physically backed
6. **Partition manager** — coherence domain lifecycle
7. **CommEdge manager** — inter-partition channels
8. **Scheduler** — deadline + cut-pressure priority (DC-4), initially with cut_pressure_boost = 0 since coherence engine is absent

The coherence engine (Layer 2) is NOT initialized during boot. The pressure engine starts in degraded mode with `degraded_flag = true` and `last_known_cut = None`. This satisfies DC-1.

### Stage 6: First Witness (BOOT_COMPLETE)

Emit the `BOOT_COMPLETE` witness record. This is a 64-byte chained witness containing:
- Witness type: `BOOT_COMPLETE`
- Monotonic timestamp (nanoseconds since reset)
- Hash of previous witness (genesis hash for first witness)
- Hardware fingerprint (arch, core count, RAM)
- Boot duration measurement

**This is the 250ms gate.** The elapsed time from reset vector entry to this witness must be under 250 milliseconds.

### Stage 7: Create Initial Partition

Create the first user-space coherence domain:
1. Allocate a stage-2 address space for the partition
2. Create a capability table scoped to the partition
3. Load the boot RVF (RuVector Format) payload if present
4. Transition the partition to `Active` state
5. Enter the scheduler loop (never returns)

### HAL Trait: `HypervisorHal`

The Hardware Abstraction Layer trait captures all operations that differ between architectures. Each architecture crate (`ruvix-aarch64`, `ruvix-riscv`, `ruvix-x86_64`) provides an implementation.

```rust
pub trait HypervisorHal {
    /// Stage-2/EPT page table type
    type Stage2Table;

    /// Virtual CPU context type
    type VcpuContext;

    /// Configure the CPU for hypervisor mode (Stage 4).
    unsafe fn init_hypervisor_mode(&self) -> Result<(), HalError>;

    /// Create a new stage-2 address space for a partition.
    fn create_stage2_table(
        &self,
        phys: &mut dyn PhysicalAllocator,
    ) -> Result<Self::Stage2Table, HalError>;

    /// Map a page in a stage-2 table (IPA -> PA).
    fn stage2_map(
        &self,
        table: &mut Self::Stage2Table,
        ipa: u64, pa: u64,
        attrs: Stage2Attrs,
    ) -> Result<(), HalError>;

    /// Unmap a page from a stage-2 table.
    fn stage2_unmap(
        &self,
        table: &mut Self::Stage2Table,
        ipa: u64,
    ) -> Result<(), HalError>;

    /// Switch to a partition's address space and restore vCPU context.
    unsafe fn enter_partition(
        &self,
        table: &Self::Stage2Table,
        vcpu: &Self::VcpuContext,
    );

    /// Handle a trap from a partition.
    fn handle_trap(
        &self,
        vcpu: &mut Self::VcpuContext,
        trap: TrapInfo,
    ) -> TrapAction;

    /// Inject a virtual interrupt into a partition.
    fn inject_virtual_irq(
        &self,
        vcpu: &mut Self::VcpuContext,
        irq: u32,
    ) -> Result<(), HalError>;

    /// Flush stage-2 TLB entries for a partition.
    fn flush_stage2_tlb(&self, vmid: u16);
}
```

### Architecture Targets

| Priority | Architecture | Platform | HAL Crate | Status |
|----------|-------------|----------|-----------|--------|
| Primary | AArch64 | QEMU virt | `ruvix-aarch64` | Stubs exist (`boot.rs`, `mmu.rs`) |
| Secondary | RISC-V | QEMU virt (H-extension) | `ruvix-riscv` | Phase C |
| Tertiary | x86-64 | QEMU with VMX | `ruvix-x86_64` | Phase D |

### Measured Boot: Witness Instrumentation

Every boot stage emits a witness record for timing and attestation:

| Stage | Witness Type | Measurement |
|-------|-------------|-------------|
| 0 | `RESET_VECTOR_ENTRY` | Timestamp at first Rust-accessible point (immediately after assembly) |
| 1 | `HARDWARE_DETECTED` | Platform info: arch, cores, RAM |
| 2 | `UART_INITIALIZED` | Console ready, elapsed since reset |
| 3 | `MMU_CONFIGURED` | Page table root address, VA width |
| 4 | `HYPERVISOR_ACTIVE` | Privilege level confirmed, trap configuration |
| 5 | `KERNEL_OBJECTS_READY` | Object table sizes, allocator state |
| 6 | `BOOT_COMPLETE` | Full boot duration, hardware fingerprint |
| 7 | `FIRST_PARTITION_CREATED` | Partition ID, stage-2 table base |

Witnesses before Stage 5 (when the witness log is initialized) are buffered in a small static array and flushed to the log during Stage 5. The buffer holds up to 8 pre-log witness records.

### Boot Without Coherence Engine (DC-1 Compliance)

The boot sequence has zero dependencies on Layer 2. Specifically:

- The scheduler initializes with `cut_pressure_boost = 0` for all partitions
- The pressure engine starts in `degraded_flag = true` with no active graph
- Partition placement uses static affinity (core 0 by default)
- The coherence engine may be loaded later as an optional Layer 2 module
- If the coherence engine is never loaded, the system runs indefinitely with locality-based scheduling

---

## Implementation

### Existing Code

The `crates/ruvix/crates/aarch64/` directory contains:

| File | Contents | Boot Relevance |
|------|----------|----------------|
| `boot.rs` | `early_init()`: BSS clear, EL1 MMU init, exception vectors, `kernel_main()` | Must be upgraded to EL2 entry, `ruvix_entry` handoff |
| `mmu.rs` | `Mmu` struct: MAIR/TCR/TTBR at EL1, 4KB granule, 48-bit VA, `MmuTrait` impl | Must add EL2 registers and stage-2 table support |
| `exception.rs` | Exception vector stubs | Must be extended for EL2 trap handling |
| `registers.rs` | Register accessors (`sctlr_el1`, `vbar_el1`, `ttbr0_el1`, etc.) | Must add EL2 register accessors |
| `lib.rs` | Module root | Module exports |

### Required Changes

1. **`boot.rs`**: Replace `early_init` at EL1 with `ruvix_entry`-compatible EL2 boot path. Remove direct `kernel_main` call; instead, the assembly reset vector calls `ruvix_entry` in `ruvix-nucleus`.
2. **`mmu.rs`**: Add `Stage2Tables` struct and EL2-level page table configuration (VTCR_EL2, VTTBR_EL2). Retain EL1 page table support for partition-internal use.
3. **`registers.rs`**: Add accessors for `sctlr_el2`, `hcr_el2`, `vtcr_el2`, `vttbr_el2`, `vbar_el2`, `ttbr0_el2`.
4. **New: `ruvix-hal/src/hypervisor.rs`**: Define the `HypervisorHal` trait.
5. **New: `ruvix-nucleus/src/entry.rs`**: The unified `ruvix_entry` function.
6. **New: `ruvix-nucleus/src/init.rs`**: `Kernel::init` for Stage 5 object initialization.

### Linker Script Requirements

Each architecture needs a linker script that:
- Places `.text.boot` at the reset vector address
- Defines `_stack_top` (typically 64KB stack for boot)
- Defines `__bss_start` and `__bss_end`
- Places the witness pre-log buffer in a known static location

### QEMU Invocation (Reference)

```bash
qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a72 \
    -m 256M \
    -nographic \
    -kernel target/aarch64-unknown-none/release/ruvix \
    -semihosting-config enable=on,target=native
```

No `-enable-kvm`. No `-kernel` pointing to a Linux image. The `ruvix` binary IS the firmware.

---

## Success Criteria

| # | Criterion | Target |
|---|-----------|--------|
| 1 | Cold boot to `BOOT_COMPLETE` witness | < 250ms on QEMU AArch64 virt |
| 2 | Assembly budget | < 500 lines per architecture |
| 3 | EL2 ownership verified | `CurrentEL` reads 0x8 (EL2) after Stage 0 |
| 4 | Stage-2 translation active | Partition IPA access translated to PA via VTTBR_EL2 |
| 5 | Witness chain complete | 7 chained witness records from reset to first partition |
| 6 | Boot without coherence engine | System runs, schedules, and emits witnesses with Layer 2 absent |

---

## Consequences

### Positive

- **No Linux dependency**: The entire boot chain is self-contained Rust + minimal assembly. No initramfs, no kernel modules, no device tree overlay complexity.
- **Measured boot from reset**: Full witness chain enables post-hoc boot timing analysis and remote attestation of the boot sequence.
- **Multi-architecture from day one**: The `HypervisorHal` trait ensures that adding RISC-V and x86-64 support is a matter of implementing the trait, not restructuring the boot flow.
- **DC-1 validated at boot**: Boot explicitly tests the "kernel without coherence engine" configuration, preventing accidental coupling.
- **Existing code reusable**: The `aarch64/boot.rs` and `aarch64/mmu.rs` stubs provide a foundation; upgrade from EL1 to EL2 is incremental.

### Negative

- **Bare-metal boot is harder than KVM-assisted**: No KVM means no `KVM_SET_VCPU_STATE`, no `KVM_RUN`. Every trap, every page table walk, every interrupt injection must be implemented from scratch.
- **Assembly per architecture**: Three assembly stubs to maintain (AArch64, RISC-V, x86-64), each with subtle platform-specific requirements.
- **QEMU is not real hardware**: Boot timing on QEMU is not representative of real silicon. The 250ms target must be re-validated on physical hardware during M7.
- **Pre-log witness buffering adds complexity**: Witnesses emitted before the log is initialized require a separate static buffer and flush path.
- **EL2 debugging is harder**: Fewer tools support hypervisor-level debugging compared to EL1/Ring 0. QEMU's `-d` flags and semihosting are the primary debug aids.

---

## Rejected Alternatives

| Alternative | Reason for Rejection |
|-------------|---------------------|
| **KVM-assisted boot** | Adds Linux kernel dependency. Cannot achieve sub-10-microsecond partition switch through KVM exit path. Contradicts ADR-132 core decision. |
| **U-Boot as first stage** | Adds a C-based firmware dependency. DTB is available from QEMU directly; U-Boot's SPL/TPL chain is unnecessary overhead. |
| **EL1-only operation** | Loses two-stage address translation. Cannot trap partition page table modifications. Cannot enforce hypervisor-level isolation. |
| **Unified assembly for all architectures** | ARM, RISC-V, and x86 have fundamentally different instruction sets, privilege models, and boot conventions. A single assembly file is impossible. |
| **Rust `global_asm!` instead of separate `.S` files** | Inline assembly is harder to debug, harder to set linker section attributes, and harder to review for correctness. Separate assembly files with clear contracts are preferred. |

---

## References

- ARM Architecture Reference Manual, ARMv8-A (EL2/EL3 boot, HCR_EL2, VTCR_EL2, VTTBR_EL2)
- RISC-V Privileged Specification, v1.12 (HS-mode, hgatp, hstatus)
- Intel Software Developer's Manual, Vol. 3, Ch. 23-28 (VMX, VMCS, EPT)
- Agache, A., et al. "Firecracker: Lightweight Virtualization for Serverless Applications." NSDI 2020.
- Boos, K., et al. "Theseus: an Experiment in Operating System Structure and State Management." OSDI 2020.
- Levy, A., et al. "The Case for Writing a Kernel in Rust." APSys 2017.
- RVM architecture document: `docs/research/ruvm/architecture.md`
- Existing AArch64 stubs: `crates/ruvix/crates/aarch64/src/boot.rs`, `crates/ruvix/crates/aarch64/src/mmu.rs`
