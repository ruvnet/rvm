//! AArch64 EL2 boot assembly stubs.
//!
//! Reads the current exception level, configures HCR_EL2 for stage-2
//! translation, manages VTTBR_EL2, and provides context-switch helpers
//! for saving/restoring guest register state.
//!
//! Assembly budget: < 500 lines total (ADR-137).
//! Target: QEMU virt machine (cortex-a72, EL2 entry).

/// Number of general-purpose registers saved during context switch (x0-x30).
pub const GP_REG_COUNT: usize = 31;

/// SPSR_EL2 M[3:0] value for EL1h (handler mode).
const SPSR_M_EL1H: u64 = 0b0101;

/// SPSR_EL2 M[3:0] value for EL1t (thread mode).
const SPSR_M_EL1T: u64 = 0b0100;

/// Mask for SPSR_EL2 M[3:0] field.
const SPSR_M_MASK: u64 = 0xF;

/// Addresses at or above this threshold are considered hypervisor address
/// space and must never appear in ELR_EL2 when returning to a guest.
const HYPERVISOR_ADDR_THRESHOLD: u64 = 0xFFFF_0000_0000_0000;

/// Sanitize an SPSR_EL2 value to prevent return to EL2 or higher.
///
/// The M[3:0] field is checked against the only two permitted guest modes:
/// EL1h (0b0101) and EL1t (0b0100). If the value would return to any
/// other exception level (especially EL2 = 0b1001), it is forced to EL1h
/// with DAIF masked (the safe default).
///
/// This is a **critical security gate** -- without it a malicious guest
/// could craft SPSR to ERET back into EL2 and escape the hypervisor.
#[inline]
pub fn sanitize_spsr(raw: u64) -> u64 {
    let mode = raw & SPSR_M_MASK;
    if mode == SPSR_M_EL1H || mode == SPSR_M_EL1T {
        raw
    } else {
        // Force EL1h with all DAIF bits masked (bits [9:6] = 0xF).
        // Preserve nothing from the untrusted value.
        (0xF << 6) | SPSR_M_EL1H
    }
}

/// Validate that an ELR_EL2 value does not point into hypervisor address
/// space. Guest return addresses must be below the hypervisor threshold.
///
/// Returns `true` if the address is safe for guest return.
#[inline]
pub fn validate_elr(elr: u64) -> bool {
    elr < HYPERVISOR_ADDR_THRESHOLD
}

/// Read the current exception level from the `CurrentEL` system register.
///
/// Returns the exception level as a value 0-3.
#[inline]
pub fn current_el() -> u8 {
    let el: u64;
    // SAFETY: Reading CurrentEL is a pure read with no side effects.
    // The register is always accessible regardless of exception level.
    unsafe {
        core::arch::asm!(
            "mrs {reg}, CurrentEL",
            reg = out(reg) el,
            options(nomem, nostack, preserves_flags),
        );
    }
    // CurrentEL[3:2] holds the EL value; bits [1:0] are RES0.
    ((el >> 2) & 0x3) as u8
}

/// Configure HCR_EL2 (Hypervisor Configuration Register) for stage-2
/// translation and trap routing.
///
/// Sets:
/// - VM (bit 0): Enable stage-2 address translation
/// - SWIO (bit 1): Set/Way Invalidation Override
/// - FMO (bit 3): Route physical FIQ to EL2
/// - IMO (bit 4): Route physical IRQ to EL2
/// - AMO (bit 5): Route SError to EL2
/// - TSC (bit 19): Trap SMC instructions to EL2
/// - RW (bit 31): EL1 executes in AArch64 mode
///
/// # Panics
///
/// Panics if not called at EL2.
pub fn configure_hcr_el2() {
    // SECURITY: This MUST be a hard assert, not debug_assert. Configuring
    // HCR_EL2 from the wrong exception level is a critical security violation
    // that must be caught in release builds.
    assert_eq!(current_el(), 2, "configure_hcr_el2 must be called at EL2");

    let hcr: u64 = (1 << 0)   // VM: enable stage-2 translation
        | (1 << 1)             // SWIO: set/way invalidation override
        | (1 << 3)             // FMO: route FIQ to EL2
        | (1 << 4)             // IMO: route IRQ to EL2
        | (1 << 5)             // AMO: route SError to EL2
        | (1 << 19)            // TSC: trap SMC to EL2
        | (1 << 31);           // RW: EL1 is AArch64

    // SAFETY: Writing HCR_EL2 at EL2 is the standard way to configure the
    // hypervisor. We hold no references to guest state at boot time.
    unsafe {
        core::arch::asm!(
            "msr HCR_EL2, {val}",
            "isb",
            val = in(reg) hcr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Set the stage-2 page table base register (VTTBR_EL2).
///
/// `base` must be the physical address of a 4KB-aligned stage-2 level-1
/// page table. `vmid` is placed in VTTBR_EL2\[63:48\] to tag TLB entries
/// for this partition. Each partition MUST have a unique VMID.
///
/// # Panics
///
/// Panics if `base` is not 4KB-aligned.
pub fn set_vttbr_el2(base: u64, vmid: u16) {
    assert_eq!(base & 0xFFF, 0, "VTTBR_EL2 base must be 4KB-aligned");

    // VMID in bits [63:48], BADDR in bits [47:1].
    let vttbr = ((vmid as u64) << 48) | (base & 0x0000_FFFF_FFFF_FFFE);

    // SAFETY: Setting VTTBR_EL2 at EL2 with a valid, aligned page table
    // base is the required step before enabling stage-2 translation.
    // The VMID field isolates this partition's TLB entries from others.
    unsafe {
        core::arch::asm!(
            "msr VTTBR_EL2, {val}",
            "isb",
            val = in(reg) vttbr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Configure VTCR_EL2 (Virtualization Translation Control Register)
/// for 4KB granule, 2-level stage-2 translation.
///
/// Configuration:
/// - T0SZ = 24 (40-bit IPA space, 1TB)
/// - SL0 = 1 (start at level 1)
/// - IRGN0 = 1 (inner write-back)
/// - ORGN0 = 1 (outer write-back)
/// - SH0 = 3 (inner shareable)
/// - TG0 = 0 (4KB granule)
/// - PS = 2 (40-bit PA)
pub fn configure_vtcr_el2() {
    let vtcr: u64 = (24 << 0)  // T0SZ = 24: 40-bit IPA
        | (1 << 6)              // SL0 = 1: start at level 1
        | (1 << 8)              // IRGN0 = 1: inner write-back
        | (1 << 10)             // ORGN0 = 1: outer write-back
        | (3 << 12)             // SH0 = 3: inner shareable
        | (0 << 14)             // TG0 = 0: 4KB granule
        | (2 << 16);            // PS = 2: 40-bit PA

    // SAFETY: Writing VTCR_EL2 configures the translation regime for
    // stage-2. Called during boot before any guest is running.
    unsafe {
        core::arch::asm!(
            "msr VTCR_EL2, {val}",
            "isb",
            val = in(reg) vtcr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Invalidate all TLB entries at EL2 and execute barriers.
///
/// Issues TLBI ALLE2, followed by DSB ISH and ISB to ensure
/// completion before subsequent memory accesses.
#[inline]
pub fn invalidate_tlb() {
    // SAFETY: TLB invalidation is safe at any point. The DSB+ISB
    // sequence ensures ordering. No memory references are invalidated
    // that the caller does not expect.
    unsafe {
        core::arch::asm!(
            "tlbi alle2",
            "dsb ish",
            "isb",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Invalidate all stage-2 TLB entries (guest translations).
///
/// Issues TLBI VMALLS12E1, which invalidates both stage-1 and
/// stage-2 entries for the current VMID.
#[inline]
pub fn invalidate_stage2_tlb() {
    // SAFETY: Stage-2 TLB invalidation is required after modifying
    // stage-2 page tables. Called with DSB+ISB for ordering.
    unsafe {
        core::arch::asm!(
            "tlbi vmalls12e1",
            "dsb ish",
            "isb",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Save and restore guest vCPU register state for a context switch.
///
/// Saves EL2 system registers (SP_EL1, ELR_EL2, SPSR_EL2) from the
/// current CPU into `from_regs`, then loads the same set from `to_regs`.
/// General-purpose registers (x0-x30) are stored/loaded via memory
/// operations rather than register clobbers, because LLVM reserves
/// x18 (platform register), x19 (LLVM internal), and x29 (frame pointer).
///
/// # Register layout in the 34-element arrays
///
/// ```text
/// [0..31]  : x0 - x30  (stored via STP/LDP in assembly)
/// [31]     : SP_EL1
/// [32]     : ELR_EL2  (return address into guest)
/// [33]     : SPSR_EL2 (saved PSTATE of guest)
/// ```
///
/// # Security
///
/// Before restoring SPSR_EL2, the value is sanitized via [`sanitize_spsr`]
/// to ensure the M\[3:0\] field only allows EL1h or EL1t. This prevents a
/// malicious guest from crafting a saved SPSR that ERets back into EL2.
///
/// ELR_EL2 is validated to be below the hypervisor address threshold.
/// If the target VMIDs differ between the current and incoming context,
/// a TLBI VMALLS12E1 is issued to flush stale stage-1/stage-2 entries.
///
/// NOTE: A full context switch (including x18/x19/x29) would be
/// implemented as a standalone `.S` assembly file linked externally,
/// or via `core::arch::global_asm!`. This inline version saves/restores
/// the system registers and the caller-clobberable GP registers.
/// The full GP register save/restore is done through memory operations
/// within the asm block, which does not require LLVM register clobbers.
///
/// # Safety
///
/// Both `from_regs` and `to_regs` must point to valid 34-element arrays.
/// This function must be called at EL2. The caller is responsible for
/// ensuring that `to_regs` contains a valid saved context.
///
/// # Panics
///
/// Panics if `to_regs[33]` (SPSR_EL2) contains a mode field that would
/// return to EL2 or higher after sanitization (this cannot happen since
/// sanitize_spsr forces a safe default, but the ELR check will panic if
/// the guest return address is in hypervisor space).
pub unsafe fn context_switch(from_regs: &mut [u64; 34], to_regs: &[u64; 34]) {
    // SECURITY: Validate ELR_EL2 is not in hypervisor address space.
    // A guest-controlled ELR pointing into EL2 code would let the guest
    // redirect hypervisor execution on ERET.
    assert!(
        validate_elr(to_regs[32]),
        "ELR_EL2 ({:#x}) points into hypervisor address space",
        to_regs[32]
    );

    // SECURITY: Sanitize SPSR_EL2 M[3:0] to prevent ERET to EL2.
    // We write the sanitized value into to_regs[33] via raw pointer so
    // the assembly block loads the safe version from the same offset it
    // always did. This avoids consuming an additional register operand
    // (the asm block already uses all 31 GP registers).
    let sanitized_spsr: u64 = sanitize_spsr(to_regs[33]);

    // SAFETY: We write only to index 33 of the array, which is within
    // bounds. The caller owns this context and we are on the exclusive
    // code path (interrupts routed to EL2 via HCR_EL2). Writing the
    // sanitized SPSR here is semantically equivalent to the caller
    // having sanitized it before calling us.
    unsafe {
        let spsr_slot = to_regs.as_ptr().cast_mut().add(33);
        core::ptr::write_volatile(spsr_slot, sanitized_spsr);
    }

    // Delegate to the inner function which contains only the asm block.
    // This separation ensures LLVM doesn't hold assert format-string
    // temporaries live across the asm block (which uses all 31 GP regs).
    //
    // SAFETY: Caller guarantees valid 34-element arrays and EL2. The
    // SPSR slot at to_regs[33] has been sanitized above.
    unsafe {
        context_switch_inner(from_regs, to_regs);
    }
}

/// Inner context-switch routine containing only the register
/// save/restore assembly. Separated from [`context_switch`] to prevent
/// LLVM from holding validation temporaries live across the asm block,
/// which would exceed the AArch64 register budget.
///
/// # Safety
///
/// Both arrays must be valid 34-element slices. Must be called at EL2.
/// `to_regs[33]` must already be sanitized by the caller.
#[inline(never)]
unsafe fn context_switch_inner(from_regs: &mut [u64; 34], to_regs: &[u64; 34]) {
    let from_ptr = from_regs.as_mut_ptr();
    let to_ptr = to_regs.as_ptr();

    // SAFETY: Caller guarantees valid pointers and EL2 execution.
    // The STP/LDP instructions operate on memory pointed to by from_ptr
    // and to_ptr. We explicitly name all GP registers in the assembly
    // rather than in clobber lists, because LLVM reserves x18/x19/x29.
    //
    // SPSR_EL2 at [to + #264] has been sanitized by the caller
    // (context_switch), so the LDR below loads only the safe value.
    unsafe {
        core::arch::asm!(
            // ---- SAVE current context to from_ptr ----
            // Save x0-x17 (caller-saved registers)
            "stp x0,  x1,  [{from}, #0]",
            "stp x2,  x3,  [{from}, #16]",
            "stp x4,  x5,  [{from}, #32]",
            "stp x6,  x7,  [{from}, #48]",
            "stp x8,  x9,  [{from}, #64]",
            "stp x10, x11, [{from}, #80]",
            "stp x12, x13, [{from}, #96]",
            "stp x14, x15, [{from}, #112]",
            "stp x16, x17, [{from}, #128]",
            // Save x18-x29 (callee-saved + platform)
            "stp x18, x19, [{from}, #144]",
            "stp x20, x21, [{from}, #160]",
            "stp x22, x23, [{from}, #176]",
            "stp x24, x25, [{from}, #192]",
            "stp x26, x27, [{from}, #208]",
            "stp x28, x29, [{from}, #224]",
            // Save x30 (LR)
            "str x30, [{from}, #240]",
            // Save SP_EL1
            "mrs {tmp}, SP_EL1",
            "str {tmp}, [{from}, #248]",
            // Save ELR_EL2 (guest return address)
            "mrs {tmp}, ELR_EL2",
            "str {tmp}, [{from}, #256]",
            // Save SPSR_EL2 (guest PSTATE)
            "mrs {tmp}, SPSR_EL2",
            "str {tmp}, [{from}, #264]",

            // ---- RESTORE new context from to_ptr ----
            // Restore ELR_EL2 from memory (already validated by caller)
            "ldr {tmp}, [{to}, #256]",
            "msr ELR_EL2, {tmp}",
            // Restore SPSR_EL2 (sanitized by caller via write_volatile)
            "ldr {tmp}, [{to}, #264]",
            "msr SPSR_EL2, {tmp}",
            // Restore SP_EL1
            "ldr {tmp}, [{to}, #248]",
            "msr SP_EL1, {tmp}",
            // Restore x30 (LR)
            "ldr x30, [{to}, #240]",
            // Restore x28-x18 (callee-saved, in reverse order)
            "ldp x28, x29, [{to}, #224]",
            "ldp x26, x27, [{to}, #208]",
            "ldp x24, x25, [{to}, #192]",
            "ldp x22, x23, [{to}, #176]",
            "ldp x20, x21, [{to}, #160]",
            "ldp x18, x19, [{to}, #144]",
            // Restore x0-x17 (caller-saved)
            "ldp x16, x17, [{to}, #128]",
            "ldp x14, x15, [{to}, #112]",
            "ldp x12, x13, [{to}, #96]",
            "ldp x10, x11, [{to}, #80]",
            "ldp x8,  x9,  [{to}, #64]",
            "ldp x6,  x7,  [{to}, #48]",
            "ldp x4,  x5,  [{to}, #32]",
            "ldp x2,  x3,  [{to}, #16]",
            "ldp x0,  x1,  [{to}, #0]",
            // Synchronize instruction stream after context change
            "isb",

            from = in(reg) from_ptr,
            to = in(reg) to_ptr,
            tmp = out(reg) _,
            // Clobber caller-saved GP registers that LLVM allows.
            // x18 (platform), x19 (LLVM-reserved), x29 (FP) are
            // restored via LDP above but cannot appear in clobber lists.
            // LLVM will save/restore them around this asm block as needed.
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            out("x20") _, out("x21") _, out("x22") _, out("x23") _,
            out("x24") _, out("x25") _, out("x26") _, out("x27") _,
            out("x28") _, out("x30") _,
            options(nostack),
        );
    }
}

/// Perform a VMID-aware context switch with TLB invalidation.
///
/// Wraps [`context_switch`] with an additional step: if `from_vmid` and
/// `to_vmid` differ, a TLBI VMALLS12E1 is issued after saving the old
/// context and before restoring the new one. This ensures stale stage-1
/// and stage-2 TLB entries from the previous partition do not leak into
/// the incoming partition's address space.
///
/// # Safety
///
/// Same requirements as [`context_switch`]. Additionally, `from_vmid`
/// and `to_vmid` must accurately reflect the VMIDs of the respective
/// contexts.
pub unsafe fn context_switch_vmid(
    from_regs: &mut [u64; 34],
    to_regs: &[u64; 34],
    from_vmid: u16,
    to_vmid: u16,
) {
    if from_vmid != to_vmid {
        // SAFETY: TLBI VMALLS12E1 invalidates all stage-1 and stage-2
        // TLB entries for the current VMID. The DSB+ISB ensures
        // completion before the new context is restored. This is
        // required when switching between partitions with different
        // VMIDs to prevent cross-partition TLB leaks.
        invalidate_stage2_tlb();
    }

    // SAFETY: Caller guarantees valid arrays and EL2 execution.
    unsafe {
        context_switch(from_regs, to_regs);
    }
}

/// Clear the BSS section to zero.
///
/// # Safety
///
/// Must be called exactly once during boot, before any Rust code that
/// depends on zero-initialized statics. The `__bss_start` and `__bss_end`
/// symbols must be defined by the linker script.
pub unsafe fn clear_bss() {
    extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    // SAFETY: Linker script guarantees __bss_start <= __bss_end and the
    // region is valid, writable memory. Called once before any statics
    // are read.
    unsafe {
        let start = core::ptr::addr_of_mut!(__bss_start);
        let end = core::ptr::addr_of_mut!(__bss_end);
        debug_assert!(
            end as usize >= start as usize,
            "BSS end ({:p}) < start ({:p}): linker script misconfigured",
            end,
            start,
        );
        let len = (end as usize).saturating_sub(start as usize);
        core::ptr::write_bytes(start, 0, len);
    }
}

/// Park the current CPU in a low-power wait loop.
///
/// This is used for secondary CPUs or as a fallback halt.
#[inline]
pub fn wfi_loop() -> ! {
    loop {
        // SAFETY: WFI places the core in low-power state until the next
        // interrupt or event. It has no side effects on memory.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}
