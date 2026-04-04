//! The hot-path partition switch.
//!
//! This is the < 10 microsecond critical path from ADR-132.
//! **NO** allocation. **NO** graph work. **NO** policy evaluation.
//! Just: save registers -> update VTTBR -> flush TLB -> restore registers.
//!
//! Actual register manipulation requires `unsafe` / inline assembly and
//! is handled by the HAL crate. This module provides the safe stub
//! interface and timing measurement scaffolding.

/// Saved register state for a partition context.
///
/// Captures the minimal AArch64 EL2-visible state required to resume
/// execution in a partition. The HAL populates these fields from the
/// actual hardware registers.
#[derive(Debug, Clone, Copy)]
pub struct SwitchContext {
    /// General-purpose registers x0-x30.
    pub gp_regs: [u64; 31],
    /// Stack pointer for EL1 (SP_EL1).
    pub sp_el1: u64,
    /// Exception Link Register for EL2 (return address).
    pub elr_el2: u64,
    /// Saved Program Status Register for EL2.
    pub spsr_el2: u64,
    /// Stage-2 translation table base register (VTTBR_EL2).
    ///
    /// Encodes the VMID in bits \[55:48\] and the physical address of
    /// the stage-2 page table root in bits \[47:1\].
    pub vttbr_el2: u64,
}

impl SwitchContext {
    /// Create a zeroed switch context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            gp_regs: [0u64; 31],
            sp_el1: 0,
            elr_el2: 0,
            spsr_el2: 0,
            vttbr_el2: 0,
        }
    }

    /// Stub: save the current CPU registers into this context.
    ///
    /// In a real implementation, this would execute MRS instructions to
    /// read SP_EL1, ELR_EL2, SPSR_EL2, and VTTBR_EL2, plus capture x0-x30.
    /// This stub is a no-op -- the HAL agent fills in the assembly.
    pub fn save_context(&mut self) {
        // HAL stub: real implementation reads hardware registers.
        // Example (not real code):
        //   MRS x0, SP_EL1        -> self.sp_el1
        //   MRS x0, ELR_EL2       -> self.elr_el2
        //   MRS x0, SPSR_EL2      -> self.spsr_el2
        //   MRS x0, VTTBR_EL2     -> self.vttbr_el2
        //   STP x0, x1, ...       -> self.gp_regs
    }

    /// Stub: restore CPU registers from this context.
    ///
    /// The dual of [`save_context`](Self::save_context). In a real
    /// implementation, this writes MSR instructions for each system register
    /// and restores x0-x30 via LDP.
    pub fn restore_context(&self) {
        // HAL stub: real implementation writes hardware registers.
        // Example (not real code):
        //   MSR SP_EL1, x0
        //   MSR ELR_EL2, x0
        //   MSR SPSR_EL2, x0
        //   MSR VTTBR_EL2, x0
        //   LDP x0, x1, ...
    }
}

/// Perform a partition switch from `from` to `to`.
///
/// This is the hot path. Steps:
/// 1. Save current registers into `from`.
/// 2. Write `to.vttbr_el2` to VTTBR_EL2 (stage-2 page table base).
/// 3. TLB invalidate (`TLBI VMALLE1`).
/// 4. Barrier (`DSB ISH` + `ISB`).
/// 5. Restore registers from `to`.
///
/// Returns the number of nanoseconds elapsed (for profiling).
/// The stub implementation always returns 0 -- the HAL agent provides the
/// real timer-based measurement.
pub fn partition_switch(from: &mut SwitchContext, to: &SwitchContext) -> u64 {
    // Step 1: save current register state.
    from.save_context();

    // Step 2: update VTTBR_EL2.
    // HAL stub: MSR VTTBR_EL2, to.vttbr_el2
    let _ = to.vttbr_el2; // ensure the field is "read" for the compiler

    // Step 3: TLB invalidate.
    // HAL stub: TLBI VMALLE1

    // Step 4: barrier.
    // HAL stub: DSB ISH; ISB

    // Step 5: restore target register state.
    to.restore_context();

    // Stub: no real timer available without HAL.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_switch_context_new_is_zeroed() {
        let ctx = SwitchContext::new();
        assert_eq!(ctx.gp_regs, [0u64; 31]);
        assert_eq!(ctx.sp_el1, 0);
        assert_eq!(ctx.elr_el2, 0);
        assert_eq!(ctx.spsr_el2, 0);
        assert_eq!(ctx.vttbr_el2, 0);
    }

    #[test]
    fn test_save_restore_stub_is_noop() {
        let mut ctx = SwitchContext::new();
        ctx.gp_regs[0] = 0xCAFE;
        ctx.sp_el1 = 0x1000;
        ctx.elr_el2 = 0x2000;
        ctx.spsr_el2 = 0x3C5;
        ctx.vttbr_el2 = 0xDEAD_0000;

        // save_context is a stub, so it should not clobber our values.
        ctx.save_context();
        assert_eq!(ctx.gp_regs[0], 0xCAFE);
        assert_eq!(ctx.sp_el1, 0x1000);

        // restore_context is also a stub.
        ctx.restore_context();
        assert_eq!(ctx.vttbr_el2, 0xDEAD_0000);
    }

    #[test]
    fn test_switch_context_fields_preserved() {
        let mut from = SwitchContext::new();
        from.gp_regs[0] = 0xAAAA;
        from.gp_regs[30] = 0xBBBB;
        from.sp_el1 = 0x8000;
        from.elr_el2 = 0x4000_0000;
        from.spsr_el2 = 0x3C5;
        from.vttbr_el2 = 0x0001_0000_0000_0000;

        let mut to = SwitchContext::new();
        to.gp_regs[0] = 0xCCCC;
        to.sp_el1 = 0xF000;
        to.elr_el2 = 0x8000_0000;
        to.spsr_el2 = 0x1C5;
        to.vttbr_el2 = 0x0002_0000_0000_0000;

        let _ticks = partition_switch(&mut from, &to);

        // `from` fields should still hold the values we set (stub save is noop).
        assert_eq!(from.gp_regs[0], 0xAAAA);
        assert_eq!(from.sp_el1, 0x8000);

        // `to` fields should be unchanged (restore is noop).
        assert_eq!(to.gp_regs[0], 0xCCCC);
        assert_eq!(to.vttbr_el2, 0x0002_0000_0000_0000);
    }

    #[test]
    fn test_partition_switch_returns_stub_timing() {
        let mut from = SwitchContext::new();
        let to = SwitchContext::new();

        let elapsed = partition_switch(&mut from, &to);
        // Stub always returns 0 -- real timing comes from the HAL.
        assert_eq!(elapsed, 0);
    }

    #[test]
    fn test_partition_switch_is_repeatable() {
        let mut from = SwitchContext::new();
        let to = SwitchContext::new();

        let t1 = partition_switch(&mut from, &to);
        let t2 = partition_switch(&mut from, &to);
        // Stub returns the same value every time.
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_different_vttbr_values() {
        // Verify two contexts with different VTTBR values both survive a switch.
        let mut ctx_a = SwitchContext::new();
        ctx_a.vttbr_el2 = 0x0001_0000_0000_0000; // VMID 0x01

        let mut ctx_b = SwitchContext::new();
        ctx_b.vttbr_el2 = 0x0002_0000_0000_0000; // VMID 0x02

        partition_switch(&mut ctx_a, &ctx_b);

        assert_eq!(ctx_a.vttbr_el2, 0x0001_0000_0000_0000);
        assert_eq!(ctx_b.vttbr_el2, 0x0002_0000_0000_0000);
    }
}
