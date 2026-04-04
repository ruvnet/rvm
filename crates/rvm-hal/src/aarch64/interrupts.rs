//! GICv2 interrupt controller driver for QEMU virt (AArch64).
//!
//! The QEMU virt machine provides a GICv2 with:
//! - Distributor at 0x0800_0000
//! - CPU interface at 0x0801_0000
//!
//! This module provides the minimal interface needed for the hypervisor
//! to route and handle hardware interrupts at EL2.

use rvm_types::{RvmError, RvmResult};

/// GICv2 Distributor base address (QEMU virt).
const GICD_BASE: usize = 0x0800_0000;

/// GICv2 CPU Interface base address (QEMU virt).
const GICC_BASE: usize = 0x0801_0000;

// Distributor register offsets
/// Distributor Control Register.
const GICD_CTLR: usize = 0x000;
/// Interrupt Set-Enable Registers (base; 32 IRQs per register).
const GICD_ISENABLER: usize = 0x100;
/// Interrupt Clear-Enable Registers (base).
const GICD_ICENABLER: usize = 0x180;
/// Interrupt Priority Registers (base; 4 IRQs per register).
const GICD_IPRIORITYR: usize = 0x400;
/// Interrupt Processor Targets Registers (base; 4 IRQs per register).
const GICD_ITARGETSR: usize = 0x800;

// CPU Interface register offsets
/// CPU Interface Control Register.
const GICC_CTLR: usize = 0x000;
/// Priority Mask Register.
const GICC_PMR: usize = 0x004;
/// Interrupt Acknowledge Register.
const GICC_IAR: usize = 0x00C;
/// End of Interrupt Register.
const GICC_EOIR: usize = 0x010;

/// Maximum supported IRQ number.
const MAX_IRQ: u32 = 1020;

/// Spurious interrupt ID returned by GICC_IAR.
pub const IRQ_SPURIOUS: u32 = 1023;

/// Write a 32-bit value to a GIC register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped GIC register address.
#[inline]
unsafe fn gic_write(base: usize, offset: usize, val: u32) {
    let addr = (base + offset) as *mut u32;
    // SAFETY: Caller guarantees the GIC MMIO region is mapped as
    // device memory and the offset is a valid register.
    unsafe {
        core::ptr::write_volatile(addr, val);
    }
}

/// Read a 32-bit value from a GIC register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped GIC register address.
#[inline]
unsafe fn gic_read(base: usize, offset: usize) -> u32 {
    let addr = (base + offset) as *const u32;
    // SAFETY: Caller guarantees the GIC MMIO region is mapped.
    unsafe { core::ptr::read_volatile(addr) }
}

/// Initialize the GICv2 distributor and CPU interface.
///
/// Enables the distributor and CPU interface, and sets the priority mask
/// to allow all priority levels.
///
/// # Safety
///
/// Must be called once during boot. The GIC MMIO regions
/// (0x0800_0000 and 0x0801_0000) must be accessible.
pub unsafe fn gic_init() {
    // SAFETY: Boot-time GIC initialization. MMIO regions are accessible
    // in the initial flat/identity-mapped address space.
    unsafe {
        // Enable distributor (group 0 and group 1).
        gic_write(GICD_BASE, GICD_CTLR, 0x3);

        // Enable CPU interface, allow group 0 and group 1.
        gic_write(GICC_BASE, GICC_CTLR, 0x3);

        // Set priority mask to lowest priority (accept all interrupts).
        gic_write(GICC_BASE, GICC_PMR, 0xFF);
    }
}

/// Enable a specific IRQ in the GIC distributor.
///
/// Sets the corresponding bit in the GICD_ISENABLER register for the
/// given IRQ number. Also routes the IRQ to CPU 0 and sets default
/// priority.
///
/// # Errors
///
/// Returns `RvmError::InternalError` if `irq` exceeds the maximum.
///
/// # Safety
///
/// The GIC must have been initialized via [`gic_init`].
pub unsafe fn gic_enable_irq(irq: u32) -> RvmResult<()> {
    if irq > MAX_IRQ {
        return Err(RvmError::InternalError);
    }

    let reg_index = (irq / 32) as usize;
    let bit = 1u32 << (irq % 32);

    // SAFETY: GIC is initialized. The register offsets are computed
    // from a valid IRQ number within bounds.
    unsafe {
        // Enable the IRQ.
        gic_write(GICD_BASE, GICD_ISENABLER + reg_index * 4, bit);

        // Set priority to 0xA0 (middle priority).
        let prio_reg = (irq / 4) as usize;
        let prio_shift = (irq % 4) * 8;
        let prio_val = 0xA0u32 << prio_shift;
        let current = gic_read(GICD_BASE, GICD_IPRIORITYR + prio_reg * 4);
        let mask = !(0xFFu32 << prio_shift);
        gic_write(
            GICD_BASE,
            GICD_IPRIORITYR + prio_reg * 4,
            (current & mask) | prio_val,
        );

        // Route to CPU 0.
        let target_reg = (irq / 4) as usize;
        let target_shift = (irq % 4) * 8;
        let target_val = 0x01u32 << target_shift;
        let current = gic_read(GICD_BASE, GICD_ITARGETSR + target_reg * 4);
        let mask = !(0xFFu32 << target_shift);
        gic_write(
            GICD_BASE,
            GICD_ITARGETSR + target_reg * 4,
            (current & mask) | target_val,
        );
    }

    Ok(())
}

/// Disable a specific IRQ in the GIC distributor.
///
/// # Errors
///
/// Returns `RvmError::InternalError` if `irq` exceeds the maximum.
///
/// # Safety
///
/// The GIC must have been initialized via [`gic_init`].
pub unsafe fn gic_disable_irq(irq: u32) -> RvmResult<()> {
    if irq > MAX_IRQ {
        return Err(RvmError::InternalError);
    }

    let reg_index = (irq / 32) as usize;
    let bit = 1u32 << (irq % 32);

    // SAFETY: GIC is initialized. Writing to ICENABLER is safe and
    // only affects the specified IRQ.
    unsafe {
        gic_write(GICD_BASE, GICD_ICENABLER + reg_index * 4, bit);
    }

    Ok(())
}

/// Acknowledge the highest-priority pending interrupt.
///
/// Reads GICC_IAR and returns the interrupt ID. Returns
/// [`IRQ_SPURIOUS`] (1023) if no interrupt is pending.
///
/// # Safety
///
/// The GIC must have been initialized via [`gic_init`].
#[inline]
pub unsafe fn gic_ack() -> u32 {
    // SAFETY: GIC is initialized. Reading IAR is the standard
    // acknowledge sequence; it also marks the interrupt as active.
    unsafe { gic_read(GICC_BASE, GICC_IAR) & 0x3FF }
}

/// Signal end-of-interrupt for the given IRQ.
///
/// Writes the IRQ ID to GICC_EOIR to complete the interrupt handling
/// cycle. The GIC will then allow the same or lower-priority interrupts
/// to be delivered.
///
/// # Safety
///
/// The GIC must have been initialized. `irq` must be the value
/// previously returned by [`gic_ack`].
#[inline]
pub unsafe fn gic_eoi(irq: u32) {
    // SAFETY: GIC is initialized. Writing EOIR with the acknowledged
    // IRQ ID is the standard EOI sequence.
    unsafe {
        gic_write(GICC_BASE, GICC_EOIR, irq);
    }
}

/// AArch64 GIC-based interrupt controller implementing `InterruptOps`.
pub struct Aarch64Gic {
    /// Whether the GIC has been initialized.
    initialized: bool,
}

impl Aarch64Gic {
    /// Create a new, uninitialized GIC handle.
    #[must_use]
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    /// Initialize the GIC hardware.
    ///
    /// # Safety
    ///
    /// GIC MMIO regions must be accessible.
    pub unsafe fn init(&mut self) {
        // SAFETY: Caller guarantees MMIO access.
        unsafe {
            gic_init();
        }
        self.initialized = true;
    }
}

impl crate::InterruptOps for Aarch64Gic {
    fn enable(&mut self, irq: u32) -> RvmResult<()> {
        if !self.initialized {
            return Err(RvmError::InternalError);
        }
        // SAFETY: GIC was initialized in `init()`. The IRQ is validated
        // inside `gic_enable_irq`.
        unsafe { gic_enable_irq(irq) }
    }

    fn disable(&mut self, irq: u32) -> RvmResult<()> {
        if !self.initialized {
            return Err(RvmError::InternalError);
        }
        // SAFETY: GIC was initialized in `init()`.
        unsafe { gic_disable_irq(irq) }
    }

    fn acknowledge(&mut self) -> Option<u32> {
        if !self.initialized {
            return None;
        }
        // SAFETY: GIC was initialized in `init()`.
        let irq = unsafe { gic_ack() };
        if irq == IRQ_SPURIOUS {
            None
        } else {
            Some(irq)
        }
    }

    fn end_of_interrupt(&mut self, irq: u32) {
        if !self.initialized {
            return;
        }
        // SAFETY: GIC was initialized in `init()`. The caller is
        // expected to pass the IRQ ID returned by `acknowledge`.
        unsafe {
            gic_eoi(irq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InterruptOps;

    #[test]
    fn test_constants() {
        assert_eq!(GICD_BASE, 0x0800_0000);
        assert_eq!(GICC_BASE, 0x0801_0000);
        assert_eq!(MAX_IRQ, 1020);
        assert_eq!(IRQ_SPURIOUS, 1023);
    }

    #[test]
    fn test_gic_new() {
        let gic = Aarch64Gic::new();
        assert!(!gic.initialized);
    }

    #[test]
    fn test_enable_before_init_fails() {
        let mut gic = Aarch64Gic::new();
        // enable() should fail when GIC is not initialized.
        assert!(gic.enable(30).is_err());
    }

    #[test]
    fn test_acknowledge_before_init_returns_none() {
        let mut gic = Aarch64Gic::new();
        assert_eq!(gic.acknowledge(), None);
    }
}
