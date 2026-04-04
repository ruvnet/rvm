//! # RVM Hardware Abstraction Layer
//!
//! Platform-agnostic traits for the RVM microhypervisor, as specified in
//! ADR-133. Concrete implementations are provided per target (`AArch64`,
//! RISC-V, x86-64).
//!
//! ## Subsystems
//!
//! - [`Platform`] -- top-level platform discovery and initialization
//! - [`MmuOps`] -- stage-2 page table management
//! - [`TimerOps`] -- monotonic timer and deadline scheduling
//! - [`InterruptOps`] -- interrupt routing and masking
//!
//! ## Design Constraints (ADR-133)
//!
//! - All trait methods return `RvmResult`
//! - No `unsafe` in trait *definitions* (implementations may need it)
//! - Zero-copy: pass borrowed slices, never owned buffers

#![no_std]
// NOTE: `deny` instead of `forbid` because the HAL is the hardware boundary.
// Concrete arch implementations (aarch64, riscv, x86_64) require `unsafe`
// for register access, MMIO, and inline assembly. Every `unsafe` block in
// this crate must have a `// SAFETY:` comment documenting its invariant.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::new_without_default)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::identity_op)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::similar_names)]
#![allow(clippy::verbose_bit_mask)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unnecessary_wraps)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// AArch64-specific HAL implementation (QEMU virt, Cortex-A72).
///
/// This module is only compiled when targeting `aarch64`. It contains
/// the EL2 boot stubs, stage-2 page table management, PL011 UART
/// driver, GICv2 interrupt controller, and ARM generic timer.
///
/// `unsafe_code` is allowed here because this is the hardware boundary:
/// register access, MMIO writes, and inline assembly all require it.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
pub mod aarch64;

use rvm_types::{GuestPhysAddr, PhysAddr, RvmResult};

/// Top-level platform discovery and initialization.
pub trait Platform {
    /// Return the number of physical CPUs available.
    fn cpu_count(&self) -> usize;

    /// Return the total physical memory in bytes.
    fn total_memory(&self) -> u64;

    /// Halt the current CPU.
    fn halt(&self) -> !;
}

/// Stage-2 MMU operations for guest physical to host physical translation.
pub trait MmuOps {
    /// Map a guest physical page to a host physical page.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping cannot be established.
    fn map_page(&mut self, guest: GuestPhysAddr, host: PhysAddr) -> RvmResult<()>;

    /// Unmap a guest physical page.
    ///
    /// # Errors
    ///
    /// Returns an error if the page is not currently mapped.
    fn unmap_page(&mut self, guest: GuestPhysAddr) -> RvmResult<()>;

    /// Translate a guest physical address to a host physical address.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not mapped.
    fn translate(&self, guest: GuestPhysAddr) -> RvmResult<PhysAddr>;

    /// Flush TLB entries for the given guest address range.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush operation fails.
    fn flush_tlb(&mut self, guest: GuestPhysAddr, page_count: usize) -> RvmResult<()>;
}

/// Monotonic timer operations for deadline scheduling.
pub trait TimerOps {
    /// Return the current monotonic time in nanoseconds.
    fn now_ns(&self) -> u64;

    /// Set a one-shot timer deadline in nanoseconds from now.
    ///
    /// # Errors
    ///
    /// Returns an error if the deadline cannot be set.
    fn set_deadline_ns(&mut self, ns_from_now: u64) -> RvmResult<()>;

    /// Cancel the current deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if no deadline is currently set.
    fn cancel_deadline(&mut self) -> RvmResult<()>;
}

/// Interrupt controller operations.
pub trait InterruptOps {
    /// Enable the interrupt with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the interrupt ID is invalid.
    fn enable(&mut self, irq: u32) -> RvmResult<()>;

    /// Disable the interrupt with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the interrupt ID is invalid.
    fn disable(&mut self, irq: u32) -> RvmResult<()>;

    /// Acknowledge the interrupt and return its ID, or `None` if spurious.
    fn acknowledge(&mut self) -> Option<u32>;

    /// Signal end-of-interrupt for the given ID.
    fn end_of_interrupt(&mut self, irq: u32);
}
