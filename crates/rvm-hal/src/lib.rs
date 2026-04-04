//! # RVM Hardware Abstraction Layer
//!
//! Platform-agnostic traits for the RVM microhypervisor, as specified in
//! ADR-133. Concrete implementations are provided per target (AArch64,
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
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

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
    fn map_page(&mut self, guest: GuestPhysAddr, host: PhysAddr) -> RvmResult<()>;

    /// Unmap a guest physical page.
    fn unmap_page(&mut self, guest: GuestPhysAddr) -> RvmResult<()>;

    /// Translate a guest physical address to a host physical address.
    fn translate(&self, guest: GuestPhysAddr) -> RvmResult<PhysAddr>;

    /// Flush TLB entries for the given guest address range.
    fn flush_tlb(&mut self, guest: GuestPhysAddr, page_count: usize) -> RvmResult<()>;
}

/// Monotonic timer operations for deadline scheduling.
pub trait TimerOps {
    /// Return the current monotonic time in nanoseconds.
    fn now_ns(&self) -> u64;

    /// Set a one-shot timer deadline in nanoseconds from now.
    fn set_deadline_ns(&mut self, ns_from_now: u64) -> RvmResult<()>;

    /// Cancel the current deadline.
    fn cancel_deadline(&mut self) -> RvmResult<()>;
}

/// Interrupt controller operations.
pub trait InterruptOps {
    /// Enable the interrupt with the given ID.
    fn enable(&mut self, irq: u32) -> RvmResult<()>;

    /// Disable the interrupt with the given ID.
    fn disable(&mut self, irq: u32) -> RvmResult<()>;

    /// Acknowledge the interrupt and return its ID, or `None` if spurious.
    fn acknowledge(&mut self) -> Option<u32>;

    /// Signal end-of-interrupt for the given ID.
    fn end_of_interrupt(&mut self, irq: u32);
}
