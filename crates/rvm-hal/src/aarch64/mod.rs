//! AArch64-specific HAL implementation for the RVM microhypervisor.
//!
//! This module provides bare-metal support for QEMU virt (AArch64):
//! - EL2 boot assembly stubs
//! - Stage-2 page table management
//! - PL011 UART driver
//! - GICv2 interrupt controller
//! - ARM generic timer
//!
//! This is the ONE crate in RVM where `unsafe` is permitted, because it
//! forms the hardware boundary. Every `unsafe` block has a `// SAFETY:`
//! comment documenting the invariant.

pub mod boot;
pub mod interrupts;
pub mod mmu;
pub mod timer;
pub mod uart;
