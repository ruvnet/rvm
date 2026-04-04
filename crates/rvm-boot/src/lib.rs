//! # RVM Boot Sequence
//!
//! Deterministic, phased boot sequence for the RVM microhypervisor,
//! as specified in ADR-137 and ADR-140. Each phase is gated by a
//! witness entry and must complete before the next phase begins.
//!
//! ## Boot Phases (ADR-137: 7-phase deterministic boot)
//!
//! ```text
//! Phase 0: Reset vector (initial entry from firmware)
//! Phase 1: Hardware detect (enumerate CPUs, memory, devices)
//! Phase 2: MMU setup (stage-2 page tables)
//! Phase 3: Hypervisor mode (enter EL2)
//! Phase 4: Kernel object init (cap table, IPC, etc.)
//! Phase 5: First witness (genesis attestation)
//! Phase 6: Scheduler entry (hand-off to scheduler loop)
//! ```
//!
//! ## Legacy Boot Phases (ADR-140)
//!
//! ```text
//! Phase 0: HAL init (timer, MMU, interrupts)
//! Phase 1: Memory pool init (physical page allocator)
//! Phase 2: Capability table init
//! Phase 3: Witness trail init
//! Phase 4: Scheduler init
//! Phase 5: Root partition creation
//! Phase 6: Hand-off to root partition
//! ```
//!
//! ## Modules
//!
//! - [`sequence`] -- 7-phase boot sequence manager (ADR-137)
//! - [`measured`] -- Measured boot hash-chain accumulation
//! - [`hal_init`] -- HAL initialization trait stubs

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::new_without_default
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod entry;
pub mod hal_init;
pub mod measured;
pub mod sequence;

use rvm_types::{RvmError, RvmResult};

// Re-export key types for convenience.
pub use entry::{BootContext, run_boot_sequence};
pub use hal_init::{HalInit, InterruptConfig, MmuConfig, StubHal, UartConfig};
pub use measured::MeasuredBootState;
pub use sequence::{BootSequence, BootStage, PhaseTiming};

/// Boot phases executed in order during RVM initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BootPhase {
    /// Phase 0: Hardware abstraction layer initialization.
    HalInit = 0,
    /// Phase 1: Physical memory pool initialization.
    MemoryInit = 1,
    /// Phase 2: Capability table initialization.
    CapabilityInit = 2,
    /// Phase 3: Witness trail initialization.
    WitnessInit = 3,
    /// Phase 4: Scheduler initialization.
    SchedulerInit = 4,
    /// Phase 5: Root partition creation.
    RootPartition = 5,
    /// Phase 6: Hand-off to the root partition.
    Handoff = 6,
}

impl BootPhase {
    /// Return the next phase, or `None` if this is the last phase.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::HalInit => Some(Self::MemoryInit),
            Self::MemoryInit => Some(Self::CapabilityInit),
            Self::CapabilityInit => Some(Self::WitnessInit),
            Self::WitnessInit => Some(Self::SchedulerInit),
            Self::SchedulerInit => Some(Self::RootPartition),
            Self::RootPartition => Some(Self::Handoff),
            Self::Handoff => None,
        }
    }

    /// Return the human-readable name of this phase.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HalInit => "HAL init",
            Self::MemoryInit => "memory init",
            Self::CapabilityInit => "capability init",
            Self::WitnessInit => "witness init",
            Self::SchedulerInit => "scheduler init",
            Self::RootPartition => "root partition",
            Self::Handoff => "handoff",
        }
    }
}

/// Track boot progress through the phased initialization.
#[derive(Debug)]
pub struct BootTracker {
    current: Option<BootPhase>,
    completed: [bool; 7],
}

impl BootTracker {
    /// Create a new boot tracker at the beginning of the sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current: Some(BootPhase::HalInit),
            completed: [false; 7],
        }
    }

    /// Return the current phase, or `None` if boot is complete.
    #[must_use]
    pub const fn current_phase(&self) -> Option<BootPhase> {
        self.current
    }

    /// Mark the current phase as complete and advance.
    ///
    /// Returns the completed phase on success, or an error if boot
    /// is already complete or phases are executed out of order.
    pub fn complete_phase(&mut self, phase: BootPhase) -> RvmResult<BootPhase> {
        match self.current {
            Some(current) if current as u8 == phase as u8 => {
                self.completed[phase as usize] = true;
                self.current = phase.next();
                Ok(phase)
            }
            Some(_) => Err(RvmError::InternalError),
            None => Err(RvmError::Unsupported),
        }
    }

    /// Check whether all boot phases have completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.current.is_none() && self.completed.iter().all(|&c| c)
    }

    /// Check whether a specific phase has been completed.
    #[must_use]
    pub fn phase_completed(&self, phase: BootPhase) -> bool {
        self.completed[phase as usize]
    }
}
