//! # RVM Coherence-Aware Scheduler
//!
//! A 2-signal scheduler for the RVM microhypervisor, as specified in
//! ADR-132 DC-4. The scheduler combines deadline urgency and cut-pressure
//! boost into a single priority signal:
//!
//! ```text
//! priority = deadline_urgency + cut_pressure_boost
//! ```
//!
//! Novelty scoring and structural risk are deferred to post-v1.
//!
//! ## Scheduling Modes (ADR-132)
//!
//! - **Reflex**: Hard real-time. Bounded local execution only. No cross-partition traffic.
//! - **Flow**: Normal execution with coherence-aware placement.
//! - **Recovery**: Stabilization mode. Replay, rollback, split.
//!
//! ## Design Constraints
//!
//! - Partition switch is the HOT PATH: no allocation, no graph work, no policy.
//! - Switches are NOT individually witnessed (DC-10); epoch summaries instead.
//! - Coherence engine is optional (DC-1/DC-6): degraded mode uses deadline only.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod degraded;
mod epoch;
mod modes;
mod per_cpu;
mod priority;
mod scheduler;

pub use degraded::{DegradedReason, DegradedState};
pub use epoch::{EpochSummary, EpochTracker};
pub use modes::SchedulerMode;
pub use per_cpu::PerCpuScheduler;
pub use priority::compute_priority;
pub use scheduler::Scheduler;

// Re-export commonly used types.
pub use rvm_types::{CoherenceScore, CutPressure, PartitionId, RvmError, RvmResult};
