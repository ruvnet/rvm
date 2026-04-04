//! # RVM Partition Object Model
//!
//! Partition lifecycle, isolation, and coherence domain management for the
//! RVM microhypervisor, as specified in ADR-133.
//!
//! A partition is **not** a VM. It has no emulated hardware, no guest BIOS,
//! and no virtual device model. A partition is a container for:
//!
//! - A scoped capability table
//! - Communication edges to other partitions
//! - Coherence and cut-pressure metrics
//! - CPU affinity and VMID assignment
//!
//! Partitions are the unit of scheduling, isolation, migration, and fault
//! containment. Every lifecycle transition emits a witness record.
//!
//! ## Design Constraints (ADR-132, ADR-133)
//!
//! - Maximum 256 partitions per RVM instance (ARM VMID width)
//! - Partition switch target: < 10 microseconds
//! - Scheduler uses 2-signal priority: `deadline_urgency + cut_pressure_boost`
//! - Coherence engine is optional (DC-1); partition model works without it
//! - Split/merge are novel operations with strict preconditions

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod cap_table;
mod comm_edge;
mod device;
pub mod ipc;
mod lifecycle;
mod manager;
mod merge;
mod ops;
mod partition;
mod split;

pub use cap_table::CapabilityTable;
pub use comm_edge::{CommEdge, CommEdgeId};
pub use device::{ActiveLease, DeviceInfo, DeviceLeaseManager};
pub use ipc::{IpcManager, IpcMessage, MessageQueue};
pub use lifecycle::valid_transition;
pub use manager::PartitionManager;
pub use merge::{merge_preconditions_met, merge_preconditions_full, MergePreconditionError};
pub use ops::{PartitionConfig, PartitionOps, SplitConfig};
pub use partition::{
    CutPressureLocal, Partition, PartitionState, PartitionType, MAX_PARTITIONS,
};
pub use split::scored_region_assignment;

// Re-export commonly used types from rvm-types.
pub use rvm_types::{CoherenceScore, CutPressure, PartitionId, RvmError, RvmResult};
