//! Core partition data structure and constants.

use rvm_types::{CoherenceScore, CutPressure, PartitionId};

/// Maximum number of partitions per RVM instance (ARM VMID width).
pub const MAX_PARTITIONS: usize = 256;

/// The lifecycle state of a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionState {
    /// The partition has been created but not yet started.
    Created,
    /// The partition is actively running.
    Running,
    /// The partition is suspended (all vCPUs paused).
    Suspended,
    /// The partition has been destroyed and resources reclaimed.
    Destroyed,
    /// The partition is hibernated in cold storage.
    Hibernated,
}

/// The type of partition (agent vs infrastructure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    /// A normal agent workload partition.
    Agent,
    /// An infrastructure partition (e.g., driver domain).
    Infrastructure,
    /// The root partition (bootstrap authority).
    Root,
}

/// Cut pressure for a partition (graph-derived isolation signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CutPressureLocal {
    /// The raw pressure value.
    pub pressure: CutPressure,
    /// Epoch at which this pressure was computed.
    pub epoch: u32,
}

/// Core partition structure.
#[derive(Debug, Clone, Copy)]
pub struct Partition {
    /// Unique partition identifier.
    pub id: PartitionId,
    /// Current lifecycle state.
    pub state: PartitionState,
    /// Partition type.
    pub partition_type: PartitionType,
    /// Current coherence score.
    pub coherence: CoherenceScore,
    /// Current cut pressure.
    pub cut_pressure: CutPressure,
    /// Number of vCPUs allocated.
    pub vcpu_count: u16,
    /// CPU affinity mask (bitmask of allowed physical CPUs).
    pub cpu_affinity: u64,
    /// Creation epoch.
    pub epoch: u32,
}

impl Partition {
    /// Create a new partition with the given configuration.
    #[must_use]
    pub const fn new(
        id: PartitionId,
        partition_type: PartitionType,
        vcpu_count: u16,
        epoch: u32,
    ) -> Self {
        Self {
            id,
            state: PartitionState::Created,
            partition_type,
            coherence: CoherenceScore::from_basis_points(5000),
            cut_pressure: CutPressure::ZERO,
            vcpu_count,
            cpu_affinity: u64::MAX, // All CPUs by default
            epoch,
        }
    }
}
