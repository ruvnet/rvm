//! Partition configuration types (shared across crates).

use crate::CoherenceScore;

/// Maximum partitions per RVM instance.
pub const MAX_PARTITIONS: usize = 256;

/// Maximum communication edges per partition.
pub const MAX_EDGES_PER_PARTITION: usize = 64;

/// Maximum device leases per partition.
pub const MAX_DEVICES_PER_PARTITION: usize = 16;

/// Partition lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionState {
    /// Created but not yet running.
    Created,
    /// Actively running.
    Running,
    /// Suspended (all vCPUs paused).
    Suspended,
    /// Destroyed and resources reclaimed.
    Destroyed,
    /// Hibernated to cold storage.
    Hibernated,
}

/// Partition type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    /// Normal agent workload.
    Agent,
    /// Infrastructure (driver domain, service partition).
    Infrastructure,
    /// Root partition (bootstrap authority).
    Root,
}

/// Partition creation configuration.
#[derive(Debug, Clone, Copy)]
pub struct PartitionConfig {
    /// Number of vCPUs.
    pub vcpu_count: u16,
    /// Initial coherence score.
    pub initial_coherence: CoherenceScore,
    /// CPU affinity bitmask.
    pub cpu_affinity: u64,
    /// Partition type.
    pub partition_type: PartitionType,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            initial_coherence: CoherenceScore::from_basis_points(5000),
            cpu_affinity: u64::MAX,
            partition_type: PartitionType::Agent,
        }
    }
}
