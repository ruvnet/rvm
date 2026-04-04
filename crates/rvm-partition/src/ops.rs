//! Partition operations trait and configuration.

use rvm_types::{CoherenceScore, PartitionId, RvmResult};

/// Configuration for creating a new partition.
#[derive(Debug, Clone, Copy)]
pub struct PartitionConfig {
    /// Number of vCPUs to allocate.
    pub vcpu_count: u16,
    /// Initial coherence score.
    pub initial_coherence: CoherenceScore,
    /// CPU affinity mask.
    pub cpu_affinity: u64,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            initial_coherence: CoherenceScore::from_basis_points(5000),
            cpu_affinity: u64::MAX,
        }
    }
}

/// Configuration for splitting a partition.
#[derive(Debug, Clone, Copy)]
pub struct SplitConfig {
    /// Minimum coherence required for split to proceed.
    pub min_coherence: CoherenceScore,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self {
            min_coherence: CoherenceScore::DEFAULT_THRESHOLD,
        }
    }
}

/// Trait defining partition operations.
pub trait PartitionOps {
    /// Create a new partition with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the partition cannot be created.
    fn create_partition(&mut self, config: PartitionConfig) -> RvmResult<PartitionId>;

    /// Destroy a partition and reclaim its resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the partition is not found or cannot be destroyed.
    fn destroy_partition(&mut self, id: PartitionId) -> RvmResult<()>;

    /// Suspend a running partition.
    ///
    /// # Errors
    ///
    /// Returns an error if the partition is not in a suspendable state.
    fn suspend_partition(&mut self, id: PartitionId) -> RvmResult<()>;

    /// Resume a suspended partition.
    ///
    /// # Errors
    ///
    /// Returns an error if the partition is not suspended.
    fn resume_partition(&mut self, id: PartitionId) -> RvmResult<()>;
}
