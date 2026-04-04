//! Partition manager: creates, destroys, and tracks partitions.

use crate::partition::{Partition, PartitionType, MAX_PARTITIONS};
use rvm_types::{PartitionId, RvmError, RvmResult};

/// Manages the set of active partitions.
#[derive(Debug)]
pub struct PartitionManager {
    partitions: [Option<Partition>; MAX_PARTITIONS],
    count: usize,
    next_id: u32,
}

impl PartitionManager {
    /// Create an empty partition manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            partitions: [None; MAX_PARTITIONS],
            count: 0,
            next_id: 1, // 0 is reserved for hypervisor
        }
    }

    /// Create a new partition and return its identifier.
    pub fn create(
        &mut self,
        partition_type: PartitionType,
        vcpu_count: u16,
        epoch: u32,
    ) -> RvmResult<PartitionId> {
        if self.count >= MAX_PARTITIONS {
            return Err(RvmError::PartitionLimitExceeded);
        }
        let id = PartitionId::new(self.next_id);
        let partition = Partition::new(id, partition_type, vcpu_count, epoch);
        for slot in &mut self.partitions {
            if slot.is_none() {
                *slot = Some(partition);
                self.count += 1;
                self.next_id += 1;
                return Ok(id);
            }
        }
        Err(RvmError::InternalError)
    }

    /// Look up a partition by ID.
    #[must_use]
    pub fn get(&self, id: PartitionId) -> Option<&Partition> {
        self.partitions
            .iter()
            .filter_map(|p| p.as_ref())
            .find(|p| p.id == id)
    }

    /// Return the number of active partitions.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for PartitionManager {
    fn default() -> Self {
        Self::new()
    }
}
