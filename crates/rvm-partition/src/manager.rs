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
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionLimitExceeded`] if the maximum is reached.
    /// Returns [`RvmError::InternalError`] if no free slot is found.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::PartitionState;

    #[test]
    fn test_new_manager_empty() {
        let mgr = PartitionManager::new();
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_default_equals_new() {
        let a = PartitionManager::new();
        let b = PartitionManager::default();
        assert_eq!(a.count(), b.count());
    }

    #[test]
    fn test_create_returns_unique_ids() {
        let mut mgr = PartitionManager::new();
        let id1 = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        let id2 = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        let id3 = mgr.create(PartitionType::Infrastructure, 2, 1).unwrap();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_create_increments_count() {
        let mut mgr = PartitionManager::new();
        for expected in 1..=5 {
            mgr.create(PartitionType::Agent, 1, 0).unwrap();
            assert_eq!(mgr.count(), expected);
        }
    }

    #[test]
    fn test_get_existing() {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Root, 4, 0).unwrap();
        let p = mgr.get(id).unwrap();
        assert_eq!(p.id, id);
        assert_eq!(p.partition_type, PartitionType::Root);
        assert_eq!(p.vcpu_count, 4);
        assert_eq!(p.state, PartitionState::Created);
    }

    #[test]
    fn test_get_nonexistent() {
        let mgr = PartitionManager::new();
        assert!(mgr.get(PartitionId::new(999)).is_none());
    }

    #[test]
    fn test_first_id_is_not_zero() {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        // next_id starts at 1, so hypervisor id (0) is never assigned.
        assert_ne!(id, PartitionId::HYPERVISOR);
        assert_eq!(id, PartitionId::new(1));
    }

    #[test]
    fn test_create_at_max_partitions_capacity() {
        let mut mgr = PartitionManager::new();
        // Fill the manager to MAX_PARTITIONS.
        for _ in 0..MAX_PARTITIONS {
            mgr.create(PartitionType::Agent, 1, 0).unwrap();
        }
        assert_eq!(mgr.count(), MAX_PARTITIONS);

        // Next creation should fail.
        let result = mgr.create(PartitionType::Agent, 1, 0);
        assert_eq!(result, Err(RvmError::PartitionLimitExceeded));
    }

    #[test]
    fn test_partition_preserves_epoch() {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Agent, 1, 42).unwrap();
        let p = mgr.get(id).unwrap();
        assert_eq!(p.epoch, 42);
    }

    #[test]
    fn test_partition_initial_coherence() {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        let p = mgr.get(id).unwrap();
        // Default coherence is 5000 basis points.
        assert_eq!(p.coherence.as_basis_points(), 5000);
    }

    #[test]
    fn test_partition_initial_cpu_affinity() {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        let p = mgr.get(id).unwrap();
        assert_eq!(p.cpu_affinity, u64::MAX);
    }
}
