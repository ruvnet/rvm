//! Partition manager: creates, destroys, and tracks partitions.

use crate::partition::{Partition, PartitionType, MAX_PARTITIONS};
use rvm_types::{PartitionId, RvmError, RvmResult};

/// Maximum partition ID supported by the direct lookup index.
const ID_INDEX_SIZE: usize = 4096;

/// Manages the set of active partitions.
#[derive(Debug)]
pub struct PartitionManager {
    partitions: [Option<Partition>; MAX_PARTITIONS],
    /// Direct lookup index: maps `PartitionId` value to slot index.
    /// Enables O(1) lookup instead of O(N) linear scan.
    id_to_slot: [Option<u8>; ID_INDEX_SIZE],
    count: usize,
    next_id: u32,
}

impl PartitionManager {
    /// Create an empty partition manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            partitions: [None; MAX_PARTITIONS],
            id_to_slot: [None; ID_INDEX_SIZE],
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
        for (i, slot) in self.partitions.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(partition);
                self.count += 1;
                self.next_id += 1;
                // Populate direct lookup index.
                let id_val = id.as_u32() as usize;
                if id_val < ID_INDEX_SIZE {
                    self.id_to_slot[id_val] = Some(i as u8);
                }
                return Ok(id);
            }
        }
        Err(RvmError::InternalError)
    }

    /// Look up a partition by ID (O(1) via direct index).
    #[must_use]
    pub fn get(&self, id: PartitionId) -> Option<&Partition> {
        let id_val = id.as_u32() as usize;
        if id_val < ID_INDEX_SIZE {
            if let Some(slot_idx) = self.id_to_slot[id_val] {
                if let Some(ref p) = self.partitions[slot_idx as usize] {
                    if p.id == id {
                        return Some(p);
                    }
                }
            }
        }
        // Fallback: linear scan for IDs beyond index range.
        self.partitions
            .iter()
            .filter_map(|p| p.as_ref())
            .find(|p| p.id == id)
    }

    /// Mutable look-up of a partition by ID (O(1) via direct index).
    pub fn get_mut(&mut self, id: PartitionId) -> Option<&mut Partition> {
        let id_val = id.as_u32() as usize;
        if id_val < ID_INDEX_SIZE {
            if let Some(slot_idx) = self.id_to_slot[id_val] {
                if self.partitions[slot_idx as usize]
                    .as_ref()
                    .is_some_and(|p| p.id == id)
                {
                    return self.partitions[slot_idx as usize].as_mut();
                }
            }
        }
        // Fallback: linear scan for IDs beyond index range.
        self.partitions
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.id == id)
    }

    /// Iterate over all active partition IDs.
    pub fn active_ids(&self) -> impl Iterator<Item = PartitionId> + '_ {
        self.partitions
            .iter()
            .filter_map(|p| p.as_ref().map(|p| p.id))
    }

    /// Remove a partition by ID, freeing its slot for reuse.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if no partition with the given ID exists.
    pub fn remove(&mut self, id: PartitionId) -> RvmResult<()> {
        for slot in &mut self.partitions {
            let matches = slot.as_ref().is_some_and(|p| p.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                // Clear direct lookup index.
                let id_val = id.as_u32() as usize;
                if id_val < ID_INDEX_SIZE {
                    self.id_to_slot[id_val] = None;
                }
                return Ok(());
            }
        }
        Err(RvmError::PartitionNotFound)
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
