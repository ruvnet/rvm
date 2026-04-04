//! Region management for guest physical address space (ADR-136, ADR-138).
//!
//! A `RegionManager` maintains a fixed-capacity table of `OwnedRegion` entries,
//! each mapping a contiguous range of guest physical addresses to host physical
//! addresses with associated metadata (tier, permissions, ownership).
//!
//! ## Design Principles
//!
//! - **Move semantics**: Region transfer conceptually moves ownership from one
//!   partition to another. The old entry is invalidated and a new entry is created.
//! - **Bounds checking**: All operations validate that addresses and page counts
//!   do not exceed the region's bounds.
//! - **Overlap detection**: Creating a region that overlaps an existing one in the
//!   same partition is rejected.

use rvm_types::{
    GuestPhysAddr, OwnedRegionId, PartitionId, PhysAddr, RvmError, RvmResult,
};

use crate::tier::Tier;
use crate::{MemoryPermissions, PAGE_SIZE};

/// An owned memory region entry in the region table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedRegion {
    /// Unique region identifier.
    pub id: OwnedRegionId,
    /// Owning partition.
    pub owner: PartitionId,
    /// Guest physical base address (page-aligned).
    pub guest_base: GuestPhysAddr,
    /// Host physical base address (page-aligned).
    pub host_base: PhysAddr,
    /// Number of pages in this region.
    pub page_count: u32,
    /// Current memory tier.
    pub tier: Tier,
    /// Access permissions.
    pub permissions: MemoryPermissions,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl OwnedRegion {
    /// An empty (unoccupied) region slot.
    const EMPTY: Self = Self {
        id: OwnedRegionId::new(0),
        owner: PartitionId::new(0),
        guest_base: GuestPhysAddr::new(0),
        host_base: PhysAddr::new(0),
        page_count: 0,
        tier: Tier::Warm,
        permissions: MemoryPermissions::READ_ONLY,
        occupied: false,
    };

    /// Return the size of this region in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.page_count as u64 * PAGE_SIZE as u64
    }

    /// Return the guest physical end address (exclusive).
    #[must_use]
    pub const fn guest_end(&self) -> u64 {
        self.guest_base.as_u64() + self.size_bytes()
    }

    /// Return the host physical end address (exclusive).
    #[must_use]
    pub const fn host_end(&self) -> u64 {
        self.host_base.as_u64() + self.size_bytes()
    }

    /// Check if a guest physical address falls within this region.
    #[must_use]
    pub const fn contains_guest(&self, addr: GuestPhysAddr) -> bool {
        addr.as_u64() >= self.guest_base.as_u64() && addr.as_u64() < self.guest_end()
    }
}

/// Configuration for creating a new region.
#[derive(Debug, Clone, Copy)]
pub struct RegionConfig {
    /// Unique region identifier.
    pub id: OwnedRegionId,
    /// Owning partition.
    pub owner: PartitionId,
    /// Guest physical base address (must be page-aligned).
    pub guest_base: GuestPhysAddr,
    /// Host physical base address (must be page-aligned).
    pub host_base: PhysAddr,
    /// Number of pages.
    pub page_count: u32,
    /// Initial memory tier.
    pub tier: Tier,
    /// Access permissions.
    pub permissions: MemoryPermissions,
}

/// Guest-to-host address mapping entry.
#[derive(Debug, Clone, Copy)]
pub struct AddressMapping {
    /// Guest physical address.
    pub guest: GuestPhysAddr,
    /// Corresponding host physical address.
    pub host: PhysAddr,
    /// Permissions for this mapping.
    pub permissions: MemoryPermissions,
}

/// Manages a fixed-capacity table of owned memory regions.
///
/// `MAX` is the compile-time upper bound on the number of regions.
pub struct RegionManager<const MAX: usize> {
    /// The region table.
    regions: [OwnedRegion; MAX],
    /// Number of occupied slots.
    count: usize,
    /// Next region ID to assign (monotonically increasing).
    next_id: u64,
}

impl<const MAX: usize> Default for RegionManager<MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX: usize> RegionManager<MAX> {
    /// Create a new empty region manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: [OwnedRegion::EMPTY; MAX],
            count: 0,
            next_id: 1,
        }
    }

    /// Return the number of active regions.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the maximum capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        MAX
    }

    /// Create a new memory region from the given configuration.
    ///
    /// Validates alignment, non-zero page count, and overlap with existing
    /// regions in the same partition.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::AlignmentError`] if addresses are not page-aligned.
    /// Returns [`RvmError::ResourceLimitExceeded`] if page count is zero or
    /// the manager is at capacity.
    /// Returns [`RvmError::MemoryOverlap`] if the region overlaps an existing
    /// region in the same partition.
    pub fn create(&mut self, config: RegionConfig) -> RvmResult<OwnedRegionId> {
        // Validate alignment.
        if !config.guest_base.is_page_aligned() {
            return Err(RvmError::AlignmentError);
        }
        if !config.host_base.is_page_aligned() {
            return Err(RvmError::AlignmentError);
        }
        if config.page_count == 0 {
            return Err(RvmError::ResourceLimitExceeded);
        }

        // Check capacity.
        if self.count >= MAX {
            return Err(RvmError::ResourceLimitExceeded);
        }

        // Combined single-pass: check for overlap AND find the first free slot.
        let new_start = config.guest_base.as_u64();
        let new_end = new_start + u64::from(config.page_count) * PAGE_SIZE as u64;
        let new_host_start = config.host_base.as_u64();
        let new_host_end = new_host_start + u64::from(config.page_count) * PAGE_SIZE as u64;
        let mut first_free_slot: Option<usize> = None;

        for (i, region) in self.regions.iter().enumerate() {
            if !region.occupied {
                if first_free_slot.is_none() {
                    first_free_slot = Some(i);
                }
                continue;
            }
            // Guest overlap check: only within the same partition.
            if region.owner == config.owner {
                let existing_start = region.guest_base.as_u64();
                let existing_end = region.guest_end();
                if new_start < existing_end && existing_start < new_end {
                    return Err(RvmError::MemoryOverlap);
                }
            }
            // Host-physical overlap check: across ALL partitions.
            // Two partitions mapping the same host physical pages would
            // break isolation -- a partition could read/write another's memory.
            let existing_host_start = region.host_base.as_u64();
            let existing_host_end = region.host_end();
            if new_host_start < existing_host_end && existing_host_start < new_host_end {
                return Err(RvmError::MemoryOverlap);
            }
        }

        // Use the free slot found during the overlap scan.
        match first_free_slot {
            Some(idx) => {
                self.regions[idx] = OwnedRegion {
                    id: config.id,
                    owner: config.owner,
                    guest_base: config.guest_base,
                    host_base: config.host_base,
                    page_count: config.page_count,
                    tier: config.tier,
                    permissions: config.permissions,
                    occupied: true,
                };
                self.count += 1;
                Ok(config.id)
            }
            None => Err(RvmError::ResourceLimitExceeded),
        }
    }

    /// Allocate a fresh `OwnedRegionId` and create the region.
    ///
    /// # Errors
    ///
    /// See [`RegionManager::create`] for error conditions.
    pub fn create_auto_id(
        &mut self,
        owner: PartitionId,
        guest_base: GuestPhysAddr,
        host_base: PhysAddr,
        page_count: u32,
        tier: Tier,
        permissions: MemoryPermissions,
    ) -> RvmResult<OwnedRegionId> {
        let id = OwnedRegionId::new(self.next_id);
        self.next_id += 1;
        self.create(RegionConfig {
            id,
            owner,
            guest_base,
            host_base,
            page_count,
            tier,
            permissions,
        })
    }

    /// Destroy a region, freeing its slot.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region does not exist.
    pub fn destroy(&mut self, region_id: OwnedRegionId) -> RvmResult<OwnedRegion> {
        match self.find_slot(region_id) {
            Some(idx) => {
                let region = self.regions[idx];
                self.regions[idx] = OwnedRegion::EMPTY;
                self.count -= 1;
                Ok(region)
            }
            None => Err(RvmError::PartitionNotFound),
        }
    }

    /// Transfer ownership of a region to a new partition.
    ///
    /// This conceptually moves the region: the old owner loses access and
    /// the new owner gains it. The guest-physical mapping remains the same
    /// (the new partition sees the region at the same guest address).
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region does not exist.
    /// Returns [`RvmError::MemoryOverlap`] if the new owner already has a
    /// region at the same guest address range.
    pub fn transfer(
        &mut self,
        region_id: OwnedRegionId,
        new_owner: PartitionId,
    ) -> RvmResult<()> {
        let idx = self
            .find_slot(region_id)
            .ok_or(RvmError::PartitionNotFound)?;

        // Check that the new owner doesn't have an overlapping region.
        let r = &self.regions[idx];
        let xfer_start = r.guest_base.as_u64();
        let xfer_end = r.guest_end();
        for (i, region) in self.regions.iter().enumerate() {
            if i == idx || !region.occupied || region.owner != new_owner {
                continue;
            }
            let existing_start = region.guest_base.as_u64();
            let existing_end = region.guest_end();
            if xfer_start < existing_end && existing_start < xfer_end {
                return Err(RvmError::MemoryOverlap);
            }
        }

        self.regions[idx].owner = new_owner;
        Ok(())
    }

    /// Look up a region by its identifier.
    #[must_use]
    pub fn get(&self, region_id: OwnedRegionId) -> Option<&OwnedRegion> {
        self.find_slot(region_id).map(|idx| &self.regions[idx])
    }

    /// Look up a region by its identifier (mutable).
    pub fn get_mut(&mut self, region_id: OwnedRegionId) -> Option<&mut OwnedRegion> {
        self.find_slot(region_id)
            .map(|idx| &mut self.regions[idx])
    }

    /// Translate a guest physical address to a host physical address
    /// within the given partition.
    #[must_use]
    pub fn translate(
        &self,
        owner: PartitionId,
        guest: GuestPhysAddr,
    ) -> Option<AddressMapping> {
        for region in &self.regions {
            if !region.occupied || region.owner != owner {
                continue;
            }
            if region.contains_guest(guest) {
                let offset = guest.as_u64() - region.guest_base.as_u64();
                return Some(AddressMapping {
                    guest,
                    host: PhysAddr::new(region.host_base.as_u64() + offset),
                    permissions: region.permissions,
                });
            }
        }
        None
    }

    /// Count how many regions are owned by a given partition.
    #[must_use]
    pub fn count_for_partition(&self, owner: PartitionId) -> usize {
        self.regions
            .iter()
            .filter(|r| r.occupied && r.owner == owner)
            .count()
    }

    /// Iterate over the region IDs owned by a given partition.
    /// Writes matching IDs into `out` and returns the count written.
    pub fn regions_for_partition(
        &self,
        owner: PartitionId,
        out: &mut [OwnedRegionId],
    ) -> usize {
        let mut written = 0;
        for region in &self.regions {
            if written >= out.len() {
                break;
            }
            if region.occupied && region.owner == owner {
                out[written] = region.id;
                written += 1;
            }
        }
        written
    }

    // --- Private helpers ---

    /// Find the slot index for a given region ID.
    fn find_slot(&self, region_id: OwnedRegionId) -> Option<usize> {
        self.regions
            .iter()
            .position(|r| r.occupied && r.id == region_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(id: u32) -> PartitionId {
        PartitionId::new(id)
    }

    fn rid(id: u64) -> OwnedRegionId {
        OwnedRegionId::new(id)
    }

    fn gpa(addr: u64) -> GuestPhysAddr {
        GuestPhysAddr::new(addr)
    }

    fn pa(addr: u64) -> PhysAddr {
        PhysAddr::new(addr)
    }

    fn default_config(id: u64, owner: u32, guest: u64, host: u64) -> RegionConfig {
        RegionConfig {
            id: rid(id),
            owner: pid(owner),
            guest_base: gpa(guest),
            host_base: pa(host),
            page_count: 4,
            tier: Tier::Warm,
            permissions: MemoryPermissions::READ_WRITE,
        }
    }

    #[test]
    fn create_and_get() {
        let mut mgr = RegionManager::<8>::new();
        let config = default_config(1, 1, 0x1000, 0x2000_0000);
        let id = mgr.create(config).unwrap();
        assert_eq!(id, rid(1));
        assert_eq!(mgr.count(), 1);

        let region = mgr.get(id).unwrap();
        assert_eq!(region.owner, pid(1));
        assert_eq!(region.guest_base, gpa(0x1000));
        assert_eq!(region.host_base, pa(0x2000_0000));
        assert_eq!(region.page_count, 4);
        assert_eq!(region.tier, Tier::Warm);
    }

    #[test]
    fn create_unaligned_guest_fails() {
        let mut mgr = RegionManager::<8>::new();
        let config = RegionConfig {
            guest_base: gpa(0x1001), // Not page-aligned
            ..default_config(1, 1, 0x1000, 0x2000_0000)
        };
        assert_eq!(mgr.create(config), Err(RvmError::AlignmentError));
    }

    #[test]
    fn create_unaligned_host_fails() {
        let mut mgr = RegionManager::<8>::new();
        let config = RegionConfig {
            host_base: pa(0x2000_0001), // Not page-aligned
            ..default_config(1, 1, 0x1000, 0x2000_0000)
        };
        assert_eq!(mgr.create(config), Err(RvmError::AlignmentError));
    }

    #[test]
    fn create_zero_pages_fails() {
        let mut mgr = RegionManager::<8>::new();
        let config = RegionConfig {
            page_count: 0,
            ..default_config(1, 1, 0x1000, 0x2000_0000)
        };
        assert_eq!(mgr.create(config), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn create_at_capacity_fails() {
        let mut mgr = RegionManager::<2>::new();
        mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        mgr.create(default_config(2, 2, 0x1000, 0x2_0000)).unwrap();
        assert_eq!(
            mgr.create(default_config(3, 3, 0x1000, 0x3_0000)),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn overlap_same_partition_fails() {
        let mut mgr = RegionManager::<8>::new();
        // Region 1: pages at guest 0x1000..0x5000 (4 pages).
        mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        // Region 2: pages at guest 0x3000..0x7000 -- overlaps.
        assert_eq!(
            mgr.create(default_config(2, 1, 0x3000, 0x2_0000)),
            Err(RvmError::MemoryOverlap)
        );
    }

    #[test]
    fn no_overlap_different_partitions() {
        let mut mgr = RegionManager::<8>::new();
        // Same guest range but different owners AND different host ranges -- no overlap.
        mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        mgr.create(default_config(2, 2, 0x1000, 0x2_0000)).unwrap();
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn host_overlap_cross_partition_rejected() {
        let mut mgr = RegionManager::<8>::new();
        // Different owners but SAME host physical range -- must be rejected.
        mgr.create(default_config(1, 1, 0x1000, 0x10_0000)).unwrap();
        assert_eq!(
            mgr.create(default_config(2, 2, 0x5000, 0x10_0000)),
            Err(RvmError::MemoryOverlap)
        );
    }

    #[test]
    fn destroy_region() {
        let mut mgr = RegionManager::<8>::new();
        let id = mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        let destroyed = mgr.destroy(id).unwrap();
        assert_eq!(destroyed.id, rid(1));
        assert_eq!(mgr.count(), 0);
        assert!(mgr.get(id).is_none());
    }

    #[test]
    fn destroy_nonexistent_fails() {
        let mut mgr = RegionManager::<8>::new();
        assert_eq!(mgr.destroy(rid(99)), Err(RvmError::PartitionNotFound));
    }

    #[test]
    fn transfer_ownership() {
        let mut mgr = RegionManager::<8>::new();
        let id = mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        assert_eq!(mgr.get(id).unwrap().owner, pid(1));

        mgr.transfer(id, pid(2)).unwrap();
        assert_eq!(mgr.get(id).unwrap().owner, pid(2));
    }

    #[test]
    fn transfer_overlap_fails() {
        let mut mgr = RegionManager::<8>::new();
        let id = mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        // Partition 2 already has a region at the same guest range.
        mgr.create(default_config(2, 2, 0x1000, 0x2_0000)).unwrap();
        assert_eq!(mgr.transfer(id, pid(2)), Err(RvmError::MemoryOverlap));
    }

    #[test]
    fn translate_guest_to_host() {
        let mut mgr = RegionManager::<8>::new();
        // Region at guest 0x1000, host 0x2000_0000, 4 pages (16 KiB).
        mgr.create(default_config(1, 1, 0x1000, 0x2000_0000)).unwrap();

        // Translate guest 0x1000 (start of region).
        let m = mgr.translate(pid(1), gpa(0x1000)).unwrap();
        assert_eq!(m.host, pa(0x2000_0000));

        // Translate guest 0x2000 (offset 0x1000 into region).
        let m = mgr.translate(pid(1), gpa(0x2000)).unwrap();
        assert_eq!(m.host, pa(0x2000_1000));

        // Translate guest 0x5000 (past end of region) -- should return None.
        assert!(mgr.translate(pid(1), gpa(0x5000)).is_none());

        // Translate in wrong partition -- should return None.
        assert!(mgr.translate(pid(2), gpa(0x1000)).is_none());
    }

    #[test]
    fn region_contains_guest() {
        let region = OwnedRegion {
            id: rid(1),
            owner: pid(1),
            guest_base: gpa(0x1000),
            host_base: pa(0x2000_0000),
            page_count: 4,
            tier: Tier::Warm,
            permissions: MemoryPermissions::READ_WRITE,
            occupied: true,
        };
        // 4 pages = 0x4000 bytes. Range: [0x1000, 0x5000).
        assert!(region.contains_guest(gpa(0x1000)));
        assert!(region.contains_guest(gpa(0x4FFF)));
        assert!(!region.contains_guest(gpa(0x5000)));
        assert!(!region.contains_guest(gpa(0x0FFF)));
    }

    #[test]
    fn create_auto_id() {
        let mut mgr = RegionManager::<8>::new();
        let id1 = mgr
            .create_auto_id(
                pid(1), gpa(0x1000), pa(0x1_0000), 4,
                Tier::Warm, MemoryPermissions::READ_WRITE,
            )
            .unwrap();
        let id2 = mgr
            .create_auto_id(
                pid(1), gpa(0x5000), pa(0x2_0000), 2,
                Tier::Hot, MemoryPermissions::READ_ONLY,
            )
            .unwrap();
        assert_ne!(id1, id2);
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn count_for_partition() {
        let mut mgr = RegionManager::<8>::new();
        mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        mgr.create(default_config(2, 1, 0x5000, 0x2_0000)).unwrap();
        mgr.create(default_config(3, 2, 0x1000, 0x3_0000)).unwrap();

        assert_eq!(mgr.count_for_partition(pid(1)), 2);
        assert_eq!(mgr.count_for_partition(pid(2)), 1);
        assert_eq!(mgr.count_for_partition(pid(3)), 0);
    }

    #[test]
    fn regions_for_partition() {
        let mut mgr = RegionManager::<8>::new();
        mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        mgr.create(default_config(2, 1, 0x5000, 0x2_0000)).unwrap();
        mgr.create(default_config(3, 2, 0x1000, 0x3_0000)).unwrap();

        let mut buf = [OwnedRegionId::new(0); 4];
        let n = mgr.regions_for_partition(pid(1), &mut buf);
        assert_eq!(n, 2);
        assert!(buf[..n].contains(&rid(1)));
        assert!(buf[..n].contains(&rid(2)));
    }

    #[test]
    fn destroy_then_create_reuses_slot() {
        let mut mgr = RegionManager::<2>::new();
        let id1 = mgr.create(default_config(1, 1, 0x1000, 0x1_0000)).unwrap();
        mgr.create(default_config(2, 2, 0x1000, 0x2_0000)).unwrap();
        // At capacity.
        assert!(mgr.create(default_config(3, 3, 0x1000, 0x3_0000)).is_err());

        // Destroy first, then create should succeed.
        mgr.destroy(id1).unwrap();
        mgr.create(default_config(3, 3, 0x1000, 0x3_0000)).unwrap();
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn size_bytes_and_ends() {
        let region = OwnedRegion {
            id: rid(1),
            owner: pid(1),
            guest_base: gpa(0x1000),
            host_base: pa(0x2000_0000),
            page_count: 4,
            tier: Tier::Warm,
            permissions: MemoryPermissions::READ_WRITE,
            occupied: true,
        };
        assert_eq!(region.size_bytes(), 4 * PAGE_SIZE as u64);
        assert_eq!(region.guest_end(), 0x1000 + 4 * PAGE_SIZE as u64);
        assert_eq!(region.host_end(), 0x2000_0000 + 4 * PAGE_SIZE as u64);
    }
}
