//! Memory region types.

use crate::{GuestPhysAddr, PhysAddr, PartitionId};

/// Unique identifier for an owned memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct OwnedRegionId(u64);

impl OwnedRegionId {
    /// Create a new region identifier.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw identifier value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Memory tier classification (hot/warm/cold).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MemoryTier {
    /// Hot tier: SRAM or L1/L2 cache-resident.
    Hot = 0,
    /// Warm tier: DRAM.
    Warm = 1,
    /// Cold tier: persistent or swap-backed.
    Cold = 2,
}

/// Access policy for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionPolicy {
    /// Allow read access.
    pub read: bool,
    /// Allow write access.
    pub write: bool,
    /// Allow execute access.
    pub execute: bool,
}

impl RegionPolicy {
    /// Read-only policy.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read-write policy.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
}

/// Placement weights for region assignment during split.
#[derive(Debug, Clone, Copy)]
pub struct RegionPlacementWeights {
    /// Weight toward left partition.
    pub left: u16,
    /// Weight toward right partition.
    pub right: u16,
}

/// A typed, tiered, owned memory region.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Region identifier.
    pub id: OwnedRegionId,
    /// Owning partition.
    pub owner: PartitionId,
    /// Guest physical base address.
    pub guest_base: GuestPhysAddr,
    /// Host physical base address.
    pub host_base: PhysAddr,
    /// Number of pages.
    pub page_count: u32,
    /// Memory tier.
    pub tier: MemoryTier,
    /// Access policy.
    pub policy: RegionPolicy,
}
