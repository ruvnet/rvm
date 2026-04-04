//! # RVM Memory Manager
//!
//! Guest physical address space management for the RVM microhypervisor,
//! as specified in ADR-136 and ADR-138. Provides a safe abstraction over
//! four-tier coherence-driven memory with reconstruction capability.
//!
//! ## Four-Tier Memory Model (ADR-136)
//!
//! | Tier | Name | Description |
//! |------|------|-------------|
//! | 0 | Hot | Per-core SRAM / L1-adjacent; always resident during execution |
//! | 1 | Warm | Shared DRAM; resident if residency rule is met |
//! | 2 | Dormant | Compressed checkpoint + delta; reconstructed on demand |
//! | 3 | Cold | Persistent archival; accessed only during recovery |
//!
//! ## Key Components
//!
//! - [`tier::TierManager`] -- Coherence-driven tier placement and transitions
//! - [`allocator::BuddyAllocator`] -- Power-of-two physical page allocator
//! - [`region::RegionManager`] -- Owned region lifecycle and address translation
//! - [`reconstruction::ReconstructionPipeline`] -- Dormant state restoration
//!
//! ## Design Constraints
//!
//! - `#![no_std]` with zero heap allocation
//! - `#![forbid(unsafe_code)]`
//! - Works without the coherence engine (DC-1 static fallback thresholds)
//! - All tier transitions are explicit, not demand-paged

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use rvm_types::{GuestPhysAddr, PartitionId, PhysAddr, RvmError, RvmResult};

pub mod allocator;
pub mod reconstruction;
pub mod region;
pub mod tier;

// Re-export key types at crate root for convenience.
pub use allocator::BuddyAllocator;
pub use reconstruction::{
    CheckpointId, CompressedCheckpoint, ReconstructionPipeline, ReconstructionResult,
    WitnessDelta, create_checkpoint,
};
pub use region::{AddressMapping, OwnedRegion, RegionConfig, RegionManager};
pub use tier::{RegionTierState, Tier, TierManager, TierThresholds};

/// Page size in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Access permissions for a memory mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPermissions {
    /// Allow read access.
    pub read: bool,
    /// Allow write access.
    pub write: bool,
    /// Allow execute access.
    pub execute: bool,
}

impl MemoryPermissions {
    /// Read-only permissions.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read-write permissions.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// Read-execute permissions.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

/// A legacy memory region descriptor (ADR-138 compatibility).
///
/// For new code, prefer [`region::OwnedRegion`] which includes tier metadata.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Guest physical base address (must be page-aligned).
    pub guest_base: GuestPhysAddr,
    /// Host physical base address (must be page-aligned).
    pub host_base: PhysAddr,
    /// Number of pages in this region.
    pub page_count: usize,
    /// Access permissions.
    pub permissions: MemoryPermissions,
    /// The partition that owns this region.
    pub owner: PartitionId,
}

/// Validate that a memory region descriptor is well-formed.
///
/// # Errors
///
/// Returns [`RvmError::AlignmentError`] if addresses are not page-aligned.
/// Returns [`RvmError::ResourceLimitExceeded`] if the page count is zero.
/// Returns [`RvmError::Unsupported`] if no permission bits are set.
pub fn validate_region(region: &MemoryRegion) -> RvmResult<()> {
    if !region.guest_base.is_page_aligned() {
        return Err(RvmError::AlignmentError);
    }
    if !region.host_base.is_page_aligned() {
        return Err(RvmError::AlignmentError);
    }
    if region.page_count == 0 {
        return Err(RvmError::ResourceLimitExceeded);
    }
    if !region.permissions.read && !region.permissions.write && !region.permissions.execute {
        return Err(RvmError::Unsupported);
    }
    Ok(())
}

/// Check whether two memory regions overlap in guest physical space.
///
/// Guest-physical overlap is only meaningful within the same partition
/// (each partition has its own stage-2 page table). However, host-physical
/// overlap across partitions would break isolation, so callers should also
/// check `regions_overlap_host` for cross-partition safety.
#[must_use]
pub fn regions_overlap(a: &MemoryRegion, b: &MemoryRegion) -> bool {
    if a.owner != b.owner {
        return false; // Different partitions have separate guest address spaces.
    }
    let a_start = a.guest_base.as_u64();
    let a_end = a_start + (a.page_count as u64 * PAGE_SIZE as u64);
    let b_start = b.guest_base.as_u64();
    let b_end = b_start + (b.page_count as u64 * PAGE_SIZE as u64);

    a_start < b_end && b_start < a_end
}

/// Check whether two memory regions overlap in host physical space.
///
/// This is a critical isolation check: two partitions must NEVER map
/// the same host physical pages unless explicitly sharing via a
/// controlled mechanism (e.g., `RegionShare` with read-only attenuation).
#[must_use]
pub fn regions_overlap_host(a: &MemoryRegion, b: &MemoryRegion) -> bool {
    let a_start = a.host_base.as_u64();
    let a_end = a_start + (a.page_count as u64 * PAGE_SIZE as u64);
    let b_start = b.host_base.as_u64();
    let b_end = b_start + (b.page_count as u64 * PAGE_SIZE as u64);

    a_start < b_end && b_start < a_end
}
