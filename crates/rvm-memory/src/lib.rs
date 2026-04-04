//! # RVM Memory Manager
//!
//! Guest physical address space management for the RVM microhypervisor,
//! as specified in ADR-138. Provides a safe abstraction over stage-2
//! page table mappings with capability-gated access.
//!
//! ## Memory Model
//!
//! - Each partition has an independent guest physical address space
//! - Mappings are created via capability-checked hypercalls
//! - All mapping operations are recorded in the witness trail
//! - Memory regions can be shared between partitions with explicit grants

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

/// A memory region descriptor.
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
#[must_use]
pub fn regions_overlap(a: &MemoryRegion, b: &MemoryRegion) -> bool {
    if a.owner != b.owner {
        return false; // Different partitions cannot overlap.
    }
    let a_start = a.guest_base.as_u64();
    let a_end = a_start + (a.page_count as u64 * PAGE_SIZE as u64);
    let b_start = b.guest_base.as_u64();
    let b_end = b_start + (b.page_count as u64 * PAGE_SIZE as u64);

    a_start < b_end && b_start < a_end
}
