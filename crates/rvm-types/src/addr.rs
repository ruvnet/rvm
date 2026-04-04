//! Address types for the RVM microhypervisor.
//!
//! Provides strongly-typed wrappers around raw addresses to prevent
//! accidental mixing of physical, virtual, and guest-physical address spaces.

/// A host physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Create a new physical address.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Return the raw address value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check if the address is page-aligned (4 KiB).
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        self.0.trailing_zeros() >= 12
    }

    /// Align the address down to the nearest page boundary.
    #[must_use]
    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !0xFFF)
    }
}

/// A host virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Create a new virtual address.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Return the raw address value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A guest physical address, scoped to a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct GuestPhysAddr(u64);

impl GuestPhysAddr {
    /// Create a new guest physical address.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Return the raw address value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check if the address is page-aligned (4 KiB).
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        self.0.trailing_zeros() >= 12
    }
}
