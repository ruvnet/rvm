//! Identifier types for partitions, vCPUs, and other RVM entities.
//!
//! Strongly-typed newtypes prevent accidental mixing of identifiers
//! across different kernel object domains. All identifiers are `Copy +
//! Clone + Eq + Hash` compatible.

/// Unique identifier for a coherence partition.
///
/// Partitions are the primary isolation boundary in RVM. Each partition
/// runs one or more vCPUs and has its own memory map, capability space,
/// and coherence score.
///
/// The lower 8 bits serve as the hardware VMID for stage-2 TLB tagging
/// on `AArch64` (ADR-133, Section 3). VMID 0 is reserved for the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PartitionId(u32);

impl PartitionId {
    /// The hypervisor's own partition identifier (not schedulable).
    pub const HYPERVISOR: Self = Self(0);

    /// Maximum logical partition count (DC-12).
    ///
    /// Hardware VMID space is bounded (e.g., 256 on ARM). Agent workloads
    /// can exceed this, so logical partitions are multiplexed over physical
    /// VMID slots.
    pub const MAX_LOGICAL: u32 = 4096;

    /// Create a new partition identifier.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Return the raw identifier value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Extract the hardware VMID (lower 8 bits) for stage-2 TLB tagging.
    ///
    /// On `AArch64`, `VTTBR_EL2` encodes the VMID in bits \[55:48\]. Only 8 bits
    /// are used for 256 physical VMID slots; logical partitions exceeding
    /// this are multiplexed per DC-12.
    #[must_use]
    pub const fn vmid(self) -> u16 {
        (self.0 & 0xFF) as u16
    }

    /// Whether this is the hypervisor's own partition.
    #[must_use]
    pub const fn is_hypervisor(self) -> bool {
        self.0 == 0
    }
}

/// Virtual CPU identifier within a partition.
///
/// A vCPU represents a schedulable execution context. Each vCPU belongs
/// to exactly one partition and carries its own register state and
/// witness trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VcpuId {
    /// The partition this vCPU belongs to.
    partition: PartitionId,
    /// The local index of the vCPU within the partition.
    index: u16,
}

impl VcpuId {
    /// Create a new vCPU identifier.
    #[must_use]
    pub const fn new(partition: PartitionId, index: u16) -> Self {
        Self { partition, index }
    }

    /// Return the owning partition.
    #[must_use]
    pub const fn partition(self) -> PartitionId {
        self.partition
    }

    /// Return the local vCPU index.
    #[must_use]
    pub const fn index(self) -> u16 {
        self.index
    }
}
