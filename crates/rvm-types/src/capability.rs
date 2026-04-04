//! Capability types for the RVM access-control model.
//!
//! Every resource in RVM is accessed through an unforgeable capability token.
//! Capabilities carry a type tag and a rights bitmap that constrains the
//! operations a holder may perform.
//!
//! During partition split, capabilities follow the objects they reference
//! (DC-8). Capabilities referencing shared objects are attenuated to
//! `READ` only in both new partitions.

use bitflags::bitflags;

bitflags! {
    /// Access rights bitmap carried by a capability (ADR-132, DC-3/DC-8).
    ///
    /// Multiple rights can be combined. The `GRANT_ONCE` right is consumed
    /// after a single delegation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CapRights: u8 {
        /// Permission to read / inspect the resource.
        const READ       = 0x01;
        /// Permission to write / mutate the resource.
        const WRITE      = 0x02;
        /// Permission to grant (copy) this capability to another partition.
        const GRANT      = 0x04;
        /// Permission to revoke derived capabilities.
        const REVOKE     = 0x08;
        /// Permission to execute code within the resource's context.
        const EXECUTE    = 0x10;
        /// Permission to create a proof referencing this capability.
        const PROVE      = 0x20;
        /// One-time grant: capability is consumed after a single delegation.
        const GRANT_ONCE = 0x40;
    }
}

/// The type of resource a capability refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CapType {
    /// Authority over a partition (create, destroy, split, merge).
    Partition = 0,
    /// Authority over a memory region (map, transfer, tier change).
    Region = 1,
    /// Authority over a communication edge (create, destroy, send).
    CommEdge = 2,
    /// Authority over a device lease (grant, revoke, renew).
    Device = 3,
    /// Authority over the scheduler (mode switch, priority override).
    Scheduler = 4,
    /// Authority over the witness log (query, export).
    WitnessLog = 5,
    /// Authority over the proof verifier (escalation, deep proof).
    Proof = 6,
    /// Authority over a virtual CPU.
    Vcpu = 7,
    /// Authority over a coherence observer.
    Coherence = 8,
}

/// Unique identifier for a capability in the system-wide capability space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CapabilityId(u64);

impl CapabilityId {
    /// The root capability (bootstrap authority).
    pub const ROOT: Self = Self(0);

    /// Create a new capability identifier.
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

/// An unforgeable capability token.
///
/// Capability tokens are the sole mechanism for accessing RVM resources.
/// They are created by the kernel and cannot be forged by partitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapToken {
    /// Globally unique identifier for this capability.
    id: u64,
    /// The type of resource this capability grants access to.
    cap_type: CapType,
    /// Access rights bitmap.
    rights: CapRights,
    /// Monotonic epoch for stale-handle detection.
    epoch: u32,
}

impl CapToken {
    /// Create a new capability token.
    #[must_use]
    pub const fn new(id: u64, cap_type: CapType, rights: CapRights, epoch: u32) -> Self {
        Self {
            id,
            cap_type,
            rights,
            epoch,
        }
    }

    /// Return the capability identifier.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Return the capability type.
    #[must_use]
    pub const fn cap_type(self) -> CapType {
        self.cap_type
    }

    /// Return the access rights.
    #[must_use]
    pub const fn rights(self) -> CapRights {
        self.rights
    }

    /// Return the epoch counter.
    #[must_use]
    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    /// Check whether this token carries the given rights.
    #[must_use]
    pub const fn has_rights(self, required: CapRights) -> bool {
        self.rights.contains(required)
    }

    /// Return a truncated 32-bit hash for witness record embedding.
    ///
    /// This is NOT the full capability -- it is a truncated hash used
    /// for identification without leaking the full token contents.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn truncated_hash(self) -> u32 {
        // Intentional truncation: mixing 64-bit id into 32-bit hash.
        let mut h = self.id as u32;
        h ^= (self.id >> 32) as u32;
        h ^= self.epoch;
        h ^= (self.rights.bits() as u32) << 24;
        h
    }
}

/// Unforgeable capability with full delegation metadata.
///
/// This is the kernel-internal representation. [`CapToken`] is the
/// user-visible handle.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Unique identifier for this capability.
    pub id: CapabilityId,
    /// The kernel object this capability authorizes access to.
    pub object_id: u64,
    /// Kind of object targeted.
    pub object_type: CapType,
    /// Rights granted by this capability.
    pub rights: CapRights,
    /// Opaque badge value carried through IPC for endpoint identification.
    pub badge: u32,
    /// Epoch in which this capability was created (for revocation ordering).
    pub epoch: u32,
    /// Parent capability from which this was derived (`ROOT` = root).
    pub parent: CapabilityId,
    /// Current delegation depth (decremented on each grant; 0 = non-delegable).
    pub delegation_depth: u8,
}

/// Maximum delegation depth for capabilities (ADR-132).
///
/// Limits how many times a capability can be re-granted. Prevents unbounded
/// authority chains that complicate revocation.
pub const MAX_DELEGATION_DEPTH: u8 = 8;
