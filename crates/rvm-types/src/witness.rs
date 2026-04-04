//! Witness record types for the audit subsystem.
//!
//! Every privileged action in RVM emits a compact, immutable audit record.
//! This is a core invariant (INV-3): **no witness, no mutation**.
//!
//! The witness record is exactly 64 bytes, cache-line aligned, with FNV-1a
//! hash chaining for tamper evidence. See ADR-134 for the full specification.

/// A single witness record. Exactly 64 bytes, cache-line aligned.
///
/// All fields are little-endian. The record is `#[repr(C, align(64))]` to
/// guarantee layout and alignment on all target architectures (`AArch64`,
/// RISC-V, x86-64).
///
/// # Layout
///
/// | Offset | Size | Field                | Description |
/// |--------|------|----------------------|-------------|
/// | 0      | 8    | `sequence`           | Monotonic sequence number |
/// | 8      | 8    | `timestamp_ns`       | Nanosecond timestamp |
/// | 16     | 1    | `action_kind`        | Privileged action discriminant |
/// | 17     | 1    | `proof_tier`         | Proof tier (1, 2, or 3) |
/// | 18     | 1    | `flags`              | Action-specific flags |
/// | 19     | 1    | `_reserved`          | Reserved (must be zero) |
/// | 20     | 4    | `actor_partition_id` | Actor partition |
/// | 24     | 8    | `target_object_id`   | Target object |
/// | 32     | 4    | `capability_hash`    | Truncated cap hash |
/// | 36     | 8    | `payload`            | Action-specific data |
/// | 44     | 4    | `prev_hash`          | FNV-1a chain link |
/// | 48     | 4    | `record_hash`        | FNV-1a self-integrity |
/// | 52     | 8    | `aux`                | Secondary payload / TEE sig |
/// | 60     | 4    | `_pad`               | Padding to 64 bytes |
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct WitnessRecord {
    /// Monotonic sequence number. Provides global ordering of all privileged actions.
    pub sequence: u64,
    /// Nanosecond timestamp from the system timer (`CNTVCT_EL0` / `rdtsc`).
    pub timestamp_ns: u64,
    /// Which privileged action was performed (see [`ActionKind`]).
    pub action_kind: u8,
    /// Which proof tier authorized this action (1 = P1, 2 = P2, 3 = P3).
    pub proof_tier: u8,
    /// Action-specific flags (interpretation varies by `action_kind`).
    pub flags: u8,
    /// Reserved for future use. Must be zero.
    reserved: u8,
    /// Partition that performed the action.
    pub actor_partition_id: u32,
    /// Object acted upon: partition, region, capability, etc.
    pub target_object_id: u64,
    /// Truncated FNV-1a hash of the capability used (not the full token).
    pub capability_hash: u32,
    /// Action-specific data, packed by kind.
    ///
    /// Examples:
    /// - `PartitionSplit`: `new_id_a` in bytes \[0..4\], `new_id_b` in bytes \[4..8\].
    /// - `RegionTransfer`: `from_partition` in bytes \[0..4\], `to_partition` in bytes \[4..8\].
    pub payload: [u8; 8],
    /// FNV-1a hash of the previous record (chain link for tamper evidence).
    pub prev_hash: u32,
    /// FNV-1a hash of bytes \[0..44\] of this record (self-integrity).
    pub record_hash: u32,
    /// Secondary payload or TEE signature fragment.
    pub aux: [u8; 8],
    /// Padding to guarantee 64-byte total size.
    pad: [u8; 4],
}

// Compile-time size assertion: the record MUST be exactly 64 bytes.
const _: () = {
    assert!(core::mem::size_of::<WitnessRecord>() == 64);
};

impl WitnessRecord {
    /// Create a zeroed witness record (genesis / placeholder).
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            sequence: 0,
            timestamp_ns: 0,
            action_kind: 0,
            proof_tier: 0,
            flags: 0,
            reserved: 0,
            actor_partition_id: 0,
            target_object_id: 0,
            capability_hash: 0,
            payload: [0; 8],
            prev_hash: 0,
            record_hash: 0,
            aux: [0; 8],
            pad: [0; 4],
        }
    }
}

/// A 256-bit witness commitment hash.
///
/// Used to anchor state transitions in the RVM witness trail. This is
/// a fixed-size value type suitable for embedding in `no_std` contexts
/// without heap allocation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessHash {
    bytes: [u8; 32],
}

impl WitnessHash {
    /// The zero hash, used as a sentinel for the genesis state.
    pub const ZERO: Self = Self { bytes: [0u8; 32] };

    /// Create a witness hash from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Return the raw byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Check whether this is the zero (genesis) hash.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < 32 {
            if self.bytes[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl core::fmt::Debug for WitnessHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WitnessHash(")?;
        for byte in &self.bytes[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..)")
    }
}

impl core::fmt::Display for WitnessHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Privileged actions that produce witness records (ADR-134, Section 2).
///
/// Organized by subsystem. Hex values allow easy filtering by prefix in
/// audit queries (0x0_ = partition, 0x1_ = capability, 0x2_ = memory, etc.).
///
/// If a privileged action exists without a corresponding kind, the system
/// has an audit gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ActionKind {
    // --- Partition lifecycle (0x01-0x0F) ---
    /// A new partition was created.
    PartitionCreate      = 0x01,
    /// A partition was destroyed and its resources freed.
    PartitionDestroy     = 0x02,
    /// A partition was suspended (tasks paused).
    PartitionSuspend     = 0x03,
    /// A suspended partition was resumed.
    PartitionResume      = 0x04,
    /// A partition was split along a mincut boundary.
    PartitionSplit       = 0x05,
    /// Two partitions were merged into one.
    PartitionMerge       = 0x06,
    /// A partition was hibernated to dormant/cold storage.
    PartitionHibernate   = 0x07,
    /// A hibernated partition was reconstructed from its receipt.
    PartitionReconstruct = 0x08,
    /// A partition was migrated to another node.
    PartitionMigrate     = 0x09,

    // --- Capability operations (0x10-0x1F) ---
    /// A capability was granted (copied) to another partition.
    CapabilityGrant      = 0x10,
    /// A capability was revoked.
    CapabilityRevoke     = 0x11,
    /// A capability was delegated (with depth decrement).
    CapabilityDelegate   = 0x12,
    /// Delegation depth was increased (escalation).
    CapabilityEscalate   = 0x13,
    /// Capability was attenuated during a partition split (DC-8).
    CapabilityAttenuated = 0x14,

    // --- Memory operations (0x20-0x2F) ---
    /// A memory region was created.
    RegionCreate         = 0x20,
    /// A memory region was destroyed.
    RegionDestroy        = 0x21,
    /// A memory region was transferred to another partition.
    RegionTransfer       = 0x22,
    /// A memory region was shared (read-only) with another partition.
    RegionShare          = 0x23,
    /// A shared memory region was unshared.
    RegionUnshare        = 0x24,
    /// A memory region was promoted to a warmer tier.
    RegionPromote        = 0x25,
    /// A memory region was demoted to a colder tier.
    RegionDemote         = 0x26,
    /// A stage-2 mapping was added for a memory region.
    RegionMap            = 0x27,
    /// A stage-2 mapping was removed for a memory region.
    RegionUnmap          = 0x28,

    // --- Communication (0x30-0x3F) ---
    /// A communication edge was created between two partitions.
    CommEdgeCreate       = 0x30,
    /// A communication edge was destroyed.
    CommEdgeDestroy      = 0x31,
    /// An IPC message was sent.
    IpcSend              = 0x32,
    /// An IPC message was received.
    IpcReceive           = 0x33,
    /// A zero-copy memory share was established.
    ZeroCopyShare        = 0x34,
    /// A notification signal was sent.
    NotificationSignal   = 0x35,

    // --- Device operations (0x40-0x4F) ---
    /// A device lease was granted.
    DeviceLeaseGrant     = 0x40,
    /// A device lease was revoked.
    DeviceLeaseRevoke    = 0x41,
    /// A device lease expired (time-bounded).
    DeviceLeaseExpire    = 0x42,
    /// A device lease was renewed.
    DeviceLeaseRenew     = 0x43,

    // --- Proof verification (0x50-0x5F) ---
    /// A P1 capability check passed.
    ProofVerifiedP1      = 0x50,
    /// A P2 policy validation passed.
    ProofVerifiedP2      = 0x51,
    /// A P3 deep proof passed.
    ProofVerifiedP3      = 0x52,
    /// A proof was rejected.
    ProofRejected        = 0x53,
    /// A proof was escalated to a higher tier.
    ProofEscalated       = 0x54,

    // --- Scheduler decisions (0x60-0x6F) ---
    /// Scheduler epoch boundary (bulk switch summary per DC-10).
    SchedulerEpoch       = 0x60,
    /// Scheduler mode switched (Reflex / Flow / Recovery).
    SchedulerModeSwitch  = 0x61,
    /// A task was spawned within a partition.
    TaskSpawn            = 0x62,
    /// A task was terminated.
    TaskTerminate        = 0x63,
    /// Scheduler triggered a structural split.
    StructuralSplit      = 0x64,
    /// Scheduler triggered a structural merge.
    StructuralMerge      = 0x65,

    // --- Recovery actions (0x70-0x7F) ---
    /// System entered recovery mode.
    RecoveryEnter        = 0x70,
    /// System exited recovery mode.
    RecoveryExit         = 0x71,
    /// A recovery checkpoint was created.
    CheckpointCreated    = 0x72,
    /// A recovery checkpoint was restored.
    CheckpointRestored   = 0x73,
    /// Mincut budget was exceeded, stale cut used (DC-2 fallback).
    MinCutBudgetExceeded = 0x74,
    /// System entered degraded mode (DC-6).
    DegradedModeEntered  = 0x75,
    /// System exited degraded mode.
    DegradedModeExited   = 0x76,

    // --- Boot and attestation (0x80-0x8F) ---
    /// Boot attestation record (genesis witness).
    BootAttestation      = 0x80,
    /// Boot sequence completed successfully.
    BootComplete         = 0x81,
    /// TEE-backed attestation record.
    TeeAttestation       = 0x82,

    // --- Vector/Graph mutations (0x90-0x9F) ---
    /// A vector was inserted into the coherence graph.
    VectorPut            = 0x90,
    /// A vector was deleted from the coherence graph.
    VectorDelete         = 0x91,
    /// A graph mutation occurred.
    GraphMutation        = 0x92,
    /// Coherence scores were recomputed.
    CoherenceRecomputed  = 0x93,

    // --- VMID management (0xA0-0xAF) ---
    /// A physical VMID was reclaimed from a hibernated partition (DC-12).
    VmidReclaim          = 0xA0,
    /// Migration timed out and was aborted (DC-7).
    MigrationTimeout     = 0xA1,
}

impl ActionKind {
    /// Return the subsystem prefix for this action kind.
    ///
    /// Useful for filtering audit queries by subsystem:
    /// 0 = partition, 1 = capability, 2 = memory, 3 = communication,
    /// 4 = device, 5 = proof, 6 = scheduler, 7 = recovery,
    /// 8 = boot, 9 = graph, 0xA = VMID management.
    #[must_use]
    pub const fn subsystem(self) -> u8 {
        (self as u8) >> 4
    }
}

/// FNV-1a hash over a byte slice.
///
/// Chosen for speed (< 50 ns for 64 bytes), not cryptographic strength.
/// For tamper resistance against a capable adversary, use the optional
/// TEE-backed `WitnessSigner` (ADR-134, Section 9).
#[must_use]
pub const fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    let mut i = 0;
    while i < data.len() {
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3); // FNV prime
        i += 1;
    }
    hash
}

/// FNV-1a hash truncated to 32 bits.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn fnv1a_32(data: &[u8]) -> u32 {
    // Intentional truncation: 64-bit hash folded to 32 bits.
    fnv1a_64(data) as u32
}

/// Default witness ring buffer capacity in records.
///
/// 16 MiB / 64 bytes = 262,144 records.
/// At 100,000 privileged actions per second this gives approximately 2.6
/// seconds of hot storage before overflow drain is needed.
pub const WITNESS_RING_CAPACITY: usize = 262_144;

/// Witness record size in bytes.
pub const WITNESS_RECORD_SIZE: usize = 64;
