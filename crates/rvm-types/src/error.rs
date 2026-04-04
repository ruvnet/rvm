//! Error types for the RVM microhypervisor.
//!
//! All failure modes across the kernel are represented by [`RvmError`].
//! Each variant maps to a specific class of failure documented in
//! ADR-132 (DC-14) and the partition/witness/proof subsystems.

/// The unified error type for RVM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvmError {
    // --- Partition errors ---
    /// The requested partition was not found.
    PartitionNotFound,
    /// The partition is in the wrong lifecycle state for this operation.
    InvalidPartitionState,
    /// Maximum partition count has been reached (DC-12).
    PartitionLimitExceeded,
    /// The partition split preconditions were not met.
    SplitPreconditionFailed,
    /// The partition merge preconditions were not met (DC-11).
    MergePreconditionFailed,
    /// Partition migration timed out (DC-7).
    MigrationTimeout,

    // --- vCPU errors ---
    /// The requested vCPU was not found.
    VcpuNotFound,
    /// The partition has no available vCPU slots.
    VcpuLimitReached,

    // --- Capability errors ---
    /// A capability check failed -- insufficient rights.
    InsufficientCapability,
    /// The capability token is stale (epoch mismatch).
    StaleCapability,
    /// The capability type does not match the resource.
    CapabilityTypeMismatch,
    /// Maximum delegation depth exceeded.
    DelegationDepthExceeded,
    /// The capability has already been consumed (`GRANT_ONCE`).
    CapabilityConsumed,

    // --- Witness errors ---
    /// A witness verification failed.
    WitnessVerificationFailed,
    /// The witness hash chain is broken (tamper detected).
    WitnessChainBroken,
    /// The witness log is full and drain is not keeping up.
    WitnessLogFull,

    // --- Proof errors ---
    /// A proof validation failed.
    ProofInvalid,
    /// The proof tier is insufficient for this operation.
    ProofTierInsufficient,
    /// Proof verification exceeded its time budget.
    ProofBudgetExceeded,

    // --- Coherence errors ---
    /// The coherence score is below the required threshold.
    CoherenceBelowThreshold,
    /// The mincut budget was exceeded (DC-2 fallback triggered).
    MinCutBudgetExceeded,

    // --- Memory errors ---
    /// The requested memory region overlaps with an existing mapping.
    MemoryOverlap,
    /// An address is not properly aligned.
    AlignmentError,
    /// The memory tier transition is invalid.
    InvalidTierTransition,
    /// No physical memory is available for allocation.
    OutOfMemory,

    // --- Device errors ---
    /// The requested device lease was not found.
    DeviceLeaseNotFound,
    /// The device lease has expired.
    DeviceLeaseExpired,
    /// A conflicting device lease exists.
    DeviceLeaseConflict,

    // --- Recovery errors ---
    /// The recovery checkpoint was not found.
    CheckpointNotFound,
    /// The recovery checkpoint is corrupted.
    CheckpointCorrupted,
    /// Failure escalated beyond recovery capability (DC-14).
    FailureEscalated,

    // --- General errors ---
    /// The operation would exceed a configured resource limit.
    ResourceLimitExceeded,
    /// The operation is not supported in the current configuration.
    Unsupported,
    /// An internal invariant was violated (should not occur).
    InternalError,
}

impl core::fmt::Display for RvmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PartitionNotFound => write!(f, "partition not found"),
            Self::InvalidPartitionState => write!(f, "invalid partition state for operation"),
            Self::PartitionLimitExceeded => write!(f, "maximum partition count reached"),
            Self::SplitPreconditionFailed => write!(f, "split preconditions not met"),
            Self::MergePreconditionFailed => write!(f, "merge preconditions not met"),
            Self::MigrationTimeout => write!(f, "partition migration timed out"),
            Self::VcpuNotFound => write!(f, "vCPU not found"),
            Self::VcpuLimitReached => write!(f, "vCPU limit reached"),
            Self::InsufficientCapability => write!(f, "insufficient capability rights"),
            Self::StaleCapability => write!(f, "stale capability (epoch mismatch)"),
            Self::CapabilityTypeMismatch => write!(f, "capability type mismatch"),
            Self::DelegationDepthExceeded => write!(f, "delegation depth exceeded"),
            Self::CapabilityConsumed => write!(f, "capability already consumed"),
            Self::WitnessVerificationFailed => write!(f, "witness verification failed"),
            Self::WitnessChainBroken => write!(f, "witness chain broken"),
            Self::WitnessLogFull => write!(f, "witness log full"),
            Self::ProofInvalid => write!(f, "proof invalid"),
            Self::ProofTierInsufficient => write!(f, "proof tier insufficient"),
            Self::ProofBudgetExceeded => write!(f, "proof budget exceeded"),
            Self::CoherenceBelowThreshold => write!(f, "coherence below threshold"),
            Self::MinCutBudgetExceeded => write!(f, "mincut budget exceeded"),
            Self::MemoryOverlap => write!(f, "memory region overlap"),
            Self::AlignmentError => write!(f, "address alignment error"),
            Self::InvalidTierTransition => write!(f, "invalid memory tier transition"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::DeviceLeaseNotFound => write!(f, "device lease not found"),
            Self::DeviceLeaseExpired => write!(f, "device lease expired"),
            Self::DeviceLeaseConflict => write!(f, "conflicting device lease"),
            Self::CheckpointNotFound => write!(f, "checkpoint not found"),
            Self::CheckpointCorrupted => write!(f, "checkpoint corrupted"),
            Self::FailureEscalated => write!(f, "failure escalated beyond recovery"),
            Self::ResourceLimitExceeded => write!(f, "resource limit exceeded"),
            Self::Unsupported => write!(f, "operation unsupported"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}

/// Shorthand result type for RVM operations.
pub type RvmResult<T> = core::result::Result<T, RvmError>;
