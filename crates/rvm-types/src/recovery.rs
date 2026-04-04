//! Recovery and checkpoint types.

use crate::PartitionId;

/// Classification of failure severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FailureClass {
    /// Transient: retry is likely to succeed.
    Transient = 0,
    /// Recoverable: checkpoint restore can fix.
    Recoverable = 1,
    /// Permanent: partition must be destroyed.
    Permanent = 2,
    /// Catastrophic: system-wide recovery needed.
    Catastrophic = 3,
}

/// A recovery checkpoint (state snapshot).
#[derive(Debug, Clone, Copy)]
pub struct RecoveryCheckpoint {
    /// Partition this checkpoint belongs to.
    pub partition: PartitionId,
    /// Sequence number of the witness record at checkpoint time.
    pub witness_sequence: u64,
    /// Timestamp when the checkpoint was taken.
    pub timestamp_ns: u64,
    /// Epoch at checkpoint time.
    pub epoch: u32,
}

/// A receipt for reconstructing a hibernated partition.
#[derive(Debug, Clone, Copy)]
pub struct ReconstructionReceipt {
    /// Original partition ID.
    pub original_id: PartitionId,
    /// Checkpoint from which to reconstruct.
    pub checkpoint: RecoveryCheckpoint,
    /// Whether the partition was hibernated (vs destroyed).
    pub was_hibernated: bool,
}
