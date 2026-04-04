//! Chain integrity verification and audit queries.

use crate::hash::compute_chain_hash;
use crate::log::fold_u64_to_u32;
use rvm_types::WitnessRecord;

/// Errors detected during chain integrity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainIntegrityError {
    /// The chain hash link is broken at the given sequence.
    ChainBreak {
        /// Sequence number of the broken record.
        sequence: u64,
    },
    /// The record's self-integrity hash does not match.
    RecordCorrupted {
        /// Sequence number of the corrupted record.
        sequence: u64,
    },
    /// The record slice is empty.
    EmptyLog,
}

impl core::fmt::Display for ChainIntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChainBreak { sequence } => write!(f, "chain break at seq {sequence}"),
            Self::RecordCorrupted { sequence } => write!(f, "corrupted record at seq {sequence}"),
            Self::EmptyLog => write!(f, "empty log"),
        }
    }
}

/// Verifies hash chain integrity of a contiguous slice of witness records.
///
/// Returns `Ok(count)` if the chain is valid, or an error at the first
/// broken link.
///
/// # Errors
///
/// Returns [`ChainIntegrityError::EmptyLog`] if the slice is empty.
/// Returns [`ChainIntegrityError::ChainBreak`] if a chain link is broken.
/// Returns [`ChainIntegrityError::RecordCorrupted`] if a record hash does not match.
#[allow(clippy::cast_possible_truncation)]
pub fn verify_chain(records: &[WitnessRecord]) -> Result<usize, ChainIntegrityError> {
    if records.is_empty() {
        return Err(ChainIntegrityError::EmptyLog);
    }

    let mut prev_chain_hash: u64 = 0;

    for record in records {
        let expected_prev = fold_u64_to_u32(prev_chain_hash);
        if record.prev_hash != expected_prev {
            return Err(ChainIntegrityError::ChainBreak {
                sequence: record.sequence,
            });
        }

        let chain = compute_chain_hash(prev_chain_hash, record.sequence);
        if record.record_hash != fold_u64_to_u32(chain) {
            return Err(ChainIntegrityError::RecordCorrupted {
                sequence: record.sequence,
            });
        }

        prev_chain_hash = chain;
    }

    Ok(records.len())
}

/// Returns an iterator over records matching the given partition ID.
pub fn query_by_partition(
    records: &[WitnessRecord], partition_id: u32,
) -> impl Iterator<Item = &WitnessRecord> {
    records.iter().filter(move |r| r.actor_partition_id == partition_id)
}

/// Returns an iterator over records matching the given action kind.
pub fn query_by_action_kind(
    records: &[WitnessRecord], kind: u8,
) -> impl Iterator<Item = &WitnessRecord> {
    records.iter().filter(move |r| r.action_kind == kind)
}

/// Returns an iterator over records within the given time range.
pub fn query_by_time_range(
    records: &[WitnessRecord], start_ns: u64, end_ns: u64,
) -> impl Iterator<Item = &WitnessRecord> {
    records.iter().filter(move |r| r.timestamp_ns >= start_ns && r.timestamp_ns <= end_ns)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use super::*;
    use crate::log::WitnessLog;
    use rvm_types::ActionKind;

    fn build_chain(count: usize) -> Vec<WitnessRecord> {
        let log = WitnessLog::<64>::new();
        for i in 0..count {
            let mut r = WitnessRecord::zeroed();
            r.action_kind = ActionKind::SchedulerEpoch as u8;
            r.actor_partition_id = (i as u32) % 3 + 1;
            r.target_object_id = (i as u64) * 10;
            r.timestamp_ns = (i as u64) * 1000 + 100;
            log.append(r);
        }
        let mut records = vec![WitnessRecord::zeroed(); count];
        let copied = log.snapshot(&mut records);
        records.truncate(copied);
        records
    }

    #[test]
    fn test_verify_valid_chain() {
        let records = build_chain(5);
        assert_eq!(verify_chain(&records), Ok(5));
    }

    #[test]
    fn test_verify_corrupted_record() {
        let mut records = build_chain(5);
        records[2].record_hash ^= 0xFFFF;
        assert!(matches!(verify_chain(&records), Err(ChainIntegrityError::RecordCorrupted { .. })));
    }

    #[test]
    fn test_verify_broken_chain() {
        let mut records = build_chain(5);
        records[3].prev_hash ^= 0xDEAD;
        assert!(matches!(verify_chain(&records), Err(ChainIntegrityError::ChainBreak { .. })));
    }

    #[test]
    fn test_verify_empty() {
        assert_eq!(verify_chain(&[]), Err(ChainIntegrityError::EmptyLog));
    }

    #[test]
    fn test_query_by_partition() {
        let records = build_chain(9);
        let matches: Vec<_> = query_by_partition(&records, 1).collect();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_query_by_action_kind() {
        let records = build_chain(5);
        let matches: Vec<_> = query_by_action_kind(&records, ActionKind::SchedulerEpoch as u8).collect();
        assert_eq!(matches.len(), 5);
    }

    #[test]
    fn test_query_by_time_range() {
        let records = build_chain(5);
        let matches: Vec<_> = query_by_time_range(&records, 1000, 3000).collect();
        assert!(!matches.is_empty());
    }
}
