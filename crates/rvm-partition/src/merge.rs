//! Partition merge logic.

use rvm_types::CoherenceScore;

/// Error returned when merge preconditions are not met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergePreconditionError {
    /// One or both partitions have insufficient coherence.
    InsufficientCoherence,
    /// The partitions are not adjacent in the coherence graph.
    NotAdjacent,
    /// The merged partition would exceed resource limits.
    ResourceLimitExceeded,
}

/// Check whether two partitions can be merged.
///
/// Both must exceed the merge coherence threshold (DC-11).
#[must_use]
pub fn merge_preconditions_met(
    coherence_a: CoherenceScore,
    coherence_b: CoherenceScore,
) -> Result<(), MergePreconditionError> {
    let threshold = CoherenceScore::DEFAULT_MERGE_THRESHOLD;
    if !coherence_a.meets_threshold(threshold) || !coherence_b.meets_threshold(threshold) {
        return Err(MergePreconditionError::InsufficientCoherence);
    }
    Ok(())
}
