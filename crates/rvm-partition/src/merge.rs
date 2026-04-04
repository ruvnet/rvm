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

/// Check whether two partitions can be merged (DC-11).
///
/// Preconditions:
/// 1. Both must exceed the merge coherence threshold.
/// 2. The partitions must be adjacent in the coherence graph
///    (i.e., they share a communication edge).
/// 3. The combined resource count must not exceed limits.
///
/// # Parameters
///
/// - `coherence_a`, `coherence_b`: Coherence scores of the two partitions.
/// - `are_adjacent`: Whether the partitions share a communication edge in the
///   coherence graph. The caller must verify this from the graph structure.
/// - `combined_cap_count`: Total capabilities that would exist in the merged
///   partition. Must not exceed the per-partition capacity.
/// - `max_caps_per_partition`: Maximum capabilities per partition.
/// # Errors
///
/// Returns [`MergePreconditionError::InsufficientCoherence`] if either score is below threshold.
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

/// Extended merge precondition check including adjacency and resource limits.
///
/// This is the full DC-11 check. The simpler `merge_preconditions_met` is
/// retained for backward compatibility.
/// # Errors
///
/// Returns a [`MergePreconditionError`] if any precondition is violated.
pub fn merge_preconditions_full(
    coherence_a: CoherenceScore,
    coherence_b: CoherenceScore,
    are_adjacent: bool,
    combined_cap_count: usize,
    max_caps_per_partition: usize,
) -> Result<(), MergePreconditionError> {
    // Check coherence thresholds first.
    merge_preconditions_met(coherence_a, coherence_b)?;

    // Check adjacency in the coherence graph.
    if !are_adjacent {
        return Err(MergePreconditionError::NotAdjacent);
    }

    // Check that merged resources fit within limits.
    if combined_cap_count > max_caps_per_partition {
        return Err(MergePreconditionError::ResourceLimitExceeded);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(bp: u16) -> CoherenceScore {
        CoherenceScore::from_basis_points(bp)
    }

    // DEFAULT_MERGE_THRESHOLD = 7000

    // ---------------------------------------------------------------
    // Simple merge_preconditions_met tests
    // ---------------------------------------------------------------

    #[test]
    fn test_both_above_threshold_passes() {
        assert!(merge_preconditions_met(score(8000), score(9000)).is_ok());
    }

    #[test]
    fn test_both_at_threshold_passes() {
        assert!(merge_preconditions_met(score(7000), score(7000)).is_ok());
    }

    #[test]
    fn test_both_max_passes() {
        assert!(merge_preconditions_met(score(10000), score(10000)).is_ok());
    }

    #[test]
    fn test_a_below_threshold_fails() {
        let result = merge_preconditions_met(score(6999), score(8000));
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_b_below_threshold_fails() {
        let result = merge_preconditions_met(score(8000), score(6999));
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_both_below_threshold_fails() {
        let result = merge_preconditions_met(score(1000), score(2000));
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_both_zero_fails() {
        let result = merge_preconditions_met(score(0), score(0));
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    // ---------------------------------------------------------------
    // Full merge_preconditions_full tests (all 7 precondition failures)
    // ---------------------------------------------------------------

    #[test]
    fn test_full_all_conditions_met() {
        assert!(merge_preconditions_full(score(8000), score(8000), true, 100, 256).is_ok());
    }

    #[test]
    fn test_full_coherence_a_below_threshold() {
        let result = merge_preconditions_full(score(5000), score(8000), true, 100, 256);
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_full_coherence_b_below_threshold() {
        let result = merge_preconditions_full(score(8000), score(5000), true, 100, 256);
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_full_both_coherence_below_threshold() {
        let result = merge_preconditions_full(score(1000), score(2000), true, 100, 256);
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_full_not_adjacent() {
        let result = merge_preconditions_full(score(8000), score(8000), false, 100, 256);
        assert_eq!(result, Err(MergePreconditionError::NotAdjacent));
    }

    #[test]
    fn test_full_resource_limit_exceeded() {
        let result = merge_preconditions_full(score(8000), score(8000), true, 300, 256);
        assert_eq!(result, Err(MergePreconditionError::ResourceLimitExceeded));
    }

    #[test]
    fn test_full_resource_at_exact_limit() {
        assert!(merge_preconditions_full(score(8000), score(8000), true, 256, 256).is_ok());
    }

    #[test]
    fn test_full_resource_one_over_limit() {
        let result = merge_preconditions_full(score(8000), score(8000), true, 257, 256);
        assert_eq!(result, Err(MergePreconditionError::ResourceLimitExceeded));
    }

    #[test]
    fn test_full_coherence_checked_before_adjacency() {
        // If coherence fails, adjacency is not checked (coherence error returned).
        let result = merge_preconditions_full(score(1000), score(8000), false, 100, 256);
        assert_eq!(result, Err(MergePreconditionError::InsufficientCoherence));
    }

    #[test]
    fn test_full_adjacency_checked_before_resources() {
        // If adjacency fails, resources are not checked.
        let result = merge_preconditions_full(score(8000), score(8000), false, 9999, 256);
        assert_eq!(result, Err(MergePreconditionError::NotAdjacent));
    }
}
