//! Partition split logic.

use rvm_types::CoherenceScore;

/// Assign a score to a region for partition split placement.
///
/// Returns a score in [0, 10000] indicating preference for the
/// "left" partition. Higher = more likely left, lower = more likely right.
#[must_use]
pub fn scored_region_assignment(
    region_coherence: CoherenceScore,
    left_coherence: CoherenceScore,
    right_coherence: CoherenceScore,
) -> u16 {
    // Simple heuristic: assign to the partition whose coherence is closer.
    let left_diff = if region_coherence.as_basis_points() >= left_coherence.as_basis_points() {
        region_coherence.as_basis_points() - left_coherence.as_basis_points()
    } else {
        left_coherence.as_basis_points() - region_coherence.as_basis_points()
    };

    let right_diff = if region_coherence.as_basis_points() >= right_coherence.as_basis_points() {
        region_coherence.as_basis_points() - right_coherence.as_basis_points()
    } else {
        right_coherence.as_basis_points() - region_coherence.as_basis_points()
    };

    if left_diff <= right_diff {
        // Prefer left
        7500
    } else {
        // Prefer right
        2500
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(bp: u16) -> CoherenceScore {
        CoherenceScore::from_basis_points(bp)
    }

    #[test]
    fn test_region_closer_to_left() {
        // Region=5000, Left=5000, Right=1000 -> closer to left.
        let result = scored_region_assignment(score(5000), score(5000), score(1000));
        assert_eq!(result, 7500);
    }

    #[test]
    fn test_region_closer_to_right() {
        // Region=1000, Left=5000, Right=1000 -> closer to right.
        let result = scored_region_assignment(score(1000), score(5000), score(1000));
        assert_eq!(result, 2500);
    }

    #[test]
    fn test_region_equidistant_prefers_left() {
        // Region=5000, Left=3000, Right=7000 -> left_diff=2000, right_diff=2000.
        // Tie-breaking: left_diff <= right_diff, so prefers left.
        let result = scored_region_assignment(score(5000), score(3000), score(7000));
        assert_eq!(result, 7500);
    }

    #[test]
    fn test_all_same_coherence() {
        // All equal: diff=0 for both, prefers left.
        let result = scored_region_assignment(score(5000), score(5000), score(5000));
        assert_eq!(result, 7500);
    }

    #[test]
    fn test_region_zero_coherence() {
        // Region=0: closer to lower partition.
        let result = scored_region_assignment(score(0), score(10000), score(1000));
        assert_eq!(result, 2500); // right is closer (diff 1000 vs 10000)
    }

    #[test]
    fn test_region_max_coherence() {
        // Region=10000: closer to left=10000.
        let result = scored_region_assignment(score(10000), score(10000), score(0));
        assert_eq!(result, 7500);
    }

    #[test]
    fn test_both_partitions_zero_region_nonzero() {
        // Left=0, Right=0, Region=5000.
        // Both diffs are 5000, tie goes to left.
        let result = scored_region_assignment(score(5000), score(0), score(0));
        assert_eq!(result, 7500);
    }

    #[test]
    fn test_both_partitions_max_region_zero() {
        // Left=10000, Right=10000, Region=0.
        // Both diffs are 10000, tie goes to left.
        let result = scored_region_assignment(score(0), score(10000), score(10000));
        assert_eq!(result, 7500);
    }
}
