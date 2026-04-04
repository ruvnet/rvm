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
