//! Coherence score computation based on graph structure.
//!
//! The coherence score for a partition measures the ratio of internal
//! (intra-group) communication weight to total communication weight.
//! Scores are expressed in fixed-point basis points (0..10000) to
//! avoid floating-point dependencies.

use rvm_types::{CoherenceScore, PartitionId};

use crate::graph::CoherenceGraph;

/// Result of coherence scoring for a single partition.
#[derive(Debug, Clone, Copy)]
pub struct PartitionCoherenceResult {
    /// The partition that was scored.
    pub partition: PartitionId,
    /// The computed coherence score.
    pub score: CoherenceScore,
    /// Internal edge weight sum.
    pub internal_weight: u64,
    /// Total edge weight sum (internal + external).
    pub total_weight: u64,
}

/// Compute the coherence score for a single partition.
///
/// The score is the ratio of internal edge weight to total edge weight,
/// expressed in basis points. A partition with no edges receives the
/// maximum score (fully coherent -- no external coupling).
///
/// "Internal" weight here is defined as self-loop edges on the partition
/// node. In practice, the caller models intra-partition communication
/// as self-loops and inter-partition communication as edges to other nodes.
#[must_use]
pub fn compute_coherence_score<const N: usize, const E: usize>(
    partition_id: PartitionId,
    graph: &CoherenceGraph<N, E>,
) -> PartitionCoherenceResult {
    let total = graph.total_weight(partition_id);
    let internal = graph.internal_weight(partition_id);

    let score = if total == 0 {
        // No edges means the partition is self-contained.
        CoherenceScore::MAX
    } else {
        // ratio = internal / total, scaled to basis points (0..10000)
        let bp = ((internal as u128) * 10_000 / (total as u128)) as u16;
        CoherenceScore::from_basis_points(bp)
    };

    PartitionCoherenceResult {
        partition: partition_id,
        score,
        internal_weight: internal,
        total_weight: total,
    }
}

/// Batch-recompute coherence scores for all partitions in the graph.
///
/// Returns an array of results. The caller provides a fixed-size output
/// buffer; entries beyond the active node count are left as `None`.
pub fn recompute_all_scores<const N: usize, const E: usize, const OUT: usize>(
    graph: &CoherenceGraph<N, E>,
    output: &mut [Option<PartitionCoherenceResult>; OUT],
) -> u16 {
    // Clear output
    for slot in output.iter_mut() {
        *slot = None;
    }

    let mut count = 0u16;
    for (_, pid) in graph.active_nodes() {
        if (count as usize) >= OUT {
            break;
        }
        output[count as usize] = Some(compute_coherence_score(pid, graph));
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::CoherenceGraph;

    fn pid(n: u32) -> PartitionId {
        PartitionId::new(n)
    }

    #[test]
    fn isolated_partition_has_max_coherence() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();

        let result = compute_coherence_score(pid(1), &g);
        assert_eq!(result.score, CoherenceScore::MAX);
        assert_eq!(result.total_weight, 0);
    }

    #[test]
    fn fully_external_edges_yield_zero_coherence() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 1000).unwrap();
        g.add_edge(pid(2), pid(1), 500).unwrap();

        let result = compute_coherence_score(pid(1), &g);
        // All edges are external, internal = 0
        assert_eq!(result.score.as_basis_points(), 0);
        assert_eq!(result.internal_weight, 0);
        assert_eq!(result.total_weight, 1500); // 1000 outgoing + 500 incoming
    }

    #[test]
    fn mixed_internal_external_scoring() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        // Self-loop (internal communication)
        g.add_edge(pid(1), pid(1), 750).unwrap();
        // External edge
        g.add_edge(pid(1), pid(2), 250).unwrap();

        let result = compute_coherence_score(pid(1), &g);
        // total = 750 (self-loop outgoing) + 750 (self-loop incoming) + 250 (outgoing)
        // Actually: total_weight sums outgoing + incoming.
        // Self-loop: outgoing 750 (via neighbors) + incoming 750 (self-loop to==from)
        // External: outgoing 250 (via neighbors)
        // So total = 750 + 750 + 250 = 1750?
        // Wait, let's think: total_weight counts outgoing neighbors + incoming.
        // self-loop (1->1): is outgoing from 1 AND incoming to 1, so counted twice.
        // external (1->2): is outgoing from 1.
        // total for pid(1) = outgoing(750 + 250) + incoming(750) = 1750
        // internal = self-loops where from==to==1: 750
        // score = 750/1750 * 10000 = 4285 bp
        assert_eq!(result.internal_weight, 750);
        assert_eq!(result.total_weight, 1750);
        assert_eq!(result.score.as_basis_points(), 4285);
    }

    #[test]
    fn batch_recompute_all() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 100).unwrap();

        let mut out: [Option<PartitionCoherenceResult>; 8] = [None; 8];
        let count = recompute_all_scores(&g, &mut out);
        assert_eq!(count, 2);
        assert!(out[0].is_some());
        assert!(out[1].is_some());
        assert!(out[2].is_none());
    }
}
