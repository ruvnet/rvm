//! Bridge to RuVector ecosystem crates.
//!
//! When the `ruvector` feature is enabled, this module provides adapters
//! that translate between RVM's internal coherence graph and the ruvector
//! crate APIs (mincut, sparsifier, solver).
//!
//! ## Architecture
//!
//! ```text
//! rvm-coherence::CoherenceGraph
//!     | (export adjacency)
//! MinCutBackend  --> ruvector-mincut (when available)
//!     |
//! CoherenceBackend --> ruvector-coherence spectral scoring (when available)
//! ```
//!
//! ## Design
//!
//! Two backend traits decouple the engine from the mincut and scoring
//! implementations. The built-in backends (`BuiltinMinCut`,
//! `BuiltinCoherence`) use the self-contained Stoer-Wagner and ratio-based
//! scoring that ship with rvm-coherence. When the `ruvector` feature is
//! enabled, stub implementations (`RuVectorMinCut`, `SpectralCoherence`)
//! become available. These stubs currently delegate to the built-in
//! backends; once the ruvector crates gain `no_std` support, the stubs
//! will call into the real implementations.

use rvm_types::{CoherenceScore, PartitionId};

use crate::graph::CoherenceGraph;
use crate::mincut::{MinCutBridge, MinCutResult};
use crate::scoring;

// -----------------------------------------------------------------------
// MinCut backend trait
// -----------------------------------------------------------------------

/// Result of a backend minimum cut computation.
///
/// Expressed as flat arrays of partition IDs so that no heap allocation
/// is needed. Backends populate `left` / `right` with the two sides of
/// the minimum cut and report the total cut weight.
#[derive(Debug, Clone)]
pub struct BackendMinCutResult {
    /// Partition IDs on the left side of the cut.
    pub left: [Option<PartitionId>; 32],
    /// Number of valid entries in `left`.
    pub left_count: u16,
    /// Partition IDs on the right side of the cut.
    pub right: [Option<PartitionId>; 32],
    /// Number of valid entries in `right`.
    pub right_count: u16,
    /// Total weight of edges crossing the cut.
    pub cut_weight: u64,
    /// Whether the computation completed within budget.
    pub within_budget: bool,
    /// Name of the backend that produced the result.
    pub backend: &'static str,
}

impl BackendMinCutResult {
    /// Create an empty result tagged with the given backend name.
    const fn empty(backend: &'static str) -> Self {
        Self {
            left: [None; 32],
            left_count: 0,
            right: [None; 32],
            right_count: 0,
            cut_weight: 0,
            within_budget: true,
            backend,
        }
    }

    /// Convert from the internal `MinCutResult` type.
    fn from_mincut_result(r: &MinCutResult, backend: &'static str) -> Self {
        let mut out = Self::empty(backend);
        out.cut_weight = r.cut_weight;
        out.within_budget = r.within_budget;
        out.left_count = r.left_count;
        out.right_count = r.right_count;
        let copy_len_l = r.left_count as usize;
        let copy_len_r = r.right_count as usize;
        // Copy partition IDs from MinCutResult arrays
        for i in 0..copy_len_l.min(32) {
            out.left[i] = r.left[i];
        }
        for i in 0..copy_len_r.min(32) {
            out.right[i] = r.right[i];
        }
        out
    }
}

// -----------------------------------------------------------------------
// MinCutBackend trait
// -----------------------------------------------------------------------

/// Trait for pluggable mincut backends.
///
/// The default implementation uses the built-in Stoer-Wagner from
/// `mincut.rs`. With the `ruvector` feature, a RuVector-backed
/// implementation becomes available.
pub trait MinCutBackend {
    /// Find the minimum cut in the neighbourhood of `partition_id`.
    ///
    /// Returns a `BackendMinCutResult` containing the two partitions
    /// of the cut and the crossing edge weight.
    fn find_min_cut<const MN: usize, const ME: usize>(
        &mut self,
        graph: &CoherenceGraph<MN, ME>,
        partition_id: PartitionId,
    ) -> BackendMinCutResult;

    /// Name of this backend for diagnostics.
    fn backend_name(&self) -> &'static str;
}

// -----------------------------------------------------------------------
// Built-in Stoer-Wagner backend (always available)
// -----------------------------------------------------------------------

/// Built-in Stoer-Wagner mincut backend.
///
/// Delegates directly to the `MinCutBridge` from `mincut.rs`. This is
/// the default backend that requires no external crate dependencies.
pub struct BuiltinMinCut<const N: usize> {
    inner: MinCutBridge<N>,
}

impl<const N: usize> BuiltinMinCut<N> {
    /// Create a new built-in backend with the given iteration budget.
    #[must_use]
    pub const fn new(max_iterations: u32) -> Self {
        Self {
            inner: MinCutBridge::new(max_iterations),
        }
    }

    /// Return a reference to the inner `MinCutBridge` for direct access
    /// to epoch and budget counters.
    #[must_use]
    pub const fn inner(&self) -> &MinCutBridge<N> {
        &self.inner
    }

    /// Return a mutable reference to the inner `MinCutBridge`.
    pub fn inner_mut(&mut self) -> &mut MinCutBridge<N> {
        &mut self.inner
    }
}

impl<const N: usize> MinCutBackend for BuiltinMinCut<N> {
    fn find_min_cut<const MN: usize, const ME: usize>(
        &mut self,
        graph: &CoherenceGraph<MN, ME>,
        partition_id: PartitionId,
    ) -> BackendMinCutResult {
        let name = self.backend_name();
        let result = self.inner.find_min_cut(graph, partition_id);
        BackendMinCutResult::from_mincut_result(result, name)
    }

    fn backend_name(&self) -> &'static str {
        "stoer-wagner-builtin"
    }
}

// -----------------------------------------------------------------------
// RuVector mincut backend (available with `ruvector` feature)
// -----------------------------------------------------------------------

/// RuVector-backed mincut backend.
///
/// When the `ruvector` feature is enabled, this struct becomes available.
/// It will eventually call into `ruvector-mincut`'s subpolynomial dynamic
/// mincut algorithm. Currently it falls back to the built-in Stoer-Wagner
/// until the ruvector crates gain `no_std` support.
#[cfg(feature = "ruvector")]
pub struct RuVectorMinCut<const N: usize> {
    /// Fallback to built-in while ruvector-mincut lacks no_std.
    fallback: BuiltinMinCut<N>,
}

#[cfg(feature = "ruvector")]
impl<const N: usize> RuVectorMinCut<N> {
    /// Create a new RuVector backend with the given iteration budget
    /// (used by the fallback path).
    #[must_use]
    pub const fn new(max_iterations: u32) -> Self {
        Self {
            fallback: BuiltinMinCut::new(max_iterations),
        }
    }
}

#[cfg(feature = "ruvector")]
impl<const N: usize> MinCutBackend for RuVectorMinCut<N> {
    fn find_min_cut<const MN: usize, const ME: usize>(
        &mut self,
        graph: &CoherenceGraph<MN, ME>,
        partition_id: PartitionId,
    ) -> BackendMinCutResult {
        // TODO: When ruvector-mincut gains no_std support, call:
        //   ruvector_mincut::DynamicMinCut with the exported adjacency.
        // For now, fall back to the built-in Stoer-Wagner.
        let result = self.fallback.inner.find_min_cut(graph, partition_id);
        BackendMinCutResult::from_mincut_result(result, self.backend_name())
    }

    fn backend_name(&self) -> &'static str {
        "ruvector-mincut-stub"
    }
}

// -----------------------------------------------------------------------
// CoherenceBackend trait
// -----------------------------------------------------------------------

/// Trait for pluggable coherence scoring backends.
///
/// The default implementation uses the ratio-based scoring from
/// `scoring.rs`. With the `ruvector` feature, a spectral scoring
/// backend becomes available.
pub trait CoherenceBackend {
    /// Compute the coherence score for a partition.
    ///
    /// Returns the score in basis points (0..10000).
    fn compute_score<const N: usize, const E: usize>(
        &self,
        partition_id: PartitionId,
        graph: &CoherenceGraph<N, E>,
    ) -> CoherenceScore;

    /// Name of this backend for diagnostics.
    fn backend_name(&self) -> &'static str;
}

// -----------------------------------------------------------------------
// Built-in ratio-based coherence scoring (always available)
// -----------------------------------------------------------------------

/// Built-in ratio-based coherence scoring backend.
///
/// Uses the `internal_weight / total_weight` ratio from `scoring.rs`.
pub struct BuiltinCoherence;

impl CoherenceBackend for BuiltinCoherence {
    fn compute_score<const N: usize, const E: usize>(
        &self,
        partition_id: PartitionId,
        graph: &CoherenceGraph<N, E>,
    ) -> CoherenceScore {
        scoring::compute_coherence_score(partition_id, graph).score
    }

    fn backend_name(&self) -> &'static str {
        "ratio-builtin"
    }
}

// -----------------------------------------------------------------------
// RuVector spectral coherence scoring (available with `ruvector` feature)
// -----------------------------------------------------------------------

/// RuVector spectral coherence scoring backend.
///
/// When the `ruvector` feature is enabled, this struct becomes available.
/// It will eventually call into `ruvector-coherence`'s spectral scoring
/// (Fiedler vector, algebraic connectivity). Currently it falls back to
/// the built-in ratio-based scoring until the ruvector crates gain
/// `no_std` support.
#[cfg(feature = "ruvector")]
pub struct SpectralCoherence;

#[cfg(feature = "ruvector")]
impl CoherenceBackend for SpectralCoherence {
    fn compute_score<const N: usize, const E: usize>(
        &self,
        partition_id: PartitionId,
        graph: &CoherenceGraph<N, E>,
    ) -> CoherenceScore {
        // TODO: When ruvector-coherence gains no_std support, call:
        //   ruvector_coherence::spectral::SpectralCoherenceScore
        //   with an exported adjacency matrix.
        // For now, fall back to the built-in ratio-based scoring.
        BuiltinCoherence.compute_score(partition_id, graph)
    }

    fn backend_name(&self) -> &'static str {
        "ruvector-spectral-stub"
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::CoherenceGraph;

    fn pid(n: u32) -> PartitionId {
        PartitionId::new(n)
    }

    #[test]
    fn builtin_mincut_backend_name() {
        let backend = BuiltinMinCut::<8>::new(100);
        assert_eq!(backend.backend_name(), "stoer-wagner-builtin");
    }

    #[test]
    fn builtin_mincut_finds_cut() {
        let mut g = CoherenceGraph::<8, 32>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 100).unwrap();
        g.add_edge(pid(2), pid(1), 100).unwrap();

        let mut backend = BuiltinMinCut::<8>::new(100);
        let result = backend.find_min_cut(&g, pid(1));

        assert!(result.within_budget);
        assert_eq!(result.backend, "stoer-wagner-builtin");
        let total = result.left_count + result.right_count;
        assert_eq!(total, 2);
        assert!(result.cut_weight > 0);
    }

    #[test]
    fn builtin_coherence_backend_name() {
        let backend = BuiltinCoherence;
        assert_eq!(backend.backend_name(), "ratio-builtin");
    }

    #[test]
    fn builtin_coherence_isolated_partition() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();

        let backend = BuiltinCoherence;
        let score = backend.compute_score(pid(1), &g);
        assert_eq!(score, CoherenceScore::MAX);
    }

    #[test]
    fn builtin_coherence_external_edges() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 500).unwrap();

        let backend = BuiltinCoherence;
        let score = backend.compute_score(pid(1), &g);
        // All external => score = 0
        assert_eq!(score.as_basis_points(), 0);
    }

    #[cfg(feature = "ruvector")]
    #[test]
    fn ruvector_mincut_backend_name() {
        let backend = RuVectorMinCut::<8>::new(100);
        assert_eq!(backend.backend_name(), "ruvector-mincut-stub");
    }

    #[cfg(feature = "ruvector")]
    #[test]
    fn ruvector_mincut_falls_back_to_builtin() {
        let mut g = CoherenceGraph::<8, 32>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 100).unwrap();
        g.add_edge(pid(2), pid(1), 100).unwrap();

        let mut backend = RuVectorMinCut::<8>::new(100);
        let result = backend.find_min_cut(&g, pid(1));

        assert!(result.within_budget);
        assert_eq!(result.backend, "ruvector-mincut-stub");
        let total = result.left_count + result.right_count;
        assert_eq!(total, 2);
    }

    #[cfg(feature = "ruvector")]
    #[test]
    fn spectral_coherence_backend_name() {
        let backend = SpectralCoherence;
        assert_eq!(backend.backend_name(), "ruvector-spectral-stub");
    }

    #[cfg(feature = "ruvector")]
    #[test]
    fn spectral_coherence_falls_back_to_builtin() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 500).unwrap();

        let builtin = BuiltinCoherence;
        let spectral = SpectralCoherence;

        let builtin_score = builtin.compute_score(pid(1), &g);
        let spectral_score = spectral.compute_score(pid(1), &g);
        // Stub should produce identical results
        assert_eq!(builtin_score, spectral_score);
    }

    #[test]
    fn backend_mincut_result_empty() {
        let r = BackendMinCutResult::empty("test");
        assert_eq!(r.left_count, 0);
        assert_eq!(r.right_count, 0);
        assert_eq!(r.cut_weight, 0);
        assert!(r.within_budget);
        assert_eq!(r.backend, "test");
    }
}
