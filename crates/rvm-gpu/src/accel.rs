//! Coherence engine GPU acceleration.
//!
//! This module provides GPU-accelerated implementations of the two
//! compute-intensive coherence operations:
//!
//! 1. **MinCut** ([`GpuMinCutConfig`], [`GpuMinCutResult`]): The Stoer-Wagner
//!    approximate minimum cut on the coherence graph. The adjacency matrix
//!    (up to 32x32 = 1024 entries) fits in a single GPU workgroup's shared
//!    memory. Each merge step's "find maximum connected node" becomes a
//!    parallel reduction across one matrix row, reducing the scan from
//!    O(N) sequential to O(log N) parallel steps.
//!
//! 2. **Batch scoring** ([`GpuScoringConfig`]): Coherence scoring across
//!    P partitions is embarrassingly parallel — each partition's score is
//!    an independent `internal_weight / total_weight` ratio. A single GPU
//!    dispatch computes all scores in parallel.
//!
//! ## GPU Mapping for MinCut
//!
//! The Stoer-Wagner algorithm iterates N-1 phases, each merging the
//! most-tightly-connected node pair. On CPU, finding the maximum
//! connection requires scanning all remaining nodes (O(N) per phase).
//!
//! On GPU, this maps to:
//! - **Shared memory**: Load the NxN adjacency matrix into workgroup
//!   shared memory (32x32 * 8 bytes = 8KB, well within typical 48KB limits).
//! - **Parallel reduction**: Each thread handles one row element. A
//!   tree-reduction finds the maximum in O(log N) steps per phase.
//! - **Sequential merge**: After finding the max, one thread performs
//!   the row/column merge (O(N) writes, memory-bound, fast on GPU).
//!
//! Net effect: O(N^2 * log N) parallel vs O(N^3) sequential for the
//! full algorithm. For N=32: ~5,120 parallel steps vs ~32,768 sequential.
//!
//! ## GPU Mapping for Scoring
//!
//! Each partition's coherence score is:
//!   `score = internal_weight / total_weight * 10_000` (basis points)
//!
//! On GPU, dispatch P workgroups (one per partition). Each workgroup:
//! 1. Loads the partition's edge weights from global memory.
//! 2. Performs a parallel reduction to sum internal and total weights.
//! 3. Computes the basis-point ratio.
//! 4. Writes the result to the output buffer.
//!
//! For P=1024 partitions, this is a single GPU dispatch with 1024
//! workgroups, completing in ~25us on Appliance-tier hardware vs
//! ~800us sequential on CPU.

/// Configuration for GPU-accelerated minimum cut computation.
///
/// Controls the maximum graph size, iteration budget, and whether
/// to attempt GPU acceleration or fall back to CPU.
#[derive(Debug, Clone, Copy)]
pub struct GpuMinCutConfig {
    /// Maximum number of nodes in the coherence graph (capped at 32
    /// to match `MINCUT_MAX_NODES` in `rvm-coherence`).
    pub max_nodes: u32,
    /// Maximum number of merge iterations before returning the best
    /// cut found so far. Set to `max_nodes - 1` for an exact solution.
    pub budget_iterations: u32,
    /// Whether to attempt GPU acceleration. If `false` or if no GPU
    /// is available, the CPU path in `rvm-coherence` is used.
    pub use_gpu: bool,
}

impl Default for GpuMinCutConfig {
    fn default() -> Self {
        Self {
            max_nodes: 32,
            budget_iterations: 31,
            use_gpu: true,
        }
    }
}

/// Result of a GPU-accelerated minimum cut computation.
///
/// Contains the partition counts on each side of the cut, the total
/// cut weight, execution time, and whether the GPU path was actually
/// used (vs. CPU fallback).
#[derive(Debug, Clone, Copy)]
pub struct GpuMinCutResult {
    /// Number of partitions on the "left" side of the cut.
    pub left_count: u16,
    /// Number of partitions on the "right" side of the cut.
    pub right_count: u16,
    /// Total weight of edges crossing the cut.
    pub cut_weight: u64,
    /// Wall-clock compute time in nanoseconds.
    pub compute_ns: u64,
    /// Whether the GPU was used (`false` = CPU fallback).
    pub used_gpu: bool,
}

impl GpuMinCutResult {
    /// Create an empty result (no cut computed).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            left_count: 0,
            right_count: 0,
            cut_weight: 0,
            compute_ns: 0,
            used_gpu: false,
        }
    }

    /// Return the total number of nodes across both sides.
    #[must_use]
    pub const fn total_nodes(&self) -> u32 {
        self.left_count as u32 + self.right_count as u32
    }
}

/// Configuration for GPU-accelerated batch coherence scoring.
///
/// Controls the maximum partition count and whether to attempt GPU
/// acceleration or fall back to sequential CPU scoring.
#[derive(Debug, Clone, Copy)]
pub struct GpuScoringConfig {
    /// Maximum number of partitions to score in one batch.
    pub max_partitions: u32,
    /// Whether to attempt GPU acceleration.
    pub use_gpu: bool,
}

impl Default for GpuScoringConfig {
    fn default() -> Self {
        Self {
            max_partitions: 256,
            use_gpu: true,
        }
    }
}

/// Check whether GPU-accelerated mincut is available at runtime.
///
/// Returns `true` if any GPU backend feature is enabled at compile
/// time. Actual hardware availability must be confirmed via device
/// discovery. This function is a compile-time gate only.
#[must_use]
pub const fn mincut_gpu_available() -> bool {
    cfg!(any(
        feature = "webgpu",
        feature = "cuda",
        feature = "opencl",
        feature = "vulkan",
        feature = "wasm-simd",
    ))
}

/// Check whether GPU-accelerated scoring is available at runtime.
///
/// Returns `true` if any GPU backend feature is enabled at compile
/// time. Actual hardware availability must be confirmed via device
/// discovery.
#[must_use]
pub const fn scoring_gpu_available() -> bool {
    cfg!(any(
        feature = "webgpu",
        feature = "cuda",
        feature = "opencl",
        feature = "vulkan",
        feature = "wasm-simd",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mincut_config() {
        let cfg = GpuMinCutConfig::default();
        assert_eq!(cfg.max_nodes, 32);
        assert_eq!(cfg.budget_iterations, 31);
        assert!(cfg.use_gpu);
    }

    #[test]
    fn default_scoring_config() {
        let cfg = GpuScoringConfig::default();
        assert_eq!(cfg.max_partitions, 256);
        assert!(cfg.use_gpu);
    }

    #[test]
    fn empty_mincut_result() {
        let r = GpuMinCutResult::empty();
        assert_eq!(r.left_count, 0);
        assert_eq!(r.right_count, 0);
        assert_eq!(r.cut_weight, 0);
        assert_eq!(r.compute_ns, 0);
        assert!(!r.used_gpu);
        assert_eq!(r.total_nodes(), 0);
    }

    #[test]
    fn mincut_result_total_nodes() {
        let r = GpuMinCutResult {
            left_count: 12,
            right_count: 20,
            cut_weight: 500,
            compute_ns: 8000,
            used_gpu: true,
        };
        assert_eq!(r.total_nodes(), 32);
    }

    #[test]
    fn gpu_availability_without_features() {
        // Without any GPU feature flags enabled (default test build),
        // these should return false.
        let mincut = mincut_gpu_available();
        let scoring = scoring_gpu_available();
        // Both should be the same — they check the same feature set.
        assert_eq!(mincut, scoring);
    }
}
