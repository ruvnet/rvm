//! Global RVM configuration constants and defaults.

use crate::CoherenceScore;

/// Top-level RVM configuration.
#[derive(Debug, Clone, Copy)]
pub struct RvmConfig {
    /// Maximum partitions (DC-12).
    pub max_partitions: u16,
    /// Default coherence threshold.
    pub coherence_threshold: CoherenceScore,
    /// Witness ring buffer capacity in records.
    pub witness_ring_capacity: usize,
    /// Scheduler epoch interval in nanoseconds.
    pub epoch_interval_ns: u64,
}

impl Default for RvmConfig {
    fn default() -> Self {
        Self {
            max_partitions: 256,
            coherence_threshold: CoherenceScore::DEFAULT_THRESHOLD,
            witness_ring_capacity: 262_144,
            epoch_interval_ns: 10_000_000, // 10 ms
        }
    }
}
