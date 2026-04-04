//! Adaptive coherence recomputation engine (ADR-139).
//!
//! Adjusts the frequency of coherence recomputation based on an
//! externally reported CPU load estimate. Under high load, coherence
//! is recomputed less frequently to stay within the epoch time budget.
//!
//! | Load Range    | Recomputation Frequency |
//! |---------------|------------------------|
//! | > 80%         | Every 4th epoch        |
//! | 60% .. 80%    | Every 2nd epoch        |
//! | < 30%         | Every epoch            |
//! | 30% .. 60%    | Every epoch            |

/// CPU load thresholds (in percent, 0..100).
const LOAD_HIGH: u8 = 80;
/// Medium-high load threshold.
const LOAD_MEDIUM: u8 = 60;

/// Recomputation interval at high load.
const INTERVAL_HIGH: u32 = 4;
/// Recomputation interval at medium load.
const INTERVAL_MEDIUM: u32 = 2;
/// Recomputation interval at low/normal load.
const INTERVAL_LOW: u32 = 1;

/// Adaptive coherence recomputation engine.
///
/// Tracks epoch progression and determines whether coherence should
/// be recomputed on the current epoch based on CPU load.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveCoherenceEngine {
    /// Last epoch at which coherence was actually computed.
    last_compute_epoch: u32,
    /// Total number of successful coherence computations.
    pub compute_count: u32,
    /// Number of times the mincut budget was exceeded.
    pub budget_exceeded_count: u32,
    /// Current recomputation interval (1 = every epoch, 4 = every 4th).
    current_interval: u32,
    /// Current epoch.
    current_epoch: u32,
}

impl AdaptiveCoherenceEngine {
    /// Create a new adaptive engine starting at epoch 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_compute_epoch: 0,
            compute_count: 0,
            budget_exceeded_count: 0,
            current_interval: INTERVAL_LOW,
            current_epoch: 0,
        }
    }

    /// Current epoch number.
    #[must_use]
    pub const fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    /// Last epoch at which coherence was computed.
    #[must_use]
    pub const fn last_compute_epoch(&self) -> u32 {
        self.last_compute_epoch
    }

    /// Current recomputation interval.
    #[must_use]
    pub const fn current_interval(&self) -> u32 {
        self.current_interval
    }

    /// Advance to the next epoch and determine whether coherence should
    /// be recomputed, given the current CPU load (0..100).
    ///
    /// Returns `true` if coherence should be recomputed this epoch.
    pub fn tick(&mut self, cpu_load_percent: u8) -> bool {
        self.current_epoch = self.current_epoch.wrapping_add(1);

        // Adjust interval based on load
        self.current_interval = if cpu_load_percent > LOAD_HIGH {
            INTERVAL_HIGH
        } else if cpu_load_percent > LOAD_MEDIUM {
            INTERVAL_MEDIUM
        } else {
            INTERVAL_LOW
        };

        // Always compute on the first epoch (no prior computation exists).
        if self.compute_count == 0 {
            return true;
        }

        // Determine if enough epochs have elapsed since the last computation.
        let epochs_since_last = self.current_epoch.wrapping_sub(self.last_compute_epoch);
        epochs_since_last >= self.current_interval
    }

    /// Record that a coherence computation was performed this epoch.
    pub fn record_computation(&mut self) {
        self.last_compute_epoch = self.current_epoch;
        self.compute_count += 1;
    }

    /// Record that a computation exceeded its time budget.
    pub fn record_budget_exceeded(&mut self) {
        self.budget_exceeded_count += 1;
    }

    /// Compute the duty cycle: fraction of epochs that trigger recomputation.
    /// Returns basis points (0..10000).
    #[must_use]
    pub const fn duty_cycle_bp(&self) -> u16 {
        if self.current_interval == 0 {
            return 10_000;
        }
        (10_000 / self.current_interval) as u16
    }

    /// Reset all counters (useful for testing or recalibration).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_epoch_zero() {
        let engine = AdaptiveCoherenceEngine::new();
        assert_eq!(engine.current_epoch(), 0);
        assert_eq!(engine.last_compute_epoch(), 0);
        assert_eq!(engine.compute_count, 0);
    }

    #[test]
    fn low_load_computes_every_epoch() {
        let mut engine = AdaptiveCoherenceEngine::new();

        // At 20% load, should compute every epoch
        assert!(engine.tick(20));
        engine.record_computation();
        assert!(engine.tick(20));
        engine.record_computation();
        assert!(engine.tick(20));
        engine.record_computation();

        assert_eq!(engine.compute_count, 3);
        assert_eq!(engine.current_interval(), INTERVAL_LOW);
    }

    #[test]
    fn medium_load_skips_every_other_epoch() {
        let mut engine = AdaptiveCoherenceEngine::new();

        // Epoch 1: 70% load, should compute (first epoch after 0)
        assert!(engine.tick(70));
        engine.record_computation();
        assert_eq!(engine.current_interval(), INTERVAL_MEDIUM);

        // Epoch 2: still 70%, should skip (only 1 epoch since last)
        assert!(!engine.tick(70));

        // Epoch 3: still 70%, should compute (2 epochs since last)
        assert!(engine.tick(70));
        engine.record_computation();

        assert_eq!(engine.compute_count, 2);
    }

    #[test]
    fn high_load_skips_three_out_of_four() {
        let mut engine = AdaptiveCoherenceEngine::new();

        // Epoch 1: 90% load, should compute (first epoch)
        assert!(engine.tick(90));
        engine.record_computation();
        assert_eq!(engine.current_interval(), INTERVAL_HIGH);

        // Epochs 2, 3, 4: should skip
        assert!(!engine.tick(90));
        assert!(!engine.tick(90));
        assert!(!engine.tick(90));

        // Epoch 5: should compute (4 epochs since last)
        assert!(engine.tick(90));
        engine.record_computation();

        assert_eq!(engine.compute_count, 2);
    }

    #[test]
    fn load_transition_adjusts_interval() {
        let mut engine = AdaptiveCoherenceEngine::new();

        // Start at low load
        assert!(engine.tick(10));
        engine.record_computation();
        assert_eq!(engine.current_interval(), INTERVAL_LOW);

        // Jump to high load
        assert!(!engine.tick(90)); // only 1 epoch since last, interval now 4
        assert_eq!(engine.current_interval(), INTERVAL_HIGH);

        // Skip 2 more
        assert!(!engine.tick(90));

        // 3 epochs since last, interval is 4, so still skip
        assert!(!engine.tick(90));

        // Now 4 epochs since last -- should compute
        // Wait, we ticked: epoch 2 (skip), 3 (skip), 4 (skip), 5 should trigger
        assert!(engine.tick(90));
        engine.record_computation();
    }

    #[test]
    fn budget_exceeded_tracking() {
        let mut engine = AdaptiveCoherenceEngine::new();
        engine.record_budget_exceeded();
        engine.record_budget_exceeded();
        assert_eq!(engine.budget_exceeded_count, 2);
    }

    #[test]
    fn duty_cycle_reflects_interval() {
        let mut engine = AdaptiveCoherenceEngine::new();

        engine.tick(10); // low load
        assert_eq!(engine.duty_cycle_bp(), 10_000); // 100%

        engine.tick(70); // medium load
        assert_eq!(engine.duty_cycle_bp(), 5_000); // 50%

        engine.tick(90); // high load
        assert_eq!(engine.duty_cycle_bp(), 2_500); // 25%
    }

    #[test]
    fn reset_clears_state() {
        let mut engine = AdaptiveCoherenceEngine::new();
        engine.tick(50);
        engine.record_computation();
        engine.record_budget_exceeded();

        engine.reset();
        assert_eq!(engine.current_epoch(), 0);
        assert_eq!(engine.compute_count, 0);
        assert_eq!(engine.budget_exceeded_count, 0);
    }
}
