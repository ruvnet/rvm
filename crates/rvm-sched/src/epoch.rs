//! Epoch tracking for bulk witness summaries.

/// Summary of a scheduler epoch for witness logging (DC-10).
#[derive(Debug, Clone, Copy)]
pub struct EpochSummary {
    /// Epoch number.
    pub epoch: u32,
    /// Number of context switches in this epoch.
    pub switch_count: u16,
    /// Number of runnable partitions.
    pub runnable_count: u16,
}

/// Tracks epoch boundaries for witness batching.
#[derive(Debug)]
pub struct EpochTracker {
    current_epoch: u32,
    switch_count: u16,
}

impl EpochTracker {
    /// Create a new epoch tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current_epoch: 0,
            switch_count: 0,
        }
    }

    /// Record a context switch.
    pub fn record_switch(&mut self) {
        self.switch_count = self.switch_count.saturating_add(1);
    }

    /// Advance to the next epoch, returning a summary of the completed one.
    pub fn advance(&mut self, runnable_count: u16) -> EpochSummary {
        let summary = EpochSummary {
            epoch: self.current_epoch,
            switch_count: self.switch_count,
            runnable_count,
        };
        self.current_epoch += 1;
        self.switch_count = 0;
        summary
    }

    /// Return the current epoch number.
    #[must_use]
    pub const fn current_epoch(&self) -> u32 {
        self.current_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_creation() {
        let tracker = EpochTracker::new();
        assert_eq!(tracker.current_epoch(), 0);
    }

    #[test]
    fn test_epoch_advance() {
        let mut tracker = EpochTracker::new();
        tracker.record_switch();
        tracker.record_switch();

        let summary = tracker.advance(3);
        assert_eq!(summary.epoch, 0);
        assert_eq!(summary.switch_count, 2);
        assert_eq!(summary.runnable_count, 3);
        assert_eq!(tracker.current_epoch(), 1);
    }

    #[test]
    fn test_epoch_summary_resets() {
        let mut tracker = EpochTracker::new();
        tracker.record_switch();
        let _ = tracker.advance(1);

        // After advance, switch count should be reset.
        let summary = tracker.advance(0);
        assert_eq!(summary.switch_count, 0);
    }
}
