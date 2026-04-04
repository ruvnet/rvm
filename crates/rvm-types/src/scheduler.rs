//! Scheduler types.

/// Scheduler operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// Reflex mode: real-time, latency-sensitive.
    Reflex,
    /// Flow mode: throughput-optimized.
    Flow,
    /// Recovery mode: degraded, single-partition.
    Recovery,
}

/// Priority level for scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(u8);

impl Priority {
    /// Highest priority.
    pub const MAX: Self = Self(255);
    /// Lowest priority.
    pub const MIN: Self = Self(0);
    /// Default priority.
    pub const DEFAULT: Self = Self(128);

    /// Create a new priority value.
    #[must_use]
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    /// Return the raw priority value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// Configuration for a scheduler epoch.
#[derive(Debug, Clone, Copy)]
pub struct EpochConfig {
    /// Epoch interval in nanoseconds.
    pub interval_ns: u64,
    /// Maximum partitions to switch per epoch.
    pub max_switches: u16,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            interval_ns: 10_000_000, // 10 ms
            max_switches: 64,
        }
    }
}

/// Summary of a scheduler epoch for witness logging.
#[derive(Debug, Clone, Copy)]
pub struct EpochSummary {
    /// Epoch number.
    pub epoch: u32,
    /// Number of context switches in this epoch.
    pub switch_count: u16,
    /// Total partitions that were runnable.
    pub runnable_count: u16,
}
