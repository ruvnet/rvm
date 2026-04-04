//! Per-CPU scheduler state.

use crate::modes::SchedulerMode;
use rvm_types::PartitionId;

/// Per-CPU scheduler state.
///
/// Cache-line aligned (`align(64)`) to prevent false sharing between
/// CPUs when each has its own `PerCpuScheduler` in a contiguous array.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct PerCpuScheduler {
    /// CPU index.
    pub cpu_id: u16,
    /// Currently running partition (if any).
    pub current: Option<PartitionId>,
    /// Scheduler mode for this CPU.
    pub mode: SchedulerMode,
    /// Whether this CPU is idle.
    pub idle: bool,
}

impl PerCpuScheduler {
    /// Create a new per-CPU scheduler for the given CPU.
    #[must_use]
    pub const fn new(cpu_id: u16) -> Self {
        Self {
            cpu_id,
            current: None,
            mode: SchedulerMode::Flow,
            idle: true,
        }
    }
}
