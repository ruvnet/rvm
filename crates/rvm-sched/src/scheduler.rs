//! Main scheduler: ties together per-CPU schedulers, epoch management,
//! mode selection, and degraded mode handling.

use crate::epoch::{EpochSummary, EpochTracker};
use crate::modes::SchedulerMode;
use crate::per_cpu::PerCpuScheduler;
use crate::priority::compute_priority;
use rvm_types::{CutPressure, PartitionId};

/// Maximum entries in a per-CPU run queue.
pub const MAX_RUN_QUEUE: usize = 32;

/// An entry in a per-CPU run queue.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RunQueueEntry {
    /// Partition identifier.
    pub partition_id: PartitionId,
    /// Deadline urgency (higher = more urgent).
    pub deadline_urgency: u16,
    /// Cut pressure from the coherence engine.
    pub cut_pressure: CutPressure,
    /// Computed priority (cached).
    pub priority: u32,
}

/// The top-level scheduler for all CPUs.
///
/// # Type Parameters
///
/// * `MAX_CPUS` - Maximum number of physical CPUs.
/// * `MAX_PARTITIONS` - Maximum number of partitions in the system.
pub struct Scheduler<const MAX_CPUS: usize, const MAX_PARTITIONS: usize> {
    /// Per-CPU scheduler metadata.
    per_cpu: [PerCpuScheduler; MAX_CPUS],
    /// Per-CPU run queues.
    run_queues: [[Option<RunQueueEntry>; MAX_RUN_QUEUE]; MAX_CPUS],
    /// Per-CPU run queue lengths.
    queue_lens: [usize; MAX_CPUS],
    /// Current scheduling mode.
    mode: SchedulerMode,
    /// Epoch tracker.
    epoch: EpochTracker,
    /// Whether the system is in degraded mode (DC-6).
    degraded: bool,
}

impl<const MAX_CPUS: usize, const MAX_PARTITIONS: usize> Scheduler<MAX_CPUS, MAX_PARTITIONS> {
    /// Sentinel value.
    const NONE_ENTRY: Option<RunQueueEntry> = None;
    /// Empty run queue.
    const EMPTY_QUEUE: [Option<RunQueueEntry>; MAX_RUN_QUEUE] = [Self::NONE_ENTRY; MAX_RUN_QUEUE];

    /// Create a new scheduler in Flow mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_cpu: core::array::from_fn(|i| PerCpuScheduler::new(i as u16)),
            run_queues: [Self::EMPTY_QUEUE; MAX_CPUS],
            queue_lens: [0; MAX_CPUS],
            mode: SchedulerMode::Flow,
            epoch: EpochTracker::new(),
            degraded: false,
        }
    }

    /// Return the current scheduling mode.
    #[must_use]
    pub const fn mode(&self) -> SchedulerMode {
        self.mode
    }

    /// Switch to a new scheduling mode.
    pub fn set_mode(&mut self, mode: SchedulerMode) {
        self.mode = mode;
    }

    /// Return the current epoch number.
    #[must_use]
    pub const fn current_epoch(&self) -> u32 {
        self.epoch.current_epoch()
    }

    /// Return whether the system is in degraded mode.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Enter degraded mode (DC-6). In degraded mode, cut_pressure = 0.
    pub fn enter_degraded(&mut self) {
        self.degraded = true;
    }

    /// Exit degraded mode.
    pub fn exit_degraded(&mut self) {
        self.degraded = false;
    }

    /// Advance the scheduler epoch. Returns the completed epoch summary.
    pub fn tick_epoch(&mut self) -> EpochSummary {
        let runnable: u16 = self.queue_lens.iter().map(|&l| l as u16).sum();
        self.epoch.advance(runnable)
    }

    /// Enqueue a partition on a specific CPU.
    ///
    /// In degraded mode (DC-6), `cut_pressure` is zeroed automatically.
    pub fn enqueue(
        &mut self,
        cpu: usize,
        partition_id: PartitionId,
        deadline_urgency: u16,
        cut_pressure: CutPressure,
    ) -> bool {
        if cpu >= MAX_CPUS || self.queue_lens[cpu] >= MAX_RUN_QUEUE {
            return false;
        }

        let effective_pressure = if self.degraded {
            CutPressure::ZERO
        } else {
            cut_pressure
        };

        let priority = compute_priority(deadline_urgency, effective_pressure);
        let entry = RunQueueEntry {
            partition_id,
            deadline_urgency,
            cut_pressure: effective_pressure,
            priority,
        };

        // Insert maintaining sorted order (highest priority first).
        let len = self.queue_lens[cpu];
        let queue = &mut self.run_queues[cpu];

        let mut insert_pos = len;
        for i in 0..len {
            if let Some(ref existing) = queue[i] {
                if priority > existing.priority {
                    insert_pos = i;
                    break;
                }
            }
        }

        // Shift entries down.
        let mut i = len;
        while i > insert_pos {
            queue[i] = queue[i - 1];
            i -= 1;
        }

        queue[insert_pos] = Some(entry);
        self.queue_lens[cpu] += 1;
        true
    }

    /// Pick the next partition on a specific CPU and switch to it.
    ///
    /// Returns `(old_partition, new_partition)` if a switch occurred.
    pub fn switch_next(&mut self, cpu: usize) -> Option<(Option<PartitionId>, PartitionId)> {
        if cpu >= MAX_CPUS || self.queue_lens[cpu] == 0 {
            return None;
        }

        let queue = &mut self.run_queues[cpu];
        let entry = queue[0].take()?;

        // Shift entries up.
        let len = self.queue_lens[cpu];
        for i in 0..len - 1 {
            queue[i] = queue[i + 1];
        }
        queue[len - 1] = None;
        self.queue_lens[cpu] -= 1;

        let old = self.per_cpu[cpu].current;
        self.per_cpu[cpu].current = Some(entry.partition_id);
        self.per_cpu[cpu].idle = false;
        self.epoch.record_switch();

        Some((old, entry.partition_id))
    }

    /// Return a reference to the per-CPU scheduler for the given CPU.
    #[must_use]
    pub fn per_cpu(&self, cpu: usize) -> Option<&PerCpuScheduler> {
        self.per_cpu.get(cpu)
    }

    /// Return the run queue length for a specific CPU.
    #[must_use]
    pub fn queue_len(&self, cpu: usize) -> usize {
        self.queue_lens.get(cpu).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(id: u32) -> PartitionId {
        PartitionId::new(id)
    }

    #[test]
    fn test_scheduler_creation() {
        let sched: Scheduler<4, 256> = Scheduler::new();
        assert_eq!(sched.mode(), SchedulerMode::Flow);
        assert!(!sched.is_degraded());
        assert_eq!(sched.current_epoch(), 0);
    }

    #[test]
    fn test_mode_switch() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        sched.set_mode(SchedulerMode::Reflex);
        assert_eq!(sched.mode(), SchedulerMode::Reflex);
        sched.set_mode(SchedulerMode::Recovery);
        assert_eq!(sched.mode(), SchedulerMode::Recovery);
    }

    #[test]
    fn test_enqueue_and_switch() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        assert!(sched.enqueue(0, pid(1), 100, CutPressure::ZERO));
        assert!(sched.enqueue(0, pid(2), 200, CutPressure::ZERO));

        // Should switch to pid(2) which has higher deadline urgency.
        let (old, new) = sched.switch_next(0).unwrap();
        assert!(old.is_none());
        assert_eq!(new, pid(2));
    }

    #[test]
    fn test_degraded_mode_zeroes_pressure() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        sched.enter_degraded();

        // In degraded mode, cut_pressure is zeroed.
        let high_pressure = CutPressure::from_fixed(u32::MAX);
        sched.enqueue(0, pid(1), 100, high_pressure); // effective pressure = 0
        sched.enqueue(0, pid(2), 150, CutPressure::ZERO);

        // pid(2) should win because 150 > 100 (pressure zeroed).
        let (_, new) = sched.switch_next(0).unwrap();
        assert_eq!(new, pid(2));
    }

    #[test]
    fn test_degraded_mode_deadline_only() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        sched.enter_degraded();

        sched.enqueue(0, pid(1), 50, CutPressure::ZERO);
        sched.enqueue(0, pid(2), 200, CutPressure::ZERO);

        // In degraded mode, priority = deadline_urgency only.
        let (_, new) = sched.switch_next(0).unwrap();
        assert_eq!(new, pid(2));
    }

    #[test]
    fn test_epoch_tick() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        sched.enqueue(0, pid(1), 100, CutPressure::ZERO);
        sched.switch_next(0);

        let summary = sched.tick_epoch();
        assert_eq!(summary.epoch, 0);
        assert_eq!(summary.switch_count, 1);
        assert_eq!(sched.current_epoch(), 1);
    }

    #[test]
    fn test_epoch_summary_degraded() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        sched.enter_degraded();
        let summary = sched.tick_epoch();
        assert_eq!(summary.switch_count, 0);
    }

    #[test]
    fn test_invalid_cpu() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        assert!(!sched.enqueue(99, pid(1), 100, CutPressure::ZERO));
        assert!(sched.switch_next(99).is_none());
    }

    #[test]
    fn test_queue_full() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        for i in 0..MAX_RUN_QUEUE {
            assert!(sched.enqueue(0, pid(i as u32), 100, CutPressure::ZERO));
        }
        // Queue is full.
        assert!(!sched.enqueue(0, pid(999), 100, CutPressure::ZERO));
    }

    #[test]
    fn test_priority_ordering() {
        let mut sched: Scheduler<4, 256> = Scheduler::new();
        sched.enqueue(0, pid(1), 50, CutPressure::ZERO);
        sched.enqueue(0, pid(2), 100, CutPressure::ZERO);
        sched.enqueue(0, pid(3), 75, CutPressure::ZERO);

        // Should dequeue in priority order: 100, 75, 50.
        let (_, first) = sched.switch_next(0).unwrap();
        assert_eq!(first, pid(2));

        let (_, second) = sched.switch_next(0).unwrap();
        assert_eq!(second, pid(3));

        let (_, third) = sched.switch_next(0).unwrap();
        assert_eq!(third, pid(1));
    }
}
