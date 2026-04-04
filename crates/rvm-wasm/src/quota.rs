//! Per-partition resource quotas for WASM agents.
//!
//! Each partition running WASM agents is subject to resource budgets
//! that are enforced per-epoch. When a partition exceeds its budget,
//! the lowest-priority agent is terminated.

use rvm_types::{PartitionId, RvmError, RvmResult};

/// Resource quotas for a single partition hosting WASM agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionQuota {
    /// Maximum CPU microseconds per scheduler epoch.
    pub max_cpu_us_per_epoch: u64,
    /// Maximum Wasm linear memory pages (64 KiB each).
    pub max_memory_pages: u32,
    /// Maximum IPC messages per epoch.
    pub max_ipc_per_epoch: u32,
    /// Maximum concurrent agents.
    pub max_agents: u16,
}

impl Default for PartitionQuota {
    fn default() -> Self {
        Self {
            max_cpu_us_per_epoch: 10_000, // 10 ms
            max_memory_pages: 256,         // 16 MiB
            max_ipc_per_epoch: 1024,
            max_agents: 32,
        }
    }
}

/// The type of resource being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// CPU time in microseconds.
    Cpu,
    /// Linear memory pages.
    Memory,
    /// IPC messages.
    Ipc,
    /// Concurrent agents.
    Agents,
}

/// Current resource usage for a partition.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceUsage {
    /// CPU microseconds consumed this epoch.
    pub cpu_us: u64,
    /// Memory pages currently allocated.
    pub memory_pages: u32,
    /// IPC messages sent this epoch.
    pub ipc_count: u32,
    /// Currently active agents.
    pub agent_count: u16,
}

/// A quota tracker for a fixed number of partitions.
pub struct QuotaTracker<const MAX: usize> {
    quotas: [Option<(PartitionId, PartitionQuota, ResourceUsage)>; MAX],
    count: usize,
}

impl<const MAX: usize> QuotaTracker<MAX> {
    /// Sentinel for array init.
    const NONE: Option<(PartitionId, PartitionQuota, ResourceUsage)> = None;

    /// Create an empty quota tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quotas: [Self::NONE; MAX],
            count: 0,
        }
    }

    /// Register a partition with the given quota.
    pub fn register(&mut self, partition: PartitionId, quota: PartitionQuota) -> RvmResult<()> {
        if self.count >= MAX {
            return Err(RvmError::ResourceLimitExceeded);
        }
        for slot in self.quotas.iter_mut() {
            if slot.is_none() {
                *slot = Some((partition, quota, ResourceUsage::default()));
                self.count += 1;
                return Ok(());
            }
        }
        Err(RvmError::InternalError)
    }

    /// Check whether a resource increment is within quota.
    ///
    /// Returns `Ok(())` if the requested amount is within budget,
    /// or `Err(ResourceLimitExceeded)` if it would exceed the quota.
    ///
    /// # Deprecation
    ///
    /// **Do not use `check_quota` followed by `record_usage`.** This two-step
    /// pattern is vulnerable to TOCTOU (time-of-check-to-time-of-use) races
    /// where a concurrent caller can pass the check before either records
    /// usage. Use [`check_and_record_cpu`], [`check_and_record_memory`], or
    /// [`check_and_record_ipc`] instead, which atomically check and record
    /// in a single step.
    #[deprecated(
        note = "Use check_and_record_cpu / check_and_record_memory / check_and_record_ipc instead (TOCTOU fix)"
    )]
    pub fn check_quota(
        &self,
        partition: PartitionId,
        resource: ResourceKind,
        amount: u64,
    ) -> RvmResult<()> {
        let (_, quota, usage) = self.find(partition)?;
        let within_budget = match resource {
            ResourceKind::Cpu => usage.cpu_us + amount <= quota.max_cpu_us_per_epoch,
            ResourceKind::Memory => (usage.memory_pages as u64) + amount <= quota.max_memory_pages as u64,
            ResourceKind::Ipc => (usage.ipc_count as u64) + amount <= quota.max_ipc_per_epoch as u64,
            ResourceKind::Agents => (usage.agent_count as u64) + amount <= quota.max_agents as u64,
        };

        if within_budget {
            Ok(())
        } else {
            Err(RvmError::ResourceLimitExceeded)
        }
    }

    /// Record resource consumption. Does not enforce -- caller should
    /// call `check_quota` first.
    ///
    /// # Deprecation
    ///
    /// **Do not use `record_usage` after `check_quota`.** This two-step
    /// pattern is vulnerable to TOCTOU races. Use the combined
    /// `check_and_record_*` methods instead.
    #[deprecated(
        note = "Use check_and_record_cpu / check_and_record_memory / check_and_record_ipc instead (TOCTOU fix)"
    )]
    pub fn record_usage(
        &mut self,
        partition: PartitionId,
        resource: ResourceKind,
        amount: u64,
    ) -> RvmResult<()> {
        let (_, _, usage) = self.find_mut(partition)?;
        match resource {
            ResourceKind::Cpu => usage.cpu_us = usage.cpu_us.saturating_add(amount),
            ResourceKind::Memory => {
                usage.memory_pages = usage.memory_pages.saturating_add(amount as u32);
            }
            ResourceKind::Ipc => {
                usage.ipc_count = usage.ipc_count.saturating_add(amount as u32);
            }
            ResourceKind::Agents => {
                usage.agent_count = usage.agent_count.saturating_add(amount as u16);
            }
        }
        Ok(())
    }

    /// Atomically check and record CPU usage in microseconds.
    ///
    /// If the requested amount would exceed the quota, no usage is
    /// recorded and `Err(ResourceLimitExceeded)` is returned. This
    /// eliminates the TOCTOU race in the deprecated `check_quota` +
    /// `record_usage` pattern.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if adding `us` would
    /// exceed the partition's CPU budget.
    /// Returns [`RvmError::PartitionNotFound`] if the partition is not registered.
    pub fn check_and_record_cpu(
        &mut self,
        partition: PartitionId,
        us: u64,
    ) -> RvmResult<()> {
        let (_, quota, usage) = self.find_mut(partition)?;
        if usage.cpu_us + us > quota.max_cpu_us_per_epoch {
            return Err(RvmError::ResourceLimitExceeded);
        }
        usage.cpu_us = usage.cpu_us.saturating_add(us);
        Ok(())
    }

    /// Atomically check and record memory page allocation.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if adding `pages` would
    /// exceed the partition's memory budget.
    /// Returns [`RvmError::PartitionNotFound`] if the partition is not registered.
    pub fn check_and_record_memory(
        &mut self,
        partition: PartitionId,
        pages: u32,
    ) -> RvmResult<()> {
        let (_, quota, usage) = self.find_mut(partition)?;
        if u64::from(usage.memory_pages) + u64::from(pages)
            > u64::from(quota.max_memory_pages)
        {
            return Err(RvmError::ResourceLimitExceeded);
        }
        usage.memory_pages = usage.memory_pages.saturating_add(pages);
        Ok(())
    }

    /// Atomically check and record one IPC message.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the IPC count would
    /// exceed the partition's per-epoch budget.
    /// Returns [`RvmError::PartitionNotFound`] if the partition is not registered.
    pub fn check_and_record_ipc(
        &mut self,
        partition: PartitionId,
    ) -> RvmResult<()> {
        let (_, quota, usage) = self.find_mut(partition)?;
        if u64::from(usage.ipc_count) + 1 > u64::from(quota.max_ipc_per_epoch) {
            return Err(RvmError::ResourceLimitExceeded);
        }
        usage.ipc_count = usage.ipc_count.saturating_add(1);
        Ok(())
    }

    /// Enforce quota by checking whether any resource is over budget.
    ///
    /// Returns `true` if the partition is over budget on any dimension.
    pub fn enforce_quota(&self, partition: PartitionId) -> RvmResult<bool> {
        let (_, quota, usage) = self.find(partition)?;
        let over = usage.cpu_us > quota.max_cpu_us_per_epoch
            || usage.memory_pages > quota.max_memory_pages
            || usage.ipc_count > quota.max_ipc_per_epoch
            || usage.agent_count > quota.max_agents;
        Ok(over)
    }

    /// Reset per-epoch counters (CPU and IPC) for all partitions.
    ///
    /// Called at the start of each scheduler epoch.
    pub fn reset_epoch_counters(&mut self) {
        for slot in self.quotas.iter_mut().flatten() {
            slot.2.cpu_us = 0;
            slot.2.ipc_count = 0;
        }
    }

    /// Return the current usage for a partition.
    pub fn usage(&self, partition: PartitionId) -> RvmResult<&ResourceUsage> {
        self.find(partition).map(|(_, _, u)| u)
    }

    fn find(
        &self,
        partition: PartitionId,
    ) -> RvmResult<&(PartitionId, PartitionQuota, ResourceUsage)> {
        for slot in &self.quotas {
            if let Some(entry) = slot {
                if entry.0 == partition {
                    return Ok(entry);
                }
            }
        }
        Err(RvmError::PartitionNotFound)
    }

    fn find_mut(
        &mut self,
        partition: PartitionId,
    ) -> RvmResult<&mut (PartitionId, PartitionQuota, ResourceUsage)> {
        for slot in self.quotas.iter_mut() {
            if let Some(entry) = slot {
                if entry.0 == partition {
                    return Ok(entry);
                }
            }
        }
        Err(RvmError::PartitionNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(id: u32) -> PartitionId {
        PartitionId::new(id)
    }

    #[test]
    fn test_register_and_check() {
        let mut tracker = QuotaTracker::<4>::new();
        let quota = PartitionQuota::default();
        tracker.register(pid(1), quota).unwrap();

        // Within budget.
        assert!(tracker.check_quota(pid(1), ResourceKind::Cpu, 5_000).is_ok());

        // Exceeds budget.
        assert_eq!(
            tracker.check_quota(pid(1), ResourceKind::Cpu, 20_000),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn test_record_usage() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        tracker.record_usage(pid(1), ResourceKind::Cpu, 3_000).unwrap();
        let usage = tracker.usage(pid(1)).unwrap();
        assert_eq!(usage.cpu_us, 3_000);

        // Now check remaining budget.
        assert!(tracker.check_quota(pid(1), ResourceKind::Cpu, 7_000).is_ok());
        assert_eq!(
            tracker.check_quota(pid(1), ResourceKind::Cpu, 7_001),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn test_enforce_quota() {
        let mut tracker = QuotaTracker::<4>::new();
        let quota = PartitionQuota {
            max_cpu_us_per_epoch: 100,
            ..PartitionQuota::default()
        };
        tracker.register(pid(1), quota).unwrap();

        assert!(!tracker.enforce_quota(pid(1)).unwrap());

        tracker.record_usage(pid(1), ResourceKind::Cpu, 101).unwrap();
        assert!(tracker.enforce_quota(pid(1)).unwrap());
    }

    #[test]
    fn test_reset_epoch_counters() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();
        tracker.record_usage(pid(1), ResourceKind::Cpu, 5_000).unwrap();
        tracker.record_usage(pid(1), ResourceKind::Ipc, 100).unwrap();
        tracker.record_usage(pid(1), ResourceKind::Memory, 10).unwrap();

        tracker.reset_epoch_counters();

        let usage = tracker.usage(pid(1)).unwrap();
        assert_eq!(usage.cpu_us, 0);
        assert_eq!(usage.ipc_count, 0);
        // Memory is not per-epoch, should persist.
        assert_eq!(usage.memory_pages, 10);
    }

    #[test]
    fn test_unknown_partition() {
        let tracker = QuotaTracker::<4>::new();
        assert_eq!(
            tracker.check_quota(pid(99), ResourceKind::Cpu, 1),
            Err(RvmError::PartitionNotFound)
        );
    }

    #[test]
    fn test_capacity_limit() {
        let mut tracker = QuotaTracker::<2>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();
        tracker.register(pid(2), PartitionQuota::default()).unwrap();
        assert_eq!(
            tracker.register(pid(3), PartitionQuota::default()),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    // ---------------------------------------------------------------
    // Atomic check_and_record_* tests (TOCTOU fix)
    // ---------------------------------------------------------------

    #[test]
    fn test_check_and_record_cpu_within_budget() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        // Default max is 10_000 us.
        tracker.check_and_record_cpu(pid(1), 5_000).unwrap();
        assert_eq!(tracker.usage(pid(1)).unwrap().cpu_us, 5_000);

        tracker.check_and_record_cpu(pid(1), 5_000).unwrap();
        assert_eq!(tracker.usage(pid(1)).unwrap().cpu_us, 10_000);
    }

    #[test]
    fn test_check_and_record_cpu_exceeds_budget() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        // This should fail because 10_001 > 10_000.
        assert_eq!(
            tracker.check_and_record_cpu(pid(1), 10_001),
            Err(RvmError::ResourceLimitExceeded)
        );
        // Usage should not have changed.
        assert_eq!(tracker.usage(pid(1)).unwrap().cpu_us, 0);
    }

    #[test]
    fn test_check_and_record_cpu_partial_then_exceed() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        tracker.check_and_record_cpu(pid(1), 8_000).unwrap();
        assert_eq!(
            tracker.check_and_record_cpu(pid(1), 2_001),
            Err(RvmError::ResourceLimitExceeded)
        );
        // Usage should remain at 8_000.
        assert_eq!(tracker.usage(pid(1)).unwrap().cpu_us, 8_000);
    }

    #[test]
    fn test_check_and_record_memory_within_budget() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        // Default max is 256 pages.
        tracker.check_and_record_memory(pid(1), 100).unwrap();
        assert_eq!(tracker.usage(pid(1)).unwrap().memory_pages, 100);

        tracker.check_and_record_memory(pid(1), 156).unwrap();
        assert_eq!(tracker.usage(pid(1)).unwrap().memory_pages, 256);
    }

    #[test]
    fn test_check_and_record_memory_exceeds_budget() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        assert_eq!(
            tracker.check_and_record_memory(pid(1), 257),
            Err(RvmError::ResourceLimitExceeded)
        );
        assert_eq!(tracker.usage(pid(1)).unwrap().memory_pages, 0);
    }

    #[test]
    fn test_check_and_record_ipc_within_budget() {
        let mut tracker = QuotaTracker::<4>::new();
        tracker.register(pid(1), PartitionQuota::default()).unwrap();

        // Default max is 1024.
        for _ in 0..1024 {
            tracker.check_and_record_ipc(pid(1)).unwrap();
        }
        assert_eq!(tracker.usage(pid(1)).unwrap().ipc_count, 1024);
    }

    #[test]
    fn test_check_and_record_ipc_exceeds_budget() {
        let mut tracker = QuotaTracker::<4>::new();
        let quota = PartitionQuota {
            max_ipc_per_epoch: 2,
            ..PartitionQuota::default()
        };
        tracker.register(pid(1), quota).unwrap();

        tracker.check_and_record_ipc(pid(1)).unwrap();
        tracker.check_and_record_ipc(pid(1)).unwrap();
        assert_eq!(
            tracker.check_and_record_ipc(pid(1)),
            Err(RvmError::ResourceLimitExceeded)
        );
        assert_eq!(tracker.usage(pid(1)).unwrap().ipc_count, 2);
    }

    #[test]
    fn test_check_and_record_unknown_partition() {
        let mut tracker = QuotaTracker::<4>::new();
        assert_eq!(
            tracker.check_and_record_cpu(pid(99), 1),
            Err(RvmError::PartitionNotFound)
        );
        assert_eq!(
            tracker.check_and_record_memory(pid(99), 1),
            Err(RvmError::PartitionNotFound)
        );
        assert_eq!(
            tracker.check_and_record_ipc(pid(99)),
            Err(RvmError::PartitionNotFound)
        );
    }
}
