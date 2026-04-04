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
}
