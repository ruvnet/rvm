//! DMA and resource budget enforcement.
//!
//! Each partition is assigned resource quotas that limit CPU time,
//! memory usage, IPC rate, and DMA bandwidth. Budget checks are
//! performed before any resource allocation to prevent a single
//! partition from starving others.

use rvm_types::{RvmError, RvmResult};

/// DMA bandwidth budget for a single epoch.
///
/// Tracks how many bytes have been transferred via DMA within the
/// current epoch and enforces a per-epoch maximum.
#[derive(Debug, Clone, Copy)]
pub struct DmaBudget {
    /// Maximum DMA bytes allowed per epoch.
    pub max_bytes_per_epoch: u64,
    /// Bytes already used in the current epoch.
    pub used_bytes: u64,
}

impl DmaBudget {
    /// Create a new DMA budget with the given per-epoch maximum.
    #[must_use]
    pub const fn new(max_bytes_per_epoch: u64) -> Self {
        Self {
            max_bytes_per_epoch,
            used_bytes: 0,
        }
    }

    /// Check whether a DMA transfer of the requested size is allowed.
    ///
    /// If allowed, the budget is updated. If not, returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the transfer would exceed the budget.
    pub fn check_dma(&mut self, requested_bytes: u64) -> RvmResult<()> {
        if requested_bytes == 0 {
            return Ok(());
        }

        let new_total = self
            .used_bytes
            .checked_add(requested_bytes)
            .ok_or(RvmError::ResourceLimitExceeded)?;

        if new_total > self.max_bytes_per_epoch {
            return Err(RvmError::ResourceLimitExceeded);
        }

        self.used_bytes = new_total;
        Ok(())
    }

    /// Return the remaining DMA budget in bytes.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.max_bytes_per_epoch.saturating_sub(self.used_bytes)
    }

    /// Reset the budget for a new epoch.
    pub fn reset(&mut self) {
        self.used_bytes = 0;
    }

    /// Check whether the budget is exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.used_bytes >= self.max_bytes_per_epoch
    }
}

/// Resource quotas for a single partition.
///
/// Enforced per-epoch by the scheduler and security gate.
#[derive(Debug, Clone, Copy)]
pub struct ResourceQuota {
    /// Maximum CPU time in nanoseconds per epoch.
    pub cpu_time_ns: u64,
    /// CPU time consumed so far in this epoch.
    pub cpu_time_used_ns: u64,
    /// Maximum memory in bytes.
    pub memory_bytes: u64,
    /// Memory currently allocated.
    pub memory_used_bytes: u64,
    /// Maximum IPC messages per epoch.
    pub ipc_rate: u32,
    /// IPC messages sent so far in this epoch.
    pub ipc_used: u32,
    /// DMA bandwidth budget.
    pub dma: DmaBudget,
}

impl ResourceQuota {
    /// Create a new resource quota with the given limits.
    #[must_use]
    pub const fn new(
        cpu_time_ns: u64,
        memory_bytes: u64,
        ipc_rate: u32,
        dma_max_bytes: u64,
    ) -> Self {
        Self {
            cpu_time_ns,
            cpu_time_used_ns: 0,
            memory_bytes,
            memory_used_bytes: 0,
            ipc_rate,
            ipc_used: 0,
            dma: DmaBudget::new(dma_max_bytes),
        }
    }

    /// Check whether CPU time budget allows the requested duration.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the request would exceed the budget.
    pub fn check_cpu_time(&mut self, requested_ns: u64) -> RvmResult<()> {
        let new_total = self
            .cpu_time_used_ns
            .checked_add(requested_ns)
            .ok_or(RvmError::ResourceLimitExceeded)?;

        if new_total > self.cpu_time_ns {
            return Err(RvmError::ResourceLimitExceeded);
        }

        self.cpu_time_used_ns = new_total;
        Ok(())
    }

    /// Check whether memory budget allows the requested allocation.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::OutOfMemory`] if the request would exceed the budget.
    pub fn check_memory(&mut self, requested_bytes: u64) -> RvmResult<()> {
        let new_total = self
            .memory_used_bytes
            .checked_add(requested_bytes)
            .ok_or(RvmError::OutOfMemory)?;

        if new_total > self.memory_bytes {
            return Err(RvmError::OutOfMemory);
        }

        self.memory_used_bytes = new_total;
        Ok(())
    }

    /// Check whether the IPC rate allows another message.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the IPC rate limit is reached.
    pub fn check_ipc(&mut self) -> RvmResult<()> {
        if self.ipc_used >= self.ipc_rate {
            return Err(RvmError::ResourceLimitExceeded);
        }
        self.ipc_used += 1;
        Ok(())
    }

    /// Release previously allocated memory back to the quota.
    pub fn release_memory(&mut self, bytes: u64) {
        self.memory_used_bytes = self.memory_used_bytes.saturating_sub(bytes);
    }

    /// Reset per-epoch counters (CPU time, IPC, DMA) for a new epoch.
    pub fn reset_epoch(&mut self) {
        self.cpu_time_used_ns = 0;
        self.ipc_used = 0;
        self.dma.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DMA Budget tests ---

    #[test]
    fn test_dma_budget_allows_within_limit() {
        let mut budget = DmaBudget::new(1000);
        assert!(budget.check_dma(500).is_ok());
        assert_eq!(budget.remaining(), 500);
        assert!(budget.check_dma(500).is_ok());
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn test_dma_budget_denies_over_limit() {
        let mut budget = DmaBudget::new(1000);
        budget.check_dma(500).unwrap();
        assert_eq!(
            budget.check_dma(501),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn test_dma_budget_zero_request() {
        let mut budget = DmaBudget::new(1000);
        assert!(budget.check_dma(0).is_ok());
        assert_eq!(budget.used_bytes, 0);
    }

    #[test]
    fn test_dma_budget_reset() {
        let mut budget = DmaBudget::new(1000);
        budget.check_dma(1000).unwrap();
        assert!(budget.is_exhausted());
        budget.reset();
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining(), 1000);
    }

    #[test]
    fn test_dma_budget_overflow() {
        let mut budget = DmaBudget::new(u64::MAX);
        budget.check_dma(u64::MAX - 1).unwrap();
        assert_eq!(
            budget.check_dma(2),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    // --- Resource Quota tests ---

    #[test]
    fn test_quota_cpu_time() {
        let mut quota = ResourceQuota::new(1_000_000, 0, 0, 0);
        assert!(quota.check_cpu_time(500_000).is_ok());
        assert!(quota.check_cpu_time(500_000).is_ok());
        assert_eq!(
            quota.check_cpu_time(1),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn test_quota_memory() {
        let mut quota = ResourceQuota::new(0, 4096, 0, 0);
        assert!(quota.check_memory(2048).is_ok());
        assert!(quota.check_memory(2048).is_ok());
        assert_eq!(quota.check_memory(1), Err(RvmError::OutOfMemory));
    }

    #[test]
    fn test_quota_memory_release() {
        let mut quota = ResourceQuota::new(0, 4096, 0, 0);
        quota.check_memory(4096).unwrap();
        assert_eq!(quota.check_memory(1), Err(RvmError::OutOfMemory));
        quota.release_memory(1024);
        assert!(quota.check_memory(1024).is_ok());
    }

    #[test]
    fn test_quota_ipc_rate() {
        let mut quota = ResourceQuota::new(0, 0, 3, 0);
        assert!(quota.check_ipc().is_ok());
        assert!(quota.check_ipc().is_ok());
        assert!(quota.check_ipc().is_ok());
        assert_eq!(quota.check_ipc(), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn test_quota_dma() {
        let mut quota = ResourceQuota::new(0, 0, 0, 1000);
        assert!(quota.dma.check_dma(500).is_ok());
        assert!(quota.dma.check_dma(500).is_ok());
        assert_eq!(
            quota.dma.check_dma(1),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn test_quota_epoch_reset() {
        let mut quota = ResourceQuota::new(1000, 4096, 2, 500);
        quota.check_cpu_time(1000).unwrap();
        quota.check_ipc().unwrap();
        quota.check_ipc().unwrap();
        quota.dma.check_dma(500).unwrap();

        // All per-epoch limits exhausted
        assert_eq!(
            quota.check_cpu_time(1),
            Err(RvmError::ResourceLimitExceeded)
        );
        assert_eq!(quota.check_ipc(), Err(RvmError::ResourceLimitExceeded));
        assert_eq!(
            quota.dma.check_dma(1),
            Err(RvmError::ResourceLimitExceeded)
        );

        // Reset epoch — CPU, IPC, DMA should be available again
        quota.reset_epoch();
        assert!(quota.check_cpu_time(500).is_ok());
        assert!(quota.check_ipc().is_ok());
        assert!(quota.dma.check_dma(250).is_ok());

        // Memory is NOT reset by epoch
        // (already allocated 0, so still under limit)
    }

    #[test]
    fn test_quota_memory_not_reset_by_epoch() {
        let mut quota = ResourceQuota::new(0, 4096, 0, 0);
        quota.check_memory(4096).unwrap();
        quota.reset_epoch();
        // Memory should still be fully used
        assert_eq!(quota.check_memory(1), Err(RvmError::OutOfMemory));
    }
}
