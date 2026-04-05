//! GPU-specific resource quota enforcement.
//!
//! Each partition has a [`GpuBudget`] that limits GPU compute time,
//! memory allocation, transfer bandwidth, and kernel launch count
//! per scheduler epoch. This mirrors the [`DmaBudget`] pattern from
//! `rvm-security/src/budget.rs` but adds GPU-specific dimensions.
//!
//! All `check_*` methods verify that a request fits within the remaining
//! quota before allowing the operation. All `record_*` methods update
//! usage counters after a successful operation. The [`reset_epoch`]
//! method zeroes per-epoch counters (compute, transfer, launches)
//! while preserving the memory allocation high-water mark.

use rvm_types::{RvmError, RvmResult};

/// GPU resource quota for a single partition within one epoch.
///
/// Budget checks run before every GPU operation. If any quota is
/// exceeded, the operation is rejected with [`RvmError::ResourceLimitExceeded`].
/// Memory is a persistent allocation (not reset per epoch); compute time,
/// transfer bandwidth, and launch count are per-epoch.
#[derive(Debug, Clone, Copy)]
pub struct GpuBudget {
    /// Maximum GPU compute time per epoch in nanoseconds.
    pub compute_ns_max: u64,
    /// GPU compute time consumed in the current epoch.
    pub compute_ns_used: u64,
    /// Maximum GPU memory allocation in bytes (persistent across epochs).
    pub memory_bytes_max: u64,
    /// GPU memory currently allocated in bytes.
    pub memory_bytes_used: u64,
    /// Maximum host-device transfer bandwidth per epoch in bytes.
    pub transfer_bytes_max: u64,
    /// Transfer bandwidth consumed in the current epoch.
    pub transfer_bytes_used: u64,
    /// Maximum kernel launches per epoch.
    pub kernel_launches_max: u32,
    /// Kernel launches consumed in the current epoch.
    pub kernel_launches_used: u32,
}

impl GpuBudget {
    /// Create a new GPU budget with the given per-epoch limits.
    ///
    /// All usage counters start at zero.
    #[must_use]
    pub const fn new(
        compute_ns_max: u64,
        memory_bytes_max: u64,
        transfer_bytes_max: u64,
        kernel_launches_max: u32,
    ) -> Self {
        Self {
            compute_ns_max,
            compute_ns_used: 0,
            memory_bytes_max,
            memory_bytes_used: 0,
            transfer_bytes_max,
            transfer_bytes_used: 0,
            kernel_launches_max,
            kernel_launches_used: 0,
        }
    }

    /// Check whether the compute time budget allows the requested duration.
    ///
    /// Does NOT record — call [`record_compute`](Self::record_compute) after
    /// the kernel completes.
    pub fn check_compute(&self, requested_ns: u64) -> RvmResult<()> {
        if requested_ns == 0 {
            return Ok(());
        }
        let new_total = self
            .compute_ns_used
            .checked_add(requested_ns)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if new_total > self.compute_ns_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        Ok(())
    }

    /// Check whether the memory budget allows the requested allocation.
    pub fn check_memory(&self, requested_bytes: u64) -> RvmResult<()> {
        if requested_bytes == 0 {
            return Ok(());
        }
        let new_total = self
            .memory_bytes_used
            .checked_add(requested_bytes)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if new_total > self.memory_bytes_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        Ok(())
    }

    /// Check whether the transfer budget allows the requested byte count.
    pub fn check_transfer(&self, requested_bytes: u64) -> RvmResult<()> {
        if requested_bytes == 0 {
            return Ok(());
        }
        let new_total = self
            .transfer_bytes_used
            .checked_add(requested_bytes)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if new_total > self.transfer_bytes_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        Ok(())
    }

    /// Check whether the kernel launch budget allows another launch.
    pub fn check_launch(&self) -> RvmResult<()> {
        if self.kernel_launches_used >= self.kernel_launches_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        Ok(())
    }

    /// Record consumed compute time after a kernel completes.
    pub fn record_compute(&mut self, elapsed_ns: u64) -> RvmResult<()> {
        let new_total = self
            .compute_ns_used
            .checked_add(elapsed_ns)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if new_total > self.compute_ns_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        self.compute_ns_used = new_total;
        Ok(())
    }

    /// Record allocated GPU memory.
    pub fn record_memory(&mut self, allocated_bytes: u64) -> RvmResult<()> {
        let new_total = self
            .memory_bytes_used
            .checked_add(allocated_bytes)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if new_total > self.memory_bytes_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        self.memory_bytes_used = new_total;
        Ok(())
    }

    /// Record transferred bytes (host-device or device-host).
    pub fn record_transfer(&mut self, transferred_bytes: u64) -> RvmResult<()> {
        let new_total = self
            .transfer_bytes_used
            .checked_add(transferred_bytes)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if new_total > self.transfer_bytes_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        self.transfer_bytes_used = new_total;
        Ok(())
    }

    /// Record a kernel launch.
    pub fn record_launch(&mut self) -> RvmResult<()> {
        if self.kernel_launches_used >= self.kernel_launches_max {
            return Err(RvmError::ResourceLimitExceeded);
        }
        self.kernel_launches_used += 1;
        Ok(())
    }

    /// Reset per-epoch counters (compute, transfer, launches).
    ///
    /// Memory allocation is persistent and NOT reset — it reflects
    /// currently held allocations, not per-epoch consumption.
    pub fn reset_epoch(&mut self) {
        self.compute_ns_used = 0;
        self.transfer_bytes_used = 0;
        self.kernel_launches_used = 0;
    }

    /// Return the remaining compute budget in nanoseconds.
    #[must_use]
    pub const fn remaining_compute(&self) -> u64 {
        self.compute_ns_max.saturating_sub(self.compute_ns_used)
    }

    /// Return the remaining memory budget in bytes.
    #[must_use]
    pub const fn remaining_memory(&self) -> u64 {
        self.memory_bytes_max.saturating_sub(self.memory_bytes_used)
    }

    /// Return the remaining transfer budget in bytes.
    #[must_use]
    pub const fn remaining_transfer(&self) -> u64 {
        self.transfer_bytes_max.saturating_sub(self.transfer_bytes_used)
    }

    /// Check whether all per-epoch budgets are exhausted.
    ///
    /// Returns `true` if compute, transfer, AND launches are all at
    /// their limits. Memory exhaustion alone does not count because
    /// existing allocations may be freed.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.compute_ns_used >= self.compute_ns_max
            && self.transfer_bytes_used >= self.transfer_bytes_max
            && self.kernel_launches_used >= self.kernel_launches_max
    }
}

impl GpuBudget {
    /// A budget with all limits set to `u64::MAX` / `u32::MAX`.
    ///
    /// Useful for testing or contexts where budget enforcement is handled
    /// elsewhere.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX)
    }

    /// A budget with all limits set to zero (immediately exhausted).
    ///
    /// This is the same as [`Default`]. No GPU operations are permitted.
    #[must_use]
    pub const fn disabled() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// Default budget is **disabled** (zero limits).
///
/// All GPU operations will be rejected until explicit limits are set.
/// Use [`GpuBudget::unlimited()`] for an unrestricted budget or
/// [`GpuBudget::new()`] with explicit values.
impl Default for GpuBudget {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_allows_within_limit() {
        let mut budget = GpuBudget::new(1_000_000, 4096, 8192, 10);
        assert!(budget.check_compute(500_000).is_ok());
        assert!(budget.record_compute(500_000).is_ok());
        assert!(budget.check_compute(500_000).is_ok());
        assert!(budget.record_compute(500_000).is_ok());
        assert_eq!(budget.remaining_compute(), 0);
    }

    #[test]
    fn budget_denies_over_compute_limit() {
        let mut budget = GpuBudget::new(1000, 0, 0, 0);
        budget.record_compute(800).unwrap();
        assert_eq!(budget.check_compute(201), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn budget_memory_within_limit() {
        let mut budget = GpuBudget::new(0, 4096, 0, 0);
        assert!(budget.record_memory(2048).is_ok());
        assert!(budget.record_memory(2048).is_ok());
        assert_eq!(budget.record_memory(1), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn budget_transfer_within_limit() {
        let mut budget = GpuBudget::new(0, 0, 1000, 0);
        assert!(budget.record_transfer(500).is_ok());
        assert!(budget.record_transfer(500).is_ok());
        assert_eq!(budget.record_transfer(1), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn budget_launch_limit() {
        let mut budget = GpuBudget::new(0, 0, 0, 3);
        assert!(budget.record_launch().is_ok());
        assert!(budget.record_launch().is_ok());
        assert!(budget.record_launch().is_ok());
        assert_eq!(budget.record_launch(), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn budget_reset_epoch_preserves_memory() {
        let mut budget = GpuBudget::new(1000, 4096, 2000, 5);
        budget.record_compute(1000).unwrap();
        budget.record_memory(4096).unwrap();
        budget.record_transfer(2000).unwrap();
        for _ in 0..5 {
            budget.record_launch().unwrap();
        }
        assert!(budget.is_exhausted());

        budget.reset_epoch();

        // Per-epoch counters reset
        assert_eq!(budget.compute_ns_used, 0);
        assert_eq!(budget.transfer_bytes_used, 0);
        assert_eq!(budget.kernel_launches_used, 0);

        // Memory is NOT reset
        assert_eq!(budget.memory_bytes_used, 4096);
        assert_eq!(budget.record_memory(1), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn budget_zero_request_allowed() {
        let budget = GpuBudget::new(0, 0, 0, 0);
        assert!(budget.check_compute(0).is_ok());
        assert!(budget.check_memory(0).is_ok());
        assert!(budget.check_transfer(0).is_ok());
    }

    #[test]
    fn budget_overflow_protection() {
        let mut budget = GpuBudget::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX);
        budget.record_compute(u64::MAX - 1).unwrap();
        assert_eq!(budget.record_compute(2), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn budget_default_is_zero() {
        let budget = GpuBudget::default();
        assert_eq!(budget.compute_ns_max, 0);
        assert_eq!(budget.memory_bytes_max, 0);
        assert!(budget.is_exhausted());
    }
}
