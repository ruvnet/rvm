//! Per-partition GPU context management.
//!
//! Each partition that accesses GPU hardware gets a [`GpuContext`] that
//! tracks its device binding, status, budget, and active kernel/memory
//! state. Contexts are created lazily on first GPU access (DC-GPU-4)
//! and destroyed on partition teardown.
//!
//! The context is the central enforcement point for GPU budget checks.
//! Every GPU operation flows through the context, which gates on both
//! capability rights and budget availability before dispatching to the
//! hardware abstraction layer.

use rvm_types::{PartitionId, RvmResult};

use crate::budget::GpuBudget;
use crate::GpuStatus;

/// Per-partition GPU execution context.
///
/// Saved and restored lazily during partition context switches
/// (DC-GPU-4). Partitions that never access the GPU have no context,
/// paying zero save/restore cost.
#[derive(Debug, Clone, Copy)]
pub struct GpuContext {
    /// The partition this context belongs to.
    pub partition_id: PartitionId,
    /// The GPU device this context is bound to.
    pub device_id: u32,
    /// Current status of this GPU context.
    pub status: GpuStatus,
    /// GPU resource budget for this partition.
    pub budget: GpuBudget,
    /// Number of kernels currently executing on the GPU for this partition.
    pub active_kernels: u32,
    /// Total GPU memory currently allocated by this partition (bytes).
    pub allocated_memory: u64,
    /// Current depth of the command queue.
    pub queue_depth: u32,
}

impl GpuContext {
    /// Create a new GPU context for the given partition and device.
    ///
    /// The context starts in [`GpuStatus::Initializing`] with an empty
    /// budget. The caller must set budget limits and transition to
    /// [`GpuStatus::Ready`] after IOMMU page table setup.
    #[must_use]
    pub const fn new(partition_id: PartitionId, device_id: u32, budget: GpuBudget) -> Self {
        Self {
            partition_id,
            device_id,
            status: GpuStatus::Initializing,
            budget,
            active_kernels: 0,
            allocated_memory: 0,
            queue_depth: 0,
        }
    }

    /// Check whether the GPU context is ready for operations.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.status, GpuStatus::Ready)
    }

    /// Validate that the budget allows a kernel launch with the given
    /// estimated compute time and transfer size.
    ///
    /// This is a pre-check only — it does NOT record usage. Call the
    /// individual `record_*` methods on the budget after the operation
    /// completes.
    pub fn check_budget(&self, compute_ns: u64, transfer_bytes: u64) -> RvmResult<()> {
        self.budget.check_compute(compute_ns)?;
        self.budget.check_transfer(transfer_bytes)?;
        self.budget.check_launch()?;
        Ok(())
    }

    /// Record a successful kernel launch in the budget and active count.
    pub fn record_kernel_launch(&mut self, compute_ns: u64) -> RvmResult<()> {
        self.budget.record_compute(compute_ns)?;
        self.budget.record_launch()?;
        self.active_kernels = self.active_kernels.saturating_add(1);
        Ok(())
    }

    /// Record a completed transfer in the budget.
    pub fn record_transfer(&mut self, transferred_bytes: u64) -> RvmResult<()> {
        self.budget.record_transfer(transferred_bytes)
    }

    /// Record a kernel completion, decrementing the active kernel count.
    pub fn record_kernel_complete(&mut self) {
        self.active_kernels = self.active_kernels.saturating_sub(1);
    }

    /// Record a GPU memory allocation.
    pub fn record_memory_alloc(&mut self, bytes: u64) -> RvmResult<()> {
        self.budget.record_memory(bytes)?;
        self.allocated_memory = self.allocated_memory.saturating_add(bytes);
        Ok(())
    }

    /// Record a GPU memory deallocation.
    pub fn record_memory_free(&mut self, bytes: u64) {
        self.allocated_memory = self.allocated_memory.saturating_sub(bytes);
        self.budget.memory_bytes_used = self
            .budget
            .memory_bytes_used
            .saturating_sub(bytes);
    }

    /// Reset per-epoch budget counters (compute, transfer, launches).
    ///
    /// Called by the scheduler at epoch boundaries. Memory allocation
    /// counters are preserved since they reflect persistent state.
    pub fn reset_epoch(&mut self) {
        self.budget.reset_epoch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_partition() -> PartitionId {
        PartitionId::new(1)
    }

    fn test_budget() -> GpuBudget {
        GpuBudget::new(
            10_000_000, // 10ms compute
            1_048_576,  // 1MB memory
            4_194_304,  // 4MB transfer
            100,        // 100 launches
        )
    }

    #[test]
    fn new_context_is_initializing() {
        let ctx = GpuContext::new(test_partition(), 0, test_budget());
        assert_eq!(ctx.status, GpuStatus::Initializing);
        assert!(!ctx.is_ready());
        assert_eq!(ctx.active_kernels, 0);
        assert_eq!(ctx.allocated_memory, 0);
    }

    #[test]
    fn context_becomes_ready() {
        let mut ctx = GpuContext::new(test_partition(), 0, test_budget());
        ctx.status = GpuStatus::Ready;
        assert!(ctx.is_ready());
    }

    #[test]
    fn check_budget_passes() {
        let ctx = GpuContext::new(test_partition(), 0, test_budget());
        assert!(ctx.check_budget(1_000_000, 1024).is_ok());
    }

    #[test]
    fn check_budget_fails_on_compute() {
        let ctx = GpuContext::new(test_partition(), 0, test_budget());
        assert!(ctx.check_budget(20_000_000, 0).is_err());
    }

    #[test]
    fn record_kernel_launch_and_complete() {
        let mut ctx = GpuContext::new(test_partition(), 0, test_budget());
        assert!(ctx.record_kernel_launch(1_000_000).is_ok());
        assert_eq!(ctx.active_kernels, 1);
        assert_eq!(ctx.budget.compute_ns_used, 1_000_000);
        assert_eq!(ctx.budget.kernel_launches_used, 1);

        ctx.record_kernel_complete();
        assert_eq!(ctx.active_kernels, 0);
    }

    #[test]
    fn record_transfer() {
        let mut ctx = GpuContext::new(test_partition(), 0, test_budget());
        assert!(ctx.record_transfer(2048).is_ok());
        assert_eq!(ctx.budget.transfer_bytes_used, 2048);
    }

    #[test]
    fn record_memory_alloc_and_free() {
        let mut ctx = GpuContext::new(test_partition(), 0, test_budget());
        assert!(ctx.record_memory_alloc(4096).is_ok());
        assert_eq!(ctx.allocated_memory, 4096);
        assert_eq!(ctx.budget.memory_bytes_used, 4096);

        ctx.record_memory_free(2048);
        assert_eq!(ctx.allocated_memory, 2048);
        assert_eq!(ctx.budget.memory_bytes_used, 2048);
    }

    #[test]
    fn reset_epoch_preserves_memory() {
        let mut ctx = GpuContext::new(test_partition(), 0, test_budget());
        ctx.record_kernel_launch(5_000_000).unwrap();
        ctx.record_transfer(1024).unwrap();
        ctx.record_memory_alloc(4096).unwrap();

        ctx.reset_epoch();

        assert_eq!(ctx.budget.compute_ns_used, 0);
        assert_eq!(ctx.budget.transfer_bytes_used, 0);
        assert_eq!(ctx.budget.kernel_launches_used, 0);
        // Memory is preserved
        assert_eq!(ctx.budget.memory_bytes_used, 4096);
        assert_eq!(ctx.allocated_memory, 4096);
    }
}
