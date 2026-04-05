//! GPU integration tests -- cross-crate validation.
//!
//! These tests verify that `rvm-gpu` types compose correctly with other
//! RVM crates: `rvm-types` (device classes, queue priorities, memory
//! types), `rvm-security` (resource quotas), and the GPU subsystem's
//! own budget, context, queue, and kernel types.

use rvm_gpu::{
    GpuBudget, GpuContext, GpuMinCutConfig, GpuStatus,
    error::GpuError,
    kernel::KernelId,
    queue::{GpuQueue, QueueCommand, QueueId},
    buffer::BufferId,
    device::GpuDeviceInfo,
};
use rvm_types::{
    DeviceClass, DeviceLease, DeviceLeaseId, GpuMemoryType, GpuQueuePriority,
    PartitionId, RvmError,
};
use rvm_security::{DmaBudget, ResourceQuota};

// =========================================================================
// GpuMemoryType and GpuQueuePriority from rvm-types
// =========================================================================

#[test]
fn gpu_memory_type_variants() {
    assert_eq!(GpuMemoryType::DeviceLocal as u8, 0);
    assert_eq!(GpuMemoryType::HostVisible as u8, 1);
    assert_eq!(GpuMemoryType::Unified as u8, 2);
    assert_ne!(GpuMemoryType::DeviceLocal, GpuMemoryType::HostVisible);
}

#[test]
fn gpu_queue_priority_ordering() {
    assert!(GpuQueuePriority::Low < GpuQueuePriority::Normal);
    assert!(GpuQueuePriority::Normal < GpuQueuePriority::High);
    assert!(GpuQueuePriority::High < GpuQueuePriority::Realtime);
}

#[test]
fn gpu_queue_priority_repr_values() {
    assert_eq!(GpuQueuePriority::Low as u8, 0);
    assert_eq!(GpuQueuePriority::Normal as u8, 1);
    assert_eq!(GpuQueuePriority::High as u8, 2);
    assert_eq!(GpuQueuePriority::Realtime as u8, 3);
}

// =========================================================================
// DeviceClass::Graphics works with GPU types
// =========================================================================

#[test]
fn device_class_graphics_for_gpu() {
    let lease = DeviceLease {
        id: DeviceLeaseId::new(1),
        class: DeviceClass::Graphics,
        mmio_base: 0xFE00_0000,
        mmio_size: 0x100_0000,
        expiry_ns: 0,
        epoch: 1,
    };
    assert_eq!(lease.class, DeviceClass::Graphics);

    // A GpuDeviceInfo should use the same MMIO region concept.
    let mut gpu_info = GpuDeviceInfo::default();
    gpu_info.mmio_base = lease.mmio_base;
    gpu_info.mmio_size = lease.mmio_size;
    assert_eq!(gpu_info.mmio_base, 0xFE00_0000);
    assert_eq!(gpu_info.mmio_size, 0x100_0000);
}

#[test]
fn device_lease_id_matches_gpu_device_id() {
    let lease_id = DeviceLeaseId::new(42);
    let gpu_info = GpuDeviceInfo {
        id: lease_id.as_u64() as u32,
        ..GpuDeviceInfo::default()
    };
    assert_eq!(gpu_info.id as u64, lease_id.as_u64());
}

// =========================================================================
// GpuBudget interacts correctly with resource quotas
// =========================================================================

#[test]
fn gpu_budget_and_dma_budget_independent() {
    // A partition has both a DMA budget (from rvm-security) and a GPU
    // budget (from rvm-gpu). They track independent resources.
    let mut dma = DmaBudget::new(10_000);
    let mut gpu = GpuBudget::new(1_000_000, 4096, 8192, 100);

    // Consume DMA budget.
    dma.check_dma(5000).unwrap();
    // GPU transfer budget is unaffected.
    assert_eq!(gpu.budget_remaining_transfer(), 8192);

    // Consume GPU transfer budget.
    gpu.record_transfer(4096).unwrap();
    // DMA budget is unaffected.
    assert_eq!(dma.remaining(), 5000);
}

#[test]
fn gpu_budget_and_resource_quota_complementary() {
    let mut quota = ResourceQuota::new(10_000_000, 1_048_576, 1000, 50_000);
    let mut gpu = GpuBudget::new(5_000_000, 524_288, 2_000_000, 50);

    // Use CPU time via resource quota.
    quota.check_cpu_time(1_000_000).unwrap();
    // GPU compute budget is independent.
    assert_eq!(gpu.remaining_compute(), 5_000_000);

    // Use GPU compute.
    gpu.record_compute(2_000_000).unwrap();
    assert_eq!(gpu.remaining_compute(), 3_000_000);

    // CPU time is unaffected.
    assert_eq!(quota.cpu_time_used_ns, 1_000_000);
}

#[test]
fn gpu_budget_epoch_reset_like_resource_quota() {
    let mut quota = ResourceQuota::new(1000, 4096, 10, 5000);
    let mut gpu = GpuBudget::new(1000, 4096, 5000, 10);

    // Exhaust per-epoch quotas.
    quota.check_cpu_time(1000).unwrap();
    gpu.record_compute(1000).unwrap();
    gpu.record_transfer(5000).unwrap();
    for _ in 0..10 {
        gpu.record_launch().unwrap();
    }

    // Reset both.
    quota.reset_epoch();
    gpu.reset_epoch();

    // Both should have per-epoch counters cleared.
    assert_eq!(quota.cpu_time_used_ns, 0);
    assert_eq!(gpu.compute_ns_used, 0);
    assert_eq!(gpu.transfer_bytes_used, 0);
    assert_eq!(gpu.kernel_launches_used, 0);
}

#[test]
fn gpu_budget_memory_persists_like_resource_quota() {
    let mut quota = ResourceQuota::new(0, 4096, 0, 0);
    let mut gpu = GpuBudget::new(0, 4096, 0, 0);

    quota.check_memory(4096).unwrap();
    gpu.record_memory(4096).unwrap();

    quota.reset_epoch();
    gpu.reset_epoch();

    // Memory is NOT reset by epoch in either system.
    assert_eq!(quota.memory_used_bytes, 4096);
    assert_eq!(gpu.memory_bytes_used, 4096);
}

// =========================================================================
// GpuContext with PartitionId
// =========================================================================

#[test]
fn gpu_context_partition_isolation() {
    let pid1 = PartitionId::new(1);
    let pid2 = PartitionId::new(2);
    let budget = GpuBudget::new(1_000_000, 4096, 8192, 10);

    let mut ctx1 = GpuContext::new(pid1, 0, budget);
    let mut ctx2 = GpuContext::new(pid2, 0, budget);

    ctx1.status = GpuStatus::Ready;
    ctx2.status = GpuStatus::Ready;

    // Operations on ctx1 do not affect ctx2.
    ctx1.record_kernel_launch(500_000).unwrap();
    assert_eq!(ctx1.budget.compute_ns_used, 500_000);
    assert_eq!(ctx2.budget.compute_ns_used, 0);

    ctx2.record_transfer(2048).unwrap();
    assert_eq!(ctx2.budget.transfer_bytes_used, 2048);
    assert_eq!(ctx1.budget.transfer_bytes_used, 0);
}

#[test]
fn gpu_context_full_lifecycle() {
    let pid = PartitionId::new(1);
    let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
    let mut ctx = GpuContext::new(pid, 0, budget);

    // Phase 1: Initialize.
    assert_eq!(ctx.status, GpuStatus::Initializing);
    assert!(!ctx.is_ready());

    // Phase 2: Ready after IOMMU setup.
    ctx.status = GpuStatus::Ready;
    assert!(ctx.is_ready());

    // Phase 3: Allocate memory and launch kernels.
    ctx.record_memory_alloc(4096).unwrap();
    ctx.record_kernel_launch(1_000_000).unwrap();
    assert_eq!(ctx.active_kernels, 1);
    assert_eq!(ctx.allocated_memory, 4096);

    // Phase 4: Kernel completes.
    ctx.record_kernel_complete();
    assert_eq!(ctx.active_kernels, 0);

    // Phase 5: Free memory.
    ctx.record_memory_free(4096).unwrap();
    assert_eq!(ctx.allocated_memory, 0);
    assert_eq!(ctx.budget.memory_bytes_used, 0);

    // Phase 6: Epoch reset.
    ctx.reset_epoch();
    assert_eq!(ctx.budget.compute_ns_used, 0);
}

// =========================================================================
// GpuError to RvmError conversion in cross-crate context
// =========================================================================

#[test]
fn gpu_error_converts_to_rvm_error_for_security_gate() {
    // The security gate works with RvmError. GPU errors should convert
    // correctly for propagation through the security layer.
    let gpu_err = GpuError::BudgetExceeded;
    let rvm_err: RvmError = gpu_err.into();
    assert_eq!(rvm_err, RvmError::ResourceLimitExceeded);

    let gpu_err = GpuError::CapabilityDenied;
    let rvm_err: RvmError = gpu_err.into();
    assert_eq!(rvm_err, RvmError::InsufficientCapability);
}

#[test]
fn gpu_error_device_not_found_maps_to_device_lease() {
    let rvm_err: RvmError = GpuError::DeviceNotFound.into();
    assert_eq!(rvm_err, RvmError::DeviceLeaseNotFound);
}

// =========================================================================
// GPU queue with cross-crate kernel/buffer IDs
// =========================================================================

#[test]
fn gpu_queue_mixed_commands() {
    let pid = PartitionId::new(1);
    let mut q = GpuQueue::with_max_depth(QueueId::new(0), pid, 8);

    // Mix of command types.
    q.enqueue(&QueueCommand::kernel_launch(KernelId::new(1))).unwrap();
    q.enqueue(&QueueCommand::buffer_copy(
        BufferId::new(0),
        BufferId::new(1),
        4096,
    )).unwrap();
    q.enqueue(&QueueCommand::barrier()).unwrap();

    assert_eq!(q.pending(), 3);
    assert_eq!(q.submitted, 3);

    q.complete_one().unwrap();
    q.complete_one().unwrap();
    q.complete_one().unwrap();
    assert_eq!(q.pending(), 0);
    assert_eq!(q.completed, 3);
}

// =========================================================================
// GPU accel configs with coherence integration
// =========================================================================

#[test]
fn gpu_mincut_config_for_coherence_graph() {
    let cfg = GpuMinCutConfig::default();
    // Default max_nodes=32 matches rvm-coherence's MINCUT_MAX_NODES
    assert!(cfg.max_nodes <= 32);
    assert!(cfg.budget_iterations <= cfg.max_nodes);
}

// Helper to compute remaining transfer budget on GpuBudget.
trait BudgetExt {
    fn budget_remaining_transfer(&self) -> u64;
}

impl BudgetExt for GpuBudget {
    fn budget_remaining_transfer(&self) -> u64 {
        self.remaining_transfer()
    }
}
