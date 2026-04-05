//! Integration tests for the rvm-gpu crate.
//!
//! These tests verify that the public API surface works correctly
//! across module boundaries. Module-level unit tests live in each
//! submodule's own `#[cfg(test)] mod tests` block.

use super::*;

// =========================================================================
// Tier and status enums
// =========================================================================

#[test]
fn gpu_tier_repr_values() {
    assert_eq!(GpuTier::WasmSimd as u8, 0);
    assert_eq!(GpuTier::WebGpu as u8, 1);
    assert_eq!(GpuTier::Cuda as u8, 2);
    assert_eq!(GpuTier::OpenCl as u8, 3);
    assert_eq!(GpuTier::Vulkan as u8, 4);
}

#[test]
fn gpu_status_repr_values() {
    assert_eq!(GpuStatus::Unavailable as u8, 0);
    assert_eq!(GpuStatus::Initializing as u8, 1);
    assert_eq!(GpuStatus::Ready as u8, 2);
    assert_eq!(GpuStatus::Error as u8, 3);
}

#[test]
fn constants_are_sane() {
    assert_eq!(MAX_GPU_DEVICES, 8);
    assert_eq!(MAX_KERNELS_PER_PARTITION, 64);
    assert_eq!(DEFAULT_KERNEL_TIMEOUT_NS, 100_000_000);
}

// =========================================================================
// Cross-module integration: context + budget + queue
// =========================================================================

#[test]
fn context_budget_integration() {
    use rvm_types::PartitionId;

    let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
    let mut ctx = GpuContext::new(PartitionId::new(1), 0, budget);
    ctx.status = GpuStatus::Ready;

    assert!(ctx.is_ready());
    assert!(ctx.check_budget(1_000_000, 1024).is_ok());
    assert!(ctx.record_kernel_launch(1_000_000).is_ok());
    assert!(ctx.record_transfer(2048).is_ok());
    assert!(ctx.record_memory_alloc(4096).is_ok());
    assert_eq!(ctx.active_kernels, 1);
    assert_eq!(ctx.allocated_memory, 4096);

    ctx.record_kernel_complete();
    assert_eq!(ctx.active_kernels, 0);

    ctx.reset_epoch();
    assert_eq!(ctx.budget.compute_ns_used, 0);
    // Memory persists across epochs
    assert_eq!(ctx.budget.memory_bytes_used, 4096);
}

#[test]
fn queue_command_lifecycle() {
    use rvm_types::PartitionId;

    let mut q = GpuQueue::with_max_depth(
        QueueId::new(0),
        PartitionId::new(1),
        4,
    );

    let launch_cmd = QueueCommand::kernel_launch(KernelId::new(1));
    let barrier_cmd = QueueCommand::barrier();
    let copy_cmd = QueueCommand::buffer_copy(
        BufferId::new(0),
        BufferId::new(1),
        4096,
    );

    assert!(q.enqueue(&launch_cmd).is_ok());
    assert!(q.enqueue(&barrier_cmd).is_ok());
    assert!(q.enqueue(&copy_cmd).is_ok());
    assert_eq!(q.pending(), 3);

    q.complete_one();
    q.complete_one();
    assert_eq!(q.pending(), 1);
    assert_eq!(q.completed, 2);
    assert_eq!(q.submitted, 3);
}

#[test]
fn error_conversion_round_trip() {
    use rvm_types::RvmError;

    let gpu_err = GpuError::CapabilityDenied;
    let rvm_err: RvmError = gpu_err.into();
    assert_eq!(rvm_err, RvmError::InsufficientCapability);

    let gpu_err = GpuError::OutOfMemory;
    let rvm_err: RvmError = gpu_err.into();
    assert_eq!(rvm_err, RvmError::OutOfMemory);
}

#[test]
fn device_info_defaults() {
    let dev = GpuDevice::default();
    assert_eq!(dev.info.id, 0);
    assert_eq!(dev.info.tier, GpuTier::WasmSimd);
    assert_eq!(dev.info.name_str(), "");
    assert_eq!(dev.capabilities.warp_size, 32);
}

#[test]
fn launch_config_validation() {
    let valid = LaunchConfig {
        workgroups: [4, 2, 1],
        workgroup_size: [32, 1, 1],
        shared_memory_bytes: 0,
        timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
    };
    assert!(valid.validate().is_ok());
    assert_eq!(valid.total_threads(), 256);

    let invalid = LaunchConfig {
        workgroups: [0, 1, 1],
        workgroup_size: [1, 1, 1],
        shared_memory_bytes: 0,
        timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
    };
    assert_eq!(invalid.validate(), Err(GpuError::InvalidLaunchConfig));
}

#[test]
fn buffer_validation() {
    use crate::buffer::validate_buffer;

    assert!(validate_buffer(4096, 1_073_741_824).is_ok());
    assert_eq!(validate_buffer(0, 1024), Err(GpuError::InvalidLaunchConfig));
    assert_eq!(validate_buffer(2048, 1024), Err(GpuError::BufferTooLarge));
}

#[test]
fn accel_config_defaults() {
    let mc = GpuMinCutConfig::default();
    assert_eq!(mc.max_nodes, 32);
    assert!(mc.use_gpu);

    let sc = GpuScoringConfig::default();
    assert_eq!(sc.max_partitions, 256);
    assert!(sc.use_gpu);

    let result = GpuMinCutResult::empty();
    assert_eq!(result.total_nodes(), 0);
    assert!(!result.used_gpu);
}
