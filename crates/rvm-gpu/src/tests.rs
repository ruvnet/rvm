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

    // Test atomic try_launch
    assert!(ctx.try_launch(500_000, 1024).is_ok());
    assert_eq!(ctx.budget.compute_ns_used, 500_000);
    assert_eq!(ctx.budget.transfer_bytes_used, 1024);
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

    q.complete_one().unwrap();
    q.complete_one().unwrap();
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
    assert_eq!(validate_buffer(0, 1024), Err(GpuError::BufferTooLarge));
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

// =========================================================================
// Comprehensive budget tests (15+)
// =========================================================================

#[test]
fn budget_new_has_correct_limits() {
    let b = GpuBudget::new(1_000_000, 4096, 8192, 100);
    assert_eq!(b.compute_ns_max, 1_000_000);
    assert_eq!(b.compute_ns_used, 0);
    assert_eq!(b.memory_bytes_max, 4096);
    assert_eq!(b.memory_bytes_used, 0);
    assert_eq!(b.transfer_bytes_max, 8192);
    assert_eq!(b.transfer_bytes_used, 0);
    assert_eq!(b.kernel_launches_max, 100);
    assert_eq!(b.kernel_launches_used, 0);
}

#[test]
fn budget_check_compute_within_limit() {
    let mut b = GpuBudget::new(1_000_000, 0, 0, 0);
    assert!(b.check_compute(500_000).is_ok());
    assert!(b.record_compute(500_000).is_ok());
    assert!(b.check_compute(500_000).is_ok());
    assert!(b.record_compute(500_000).is_ok());
    assert_eq!(b.remaining_compute(), 0);
}

#[test]
fn budget_check_compute_exceeds_limit() {
    use rvm_types::RvmError;
    let mut b = GpuBudget::new(1_000_000, 0, 0, 0);
    b.record_compute(500_000).unwrap();
    assert_eq!(b.check_compute(500_001), Err(RvmError::ResourceLimitExceeded));
    assert_eq!(b.compute_ns_used, 500_000);
}

#[test]
fn budget_check_memory_within_limit() {
    let mut b = GpuBudget::new(0, 4096, 0, 0);
    assert!(b.check_memory(2048).is_ok());
    assert!(b.record_memory(2048).is_ok());
    assert!(b.record_memory(2048).is_ok());
    assert_eq!(b.memory_bytes_used, 4096);
}

#[test]
fn budget_check_memory_exceeds_limit() {
    use rvm_types::RvmError;
    let mut b = GpuBudget::new(0, 4096, 0, 0);
    b.record_memory(4096).unwrap();
    assert_eq!(b.check_memory(1), Err(RvmError::ResourceLimitExceeded));
}

#[test]
fn budget_check_transfer_within_limit() {
    let mut b = GpuBudget::new(0, 0, 8192, 0);
    assert!(b.check_transfer(4096).is_ok());
    assert!(b.record_transfer(4096).is_ok());
    assert!(b.record_transfer(4096).is_ok());
    assert_eq!(b.transfer_bytes_used, 8192);
}

#[test]
fn budget_check_transfer_exceeds_limit() {
    use rvm_types::RvmError;
    let mut b = GpuBudget::new(0, 0, 8192, 0);
    b.record_transfer(8192).unwrap();
    assert_eq!(b.check_transfer(1), Err(RvmError::ResourceLimitExceeded));
}

#[test]
fn budget_check_launch_within_limit() {
    let mut b = GpuBudget::new(0, 0, 0, 3);
    assert!(b.check_launch().is_ok());
    assert!(b.record_launch().is_ok());
    assert!(b.record_launch().is_ok());
    assert!(b.record_launch().is_ok());
    assert_eq!(b.kernel_launches_used, 3);
}

#[test]
fn budget_check_launch_exceeds_limit() {
    use rvm_types::RvmError;
    let mut b = GpuBudget::new(0, 0, 0, 2);
    b.record_launch().unwrap();
    b.record_launch().unwrap();
    assert_eq!(b.check_launch(), Err(RvmError::ResourceLimitExceeded));
}

#[test]
fn budget_reset_epoch_clears_compute() {
    let mut b = GpuBudget::new(1_000_000, 4096, 8192, 10);
    b.record_compute(1_000_000).unwrap();
    b.record_transfer(8192).unwrap();
    b.record_launch().unwrap();
    b.reset_epoch();
    assert_eq!(b.compute_ns_used, 0);
    assert_eq!(b.transfer_bytes_used, 0);
    assert_eq!(b.kernel_launches_used, 0);
    assert!(b.record_compute(500_000).is_ok());
}

#[test]
fn budget_reset_epoch_preserves_memory() {
    use rvm_types::RvmError;
    let mut b = GpuBudget::new(0, 4096, 0, 0);
    b.record_memory(4096).unwrap();
    b.reset_epoch();
    assert_eq!(b.memory_bytes_used, 4096);
    assert_eq!(b.record_memory(1), Err(RvmError::ResourceLimitExceeded));
}

#[test]
fn budget_saturating_arithmetic() {
    use rvm_types::RvmError;
    let mut b = GpuBudget::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX);
    b.record_compute(u64::MAX - 1).unwrap();
    assert_eq!(b.record_compute(2), Err(RvmError::ResourceLimitExceeded));
}

#[test]
fn budget_is_exhausted() {
    let mut b = GpuBudget::new(100, 0, 100, 1);
    assert!(!b.is_exhausted());
    b.record_compute(100).unwrap();
    b.record_transfer(100).unwrap();
    b.record_launch().unwrap();
    assert!(b.is_exhausted());
}

#[test]
fn budget_remaining_compute() {
    let mut b = GpuBudget::new(1_000_000, 4096, 8192, 10);
    assert_eq!(b.remaining_compute(), 1_000_000);
    assert_eq!(b.remaining_memory(), 4096);
    assert_eq!(b.remaining_transfer(), 8192);
    b.record_compute(300_000).unwrap();
    b.record_memory(1024).unwrap();
    b.record_transfer(2048).unwrap();
    assert_eq!(b.remaining_compute(), 700_000);
    assert_eq!(b.remaining_memory(), 3072);
    assert_eq!(b.remaining_transfer(), 6144);
}

#[test]
fn budget_multiple_operations() {
    let mut b = GpuBudget::new(1000, 2000, 3000, 5);
    b.record_compute(200).unwrap();
    b.record_memory(500).unwrap();
    b.record_transfer(1000).unwrap();
    b.record_launch().unwrap();
    b.record_compute(300).unwrap();
    b.record_memory(500).unwrap();
    b.record_transfer(1000).unwrap();
    b.record_launch().unwrap();
    assert_eq!(b.compute_ns_used, 500);
    assert_eq!(b.memory_bytes_used, 1000);
    assert_eq!(b.transfer_bytes_used, 2000);
    assert_eq!(b.kernel_launches_used, 2);
}

// =========================================================================
// Comprehensive device tests
// =========================================================================

#[test]
fn device_info_name_with_content() {
    let mut info = GpuDeviceInfo::default();
    let name = b"NVIDIA RTX 4090";
    info.name[..name.len()].copy_from_slice(name);
    info.name_len = name.len() as u8;
    assert_eq!(info.name_str(), "NVIDIA RTX 4090");
}

#[test]
fn device_info_full_name_length() {
    let mut info = GpuDeviceInfo::default();
    for (i, byte) in info.name.iter_mut().enumerate() {
        *byte = b'A' + (i % 26) as u8;
    }
    info.name_len = 64;
    assert_eq!(info.name_str().len(), 64);
}

#[test]
fn gpu_tier_equality() {
    assert_ne!(GpuTier::WasmSimd, GpuTier::Cuda);
    assert_ne!(GpuTier::WebGpu, GpuTier::Vulkan);
    assert_eq!(GpuTier::Cuda, GpuTier::Cuda);
}

// =========================================================================
// Comprehensive context tests
// =========================================================================

#[test]
fn context_new_starts_initializing() {
    use rvm_types::PartitionId;
    let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
    let ctx = GpuContext::new(PartitionId::new(42), 3, budget);
    assert_eq!(ctx.partition_id, PartitionId::new(42));
    assert_eq!(ctx.device_id, 3);
    assert_eq!(ctx.status, GpuStatus::Initializing);
    assert!(!ctx.is_ready());
}

#[test]
fn context_not_ready_when_error() {
    use rvm_types::PartitionId;
    let mut ctx = GpuContext::new(
        PartitionId::new(1),
        0,
        GpuBudget::new(1000, 1000, 1000, 10),
    );
    ctx.status = GpuStatus::Error;
    assert!(!ctx.is_ready());
}

#[test]
fn context_not_ready_when_unavailable() {
    use rvm_types::PartitionId;
    let mut ctx = GpuContext::new(
        PartitionId::new(1),
        0,
        GpuBudget::new(1000, 1000, 1000, 10),
    );
    ctx.status = GpuStatus::Unavailable;
    assert!(!ctx.is_ready());
}

#[test]
fn context_record_kernel_launch_exceeds_budget() {
    use rvm_types::PartitionId;
    let mut ctx = GpuContext::new(
        PartitionId::new(1),
        0,
        GpuBudget::new(100, 0, 0, 1),
    );
    ctx.status = GpuStatus::Ready;
    ctx.record_kernel_launch(50).unwrap();
    assert!(ctx.record_kernel_launch(50).is_err());
}

#[test]
fn context_record_transfer_exceeds_budget() {
    use rvm_types::PartitionId;
    let mut ctx = GpuContext::new(
        PartitionId::new(1),
        0,
        GpuBudget::new(0, 0, 1000, 0),
    );
    ctx.status = GpuStatus::Ready;
    ctx.record_transfer(1000).unwrap();
    assert!(ctx.record_transfer(1).is_err());
}

#[test]
fn context_memory_alloc_and_free() {
    use rvm_types::PartitionId;
    let mut ctx = GpuContext::new(
        PartitionId::new(1),
        0,
        GpuBudget::new(0, 8192, 0, 0),
    );
    ctx.status = GpuStatus::Ready;
    ctx.record_memory_alloc(4096).unwrap();
    assert_eq!(ctx.allocated_memory, 4096);
    ctx.record_memory_free(2048).unwrap();
    assert_eq!(ctx.allocated_memory, 2048);
    assert_eq!(ctx.budget.memory_bytes_used, 2048);
}

#[test]
fn context_check_budget_fails_on_transfer() {
    use rvm_types::PartitionId;
    let mut ctx = GpuContext::new(
        PartitionId::new(1),
        0,
        GpuBudget::new(u64::MAX, 0, 100, 100),
    );
    ctx.status = GpuStatus::Ready;
    assert!(ctx.check_budget(0, 200).is_err());
}

// =========================================================================
// Comprehensive kernel tests
// =========================================================================

#[test]
fn launch_config_validate_zero_workgroups_y() {
    let cfg = LaunchConfig {
        workgroups: [1, 0, 1],
        workgroup_size: [64, 1, 1],
        shared_memory_bytes: 0,
        timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
    };
    assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
}

#[test]
fn launch_config_validate_zero_workgroups_z() {
    let cfg = LaunchConfig {
        workgroups: [1, 1, 0],
        workgroup_size: [64, 1, 1],
        shared_memory_bytes: 0,
        timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
    };
    assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
}

#[test]
fn launch_config_validate_zero_size_y() {
    let cfg = LaunchConfig {
        workgroups: [1, 1, 1],
        workgroup_size: [1, 0, 1],
        shared_memory_bytes: 0,
        timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
    };
    assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
}

#[test]
fn launch_config_validate_zero_timeout() {
    let cfg = LaunchConfig {
        workgroups: [1, 1, 1],
        workgroup_size: [1, 1, 1],
        shared_memory_bytes: 0,
        timeout_ns: 0,
    };
    assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
}

#[test]
fn kernel_id_copy_and_equality() {
    let id = KernelId::new(42);
    let copy = id;
    assert_eq!(id, copy);
    assert_eq!(id.as_u32(), 42);
    assert_ne!(id, KernelId::new(43));
}

// =========================================================================
// Comprehensive buffer tests
// =========================================================================

#[test]
fn buffer_id_copy_and_equality() {
    let id = BufferId::new(99);
    let copy = id;
    assert_eq!(id, copy);
    assert_eq!(id.as_u32(), 99);
    assert_ne!(id, BufferId::new(100));
}

#[test]
fn validate_buffer_exact_max() {
    assert!(buffer::validate_buffer(1024, 1024).is_ok());
}

#[test]
fn gpu_buffer_host_mapped() {
    use rvm_types::PartitionId;
    let buf = GpuBuffer {
        id: BufferId::new(5),
        partition_id: PartitionId::new(1),
        size_bytes: 8192,
        usage: BufferUsage::CopySrc,
        host_mapped: true,
    };
    assert!(buf.host_mapped);
    assert_eq!(buf.usage, BufferUsage::CopySrc);
    assert_eq!(buf.size_bytes, 8192);
}

// =========================================================================
// Comprehensive queue tests
// =========================================================================

#[test]
fn queue_full_then_complete_allows_more() {
    use rvm_types::PartitionId;
    let mut q = GpuQueue::with_max_depth(QueueId::new(0), PartitionId::new(1), 1);
    let cmd = QueueCommand::barrier();
    q.enqueue(&cmd).unwrap();
    assert!(q.is_full());
    q.complete_one().unwrap();
    assert!(!q.is_full());
    assert!(q.enqueue(&cmd).is_ok());
}

#[test]
fn queue_id_round_trip() {
    let id = QueueId::new(7);
    assert_eq!(id.as_u32(), 7);
}

#[test]
fn queue_command_kernel_launch() {
    let cmd = QueueCommand::kernel_launch(KernelId::new(5));
    assert_eq!(cmd.cmd_type, CommandType::KernelLaunch);
    assert_eq!(cmd.kernel_id, Some(KernelId::new(5)));
    assert!(cmd.buffer_src.is_none());
}

#[test]
fn queue_command_buffer_copy() {
    let cmd = QueueCommand::buffer_copy(BufferId::new(1), BufferId::new(2), 4096);
    assert_eq!(cmd.cmd_type, CommandType::BufferCopy);
    assert_eq!(cmd.buffer_src, Some(BufferId::new(1)));
    assert_eq!(cmd.buffer_dst, Some(BufferId::new(2)));
    assert_eq!(cmd.size_bytes, 4096);
}

#[test]
fn command_type_repr_values() {
    assert_eq!(CommandType::KernelLaunch as u8, 0);
    assert_eq!(CommandType::BufferCopy as u8, 1);
    assert_eq!(CommandType::BufferFill as u8, 2);
    assert_eq!(CommandType::Barrier as u8, 3);
    assert_eq!(CommandType::TimestampQuery as u8, 4);
}

// =========================================================================
// Comprehensive error tests
// =========================================================================

#[test]
fn gpu_error_all_variants_distinct() {
    let errors = [
        GpuError::DeviceNotFound,
        GpuError::DeviceNotReady,
        GpuError::OutOfMemory,
        GpuError::BudgetExceeded,
        GpuError::KernelTimeout,
        GpuError::KernelCompilationFailed,
        GpuError::InvalidLaunchConfig,
        GpuError::BufferTooLarge,
        GpuError::QueueFull,
        GpuError::IommuViolation,
        GpuError::CapabilityDenied,
        GpuError::TransferFailed,
        GpuError::Unsupported,
    ];
    for (i, a) in errors.iter().enumerate() {
        for (j, b) in errors.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn gpu_error_to_rvm_error_complete() {
    use rvm_types::RvmError;
    assert_eq!(RvmError::from(GpuError::DeviceNotFound), RvmError::DeviceLeaseNotFound);
    assert_eq!(RvmError::from(GpuError::DeviceNotReady), RvmError::InvalidPartitionState);
    assert_eq!(RvmError::from(GpuError::OutOfMemory), RvmError::OutOfMemory);
    assert_eq!(RvmError::from(GpuError::BudgetExceeded), RvmError::ResourceLimitExceeded);
    assert_eq!(RvmError::from(GpuError::KernelTimeout), RvmError::InternalError);
    assert_eq!(RvmError::from(GpuError::InvalidLaunchConfig), RvmError::InternalError);
    assert_eq!(RvmError::from(GpuError::BufferTooLarge), RvmError::ResourceLimitExceeded);
    assert_eq!(RvmError::from(GpuError::QueueFull), RvmError::ResourceLimitExceeded);
    assert_eq!(RvmError::from(GpuError::IommuViolation), RvmError::InternalError);
    assert_eq!(RvmError::from(GpuError::CapabilityDenied), RvmError::InsufficientCapability);
    assert_eq!(RvmError::from(GpuError::Unsupported), RvmError::Unsupported);
}

#[test]
fn gpu_error_is_copy_and_clone() {
    let e = GpuError::DeviceNotFound;
    let e2 = e;
    assert_eq!(e, e2);
}

// =========================================================================
// Comprehensive accel tests
// =========================================================================

#[test]
fn mincut_gpu_available_without_features() {
    let available = accel::mincut_gpu_available();
    let scoring = accel::scoring_gpu_available();
    assert_eq!(available, scoring);
}

#[test]
fn mincut_result_total_nodes() {
    let r = GpuMinCutResult {
        left_count: 12,
        right_count: 20,
        cut_weight: 500,
        compute_ns: 8000,
        used_gpu: true,
    };
    assert_eq!(r.total_nodes(), 32);
}

#[test]
fn mincut_result_empty_has_zero_nodes() {
    let r = GpuMinCutResult::empty();
    assert_eq!(r.total_nodes(), 0);
    assert_eq!(r.cut_weight, 0);
    assert!(!r.used_gpu);
}

#[test]
fn budget_default_is_zero() {
    let b = GpuBudget::default();
    assert_eq!(b.compute_ns_max, 0);
    assert_eq!(b.memory_bytes_max, 0);
    assert!(b.is_exhausted());
}

#[test]
fn budget_zero_request_allowed() {
    let b = GpuBudget::new(0, 0, 0, 0);
    assert!(b.check_compute(0).is_ok());
    assert!(b.check_memory(0).is_ok());
    assert!(b.check_transfer(0).is_ok());
}
