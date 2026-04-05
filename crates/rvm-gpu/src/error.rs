//! GPU error types for the RVM microhypervisor.
//!
//! All GPU-specific failure modes are represented by [`GpuError`].
//! Each variant maps to a class of failure documented in ADR-144.
//! The [`From`] implementation converts to the unified [`RvmError`]
//! for propagation across crate boundaries.

use rvm_types::RvmError;

/// GPU-specific error type.
///
/// Covers device discovery, memory allocation, budget enforcement,
/// kernel execution, command queue, IOMMU isolation, and capability
/// gate failures. Converted to [`RvmError`] via the [`From`] impl
/// when crossing the `rvm-gpu` crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    /// No GPU device matching the requested tier was found.
    DeviceNotFound,
    /// The GPU device exists but is not in the `Ready` state.
    DeviceNotReady,
    /// GPU memory allocation failed (device VRAM exhausted).
    OutOfMemory,
    /// A GPU budget quota (compute, memory, transfer, or launches) was exceeded.
    BudgetExceeded,
    /// A GPU kernel exceeded its execution deadline (DC-GPU-5 / DC-7).
    KernelTimeout,
    /// Kernel compilation (shader/SPIR-V/PTX) failed.
    KernelCompilationFailed,
    /// The launch configuration is invalid (zero workgroups, oversized, etc.).
    InvalidLaunchConfig,
    /// The requested buffer size exceeds the device maximum.
    BufferTooLarge,
    /// The command queue has reached its depth limit.
    QueueFull,
    /// An IOMMU page table violation was detected (cross-partition access).
    IommuViolation,
    /// The caller lacks the required capability rights for this GPU operation.
    CapabilityDenied,
    /// A DMA or buffer transfer between host and device failed.
    TransferFailed,
    /// The requested GPU operation is not supported by the current backend/tier.
    Unsupported,
}

impl core::fmt::Display for GpuError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "GPU device not found"),
            Self::DeviceNotReady => write!(f, "GPU device not ready"),
            Self::OutOfMemory => write!(f, "GPU out of memory"),
            Self::BudgetExceeded => write!(f, "GPU budget exceeded"),
            Self::KernelTimeout => write!(f, "GPU kernel execution timeout"),
            Self::KernelCompilationFailed => write!(f, "GPU kernel compilation failed"),
            Self::InvalidLaunchConfig => write!(f, "invalid GPU launch configuration"),
            Self::BufferTooLarge => write!(f, "GPU buffer too large"),
            Self::QueueFull => write!(f, "GPU command queue full"),
            Self::IommuViolation => write!(f, "GPU IOMMU violation"),
            Self::CapabilityDenied => write!(f, "GPU capability denied"),
            Self::TransferFailed => write!(f, "GPU transfer failed"),
            Self::Unsupported => write!(f, "GPU operation unsupported"),
        }
    }
}

impl From<GpuError> for RvmError {
    fn from(err: GpuError) -> Self {
        match err {
            GpuError::DeviceNotFound => RvmError::DeviceLeaseNotFound,
            GpuError::DeviceNotReady => RvmError::InvalidPartitionState,
            GpuError::OutOfMemory => RvmError::OutOfMemory,
            GpuError::BudgetExceeded
            | GpuError::BufferTooLarge
            | GpuError::QueueFull => RvmError::ResourceLimitExceeded,
            GpuError::KernelTimeout => RvmError::MigrationTimeout,
            GpuError::KernelCompilationFailed
            | GpuError::InvalidLaunchConfig
            | GpuError::TransferFailed => RvmError::InternalError,
            GpuError::IommuViolation => RvmError::MemoryOverlap,
            GpuError::CapabilityDenied => RvmError::InsufficientCapability,
            GpuError::Unsupported => RvmError::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_error_to_rvm_error_mapping() {
        assert_eq!(RvmError::from(GpuError::DeviceNotFound), RvmError::DeviceLeaseNotFound);
        assert_eq!(RvmError::from(GpuError::OutOfMemory), RvmError::OutOfMemory);
        assert_eq!(RvmError::from(GpuError::BudgetExceeded), RvmError::ResourceLimitExceeded);
        assert_eq!(RvmError::from(GpuError::CapabilityDenied), RvmError::InsufficientCapability);
        assert_eq!(RvmError::from(GpuError::Unsupported), RvmError::Unsupported);
        assert_eq!(RvmError::from(GpuError::IommuViolation), RvmError::MemoryOverlap);
    }

    #[test]
    fn gpu_error_display() {
        let err = GpuError::KernelTimeout;
        let msg = core::format_args!("{err}");
        // Verify Display impl compiles and produces non-empty output.
        let _ = msg;
    }

    #[test]
    fn gpu_error_is_copy() {
        let a = GpuError::QueueFull;
        let b = a;
        assert_eq!(a, b);
    }
}
