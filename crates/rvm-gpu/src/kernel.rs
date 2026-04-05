//! GPU kernel management and launch configuration.
//!
//! A GPU kernel is a compiled compute program that runs on the GPU
//! hardware. Kernels are compiled from `cuda-rust-wasm` source, assigned
//! a [`KernelId`], and bound to a partition. The [`LaunchConfig`]
//! specifies workgroup dimensions, shared memory, and execution timeout.
//!
//! Kernel lifetime is scoped to the owning partition. When a partition
//! is destroyed, all its kernels are released.

use rvm_types::PartitionId;

use crate::error::GpuError;
use crate::DEFAULT_KERNEL_TIMEOUT_NS;

/// Maximum kernel name length in bytes.
const KERNEL_NAME_MAX: usize = 32;

/// Unique identifier for a compiled GPU kernel within a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct KernelId(u32);

impl KernelId {
    /// Create a new kernel identifier.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Return the raw identifier value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// GPU kernel dispatch configuration.
///
/// Specifies the 3D workgroup grid dimensions, per-workgroup thread
/// dimensions, shared memory allocation, and execution timeout.
///
/// Validated before submission to the command queue via [`validate`](Self::validate).
#[derive(Debug, Clone, Copy)]
pub struct LaunchConfig {
    /// Number of workgroups in each dimension (X, Y, Z).
    pub workgroups: [u32; 3],
    /// Number of threads per workgroup in each dimension (X, Y, Z).
    pub workgroup_size: [u32; 3],
    /// Shared memory allocation per workgroup in bytes.
    pub shared_memory_bytes: u32,
    /// Maximum execution time in nanoseconds before the kernel is killed.
    pub timeout_ns: u64,
}

/// Default launch configuration: single workgroup, single thread, 100ms timeout.
pub const DEFAULT_LAUNCH_CONFIG: LaunchConfig = LaunchConfig {
    workgroups: [1, 1, 1],
    workgroup_size: [1, 1, 1],
    shared_memory_bytes: 0,
    timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
};

impl LaunchConfig {
    /// Compute the total number of threads across all workgroups.
    ///
    /// Returns `workgroups[0] * workgroups[1] * workgroups[2]
    ///        * workgroup_size[0] * workgroup_size[1] * workgroup_size[2]`
    /// as a `u64` to avoid overflow on large grid configurations.
    #[must_use]
    pub const fn total_threads(&self) -> u64 {
        let groups = self.workgroups[0] as u64
            * self.workgroups[1] as u64
            * self.workgroups[2] as u64;
        let threads_per_group = self.workgroup_size[0] as u64
            * self.workgroup_size[1] as u64
            * self.workgroup_size[2] as u64;
        groups.saturating_mul(threads_per_group)
    }

    /// Validate the launch configuration for sanity.
    ///
    /// Rejects configurations with zero-dimension workgroups or workgroup
    /// sizes, zero timeout, or excessively large thread counts.
    ///
    /// # Errors
    ///
    /// Returns [`GpuError::InvalidLaunchConfig`] if any dimension is
    /// zero or the total thread count exceeds `u32::MAX`.
    pub const fn validate(&self) -> Result<(), GpuError> {
        // All dimensions must be non-zero.
        if self.workgroups[0] == 0
            || self.workgroups[1] == 0
            || self.workgroups[2] == 0
        {
            return Err(GpuError::InvalidLaunchConfig);
        }
        if self.workgroup_size[0] == 0
            || self.workgroup_size[1] == 0
            || self.workgroup_size[2] == 0
        {
            return Err(GpuError::InvalidLaunchConfig);
        }
        // Timeout must be positive.
        if self.timeout_ns == 0 {
            return Err(GpuError::InvalidLaunchConfig);
        }
        // Total threads must not overflow a reasonable limit.
        if self.total_threads() > u32::MAX as u64 {
            return Err(GpuError::InvalidLaunchConfig);
        }
        Ok(())
    }
}

impl Default for LaunchConfig {
    fn default() -> Self {
        DEFAULT_LAUNCH_CONFIG
    }
}

/// A compiled GPU compute kernel bound to a partition.
///
/// Kernels are created by compiling `cuda-rust-wasm` source for the
/// active backend tier. Each kernel has a unique [`KernelId`] within
/// its owning partition. The `created_epoch` records when the kernel
/// was compiled for stale-handle detection.
#[derive(Debug, Clone, Copy)]
pub struct GpuKernel {
    /// Unique identifier for this kernel within its partition.
    pub id: KernelId,
    /// Human-readable kernel name (null-padded, UTF-8 subset).
    pub name: [u8; KERNEL_NAME_MAX],
    /// Length of the kernel name (excluding padding).
    pub name_len: u8,
    /// The partition that owns this kernel.
    pub partition_id: PartitionId,
    /// Epoch in which this kernel was compiled.
    pub created_epoch: u32,
}

impl GpuKernel {
    /// Return the kernel name as a `&str`, or an empty string if invalid.
    #[must_use]
    pub fn name_str(&self) -> &str {
        let len = self.name_len as usize;
        if len > KERNEL_NAME_MAX {
            return "";
        }
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_id_round_trip() {
        let id = KernelId::new(42);
        assert_eq!(id.as_u32(), 42);
    }

    #[test]
    fn default_launch_config_is_valid() {
        assert!(DEFAULT_LAUNCH_CONFIG.validate().is_ok());
        assert_eq!(DEFAULT_LAUNCH_CONFIG.total_threads(), 1);
        assert_eq!(DEFAULT_LAUNCH_CONFIG.timeout_ns, DEFAULT_KERNEL_TIMEOUT_NS);
    }

    #[test]
    fn launch_config_total_threads() {
        let cfg = LaunchConfig {
            workgroups: [4, 2, 1],
            workgroup_size: [32, 1, 1],
            shared_memory_bytes: 0,
            timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
        };
        assert_eq!(cfg.total_threads(), 4 * 2 * 1 * 32);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn launch_config_3d() {
        let cfg = LaunchConfig {
            workgroups: [8, 8, 8],
            workgroup_size: [8, 8, 4],
            shared_memory_bytes: 16384,
            timeout_ns: 50_000_000,
        };
        assert_eq!(cfg.total_threads(), 512 * 256);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn launch_config_zero_workgroups_rejected() {
        let cfg = LaunchConfig {
            workgroups: [0, 1, 1],
            workgroup_size: [1, 1, 1],
            shared_memory_bytes: 0,
            timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
        };
        assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn launch_config_zero_workgroup_size_rejected() {
        let cfg = LaunchConfig {
            workgroups: [1, 1, 1],
            workgroup_size: [1, 0, 1],
            shared_memory_bytes: 0,
            timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
        };
        assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn launch_config_zero_timeout_rejected() {
        let cfg = LaunchConfig {
            workgroups: [1, 1, 1],
            workgroup_size: [1, 1, 1],
            shared_memory_bytes: 0,
            timeout_ns: 0,
        };
        assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn launch_config_overflow_rejected() {
        let cfg = LaunchConfig {
            workgroups: [65536, 65536, 1],
            workgroup_size: [1024, 1, 1],
            shared_memory_bytes: 0,
            timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
        };
        // 65536 * 65536 * 1024 = 2^36 > u32::MAX
        assert_eq!(cfg.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn kernel_name_str() {
        let mut kernel = GpuKernel {
            id: KernelId::new(0),
            name: [0u8; KERNEL_NAME_MAX],
            name_len: 0,
            partition_id: PartitionId::new(1),
            created_epoch: 0,
        };
        let name = b"mincut_v1";
        kernel.name[..name.len()].copy_from_slice(name);
        kernel.name_len = name.len() as u8;
        assert_eq!(kernel.name_str(), "mincut_v1");
    }
}
