//! GPU device discovery and hardware capability query.
//!
//! This module provides [`GpuDeviceInfo`] for describing discovered GPU
//! hardware, [`GpuCapabilities`] for detailed compute feature queries,
//! and [`GpuDevice`] as the top-level device handle combining both.
//!
//! Device discovery maps to `DeviceClass::Graphics` (variant 2) in
//! `rvm-types`. MMIO base and size fields align with the existing
//! [`DeviceLease`](rvm_types::DeviceLease) model.

use crate::GpuTier;

/// Maximum length of a GPU device name (null-terminated).
const GPU_NAME_MAX: usize = 64;

/// Static information about a discovered GPU device.
///
/// Populated during device enumeration. The `mmio_base` and `mmio_size`
/// fields correspond to the device's MMIO register region, matching
/// the layout in [`DeviceLease`](rvm_types::DeviceLease).
#[derive(Debug, Clone, Copy)]
pub struct GpuDeviceInfo {
    /// Unique device identifier (0-based index from enumeration).
    pub id: u32,
    /// Null-terminated device name (UTF-8 subset, padded with zeros).
    pub name: [u8; GPU_NAME_MAX],
    /// Length of the device name (excluding null terminator).
    pub name_len: u8,
    /// GPU compute tier this device belongs to.
    pub tier: GpuTier,
    /// Number of compute units (shader cores / streaming multiprocessors).
    pub compute_units: u32,
    /// Total device memory in bytes.
    pub memory_bytes: u64,
    /// Maximum workgroup size (threads per workgroup).
    pub max_workgroup_size: u32,
    /// Maximum buffer allocation size in bytes.
    pub max_buffer_size: u64,
    /// Whether the device supports half-precision (f16) compute.
    pub supports_f16: bool,
    /// Whether the device supports double-precision (f64) compute.
    pub supports_f64: bool,
    /// MMIO register base address.
    pub mmio_base: u64,
    /// MMIO register region size in bytes.
    pub mmio_size: u64,
}

impl GpuDeviceInfo {
    /// Return the device name as a `&str`, or an empty string if invalid UTF-8.
    #[must_use]
    pub fn name_str(&self) -> &str {
        let len = self.name_len as usize;
        if len > GPU_NAME_MAX {
            return "";
        }
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

impl Default for GpuDeviceInfo {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0u8; GPU_NAME_MAX],
            name_len: 0,
            tier: GpuTier::WasmSimd,
            compute_units: 0,
            memory_bytes: 0,
            max_workgroup_size: 0,
            max_buffer_size: 0,
            supports_f16: false,
            supports_f64: false,
            mmio_base: 0,
            mmio_size: 0,
        }
    }
}

/// Detailed compute capabilities of a GPU device.
///
/// Queried after device discovery to determine what features are
/// available for kernel compilation and launch configuration.
#[derive(Debug, Clone, Copy)]
pub struct GpuCapabilities {
    /// Maximum number of kernels that can execute concurrently.
    pub max_concurrent_kernels: u32,
    /// Maximum shared memory per workgroup in bytes.
    pub max_shared_memory: u64,
    /// Warp/wavefront size (threads that execute in lockstep).
    pub warp_size: u32,
    /// Whether the device supports async compute (overlapped copy + compute).
    pub supports_async_compute: bool,
    /// Whether the device supports unified (shared) host-device memory.
    pub supports_unified_memory: bool,
}

impl Default for GpuCapabilities {
    fn default() -> Self {
        Self {
            max_concurrent_kernels: 1,
            max_shared_memory: 0,
            warp_size: 32,
            supports_async_compute: false,
            supports_unified_memory: false,
        }
    }
}

/// Top-level GPU device handle combining device info and capabilities.
///
/// Represents a single discovered GPU device that has been probed
/// for its hardware capabilities. The `info` field is populated at
/// enumeration time; `capabilities` is populated during initialization.
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuDevice {
    /// Static device information from enumeration.
    pub info: GpuDeviceInfo,
    /// Detailed compute capabilities from device query.
    pub capabilities: GpuCapabilities,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_info_name_str_valid() {
        let mut info = GpuDeviceInfo::default();
        let name = b"TestGPU";
        info.name[..name.len()].copy_from_slice(name);
        info.name_len = name.len() as u8;
        assert_eq!(info.name_str(), "TestGPU");
    }

    #[test]
    fn device_info_name_str_empty() {
        let info = GpuDeviceInfo::default();
        assert_eq!(info.name_str(), "");
    }

    #[test]
    fn device_info_name_str_full_length() {
        let mut info = GpuDeviceInfo::default();
        for (i, byte) in info.name.iter_mut().enumerate() {
            // Fill with printable ASCII: 'A' + (i % 26)
            *byte = b'A' + (i % 26) as u8;
        }
        info.name_len = 64;
        assert_eq!(info.name_str().len(), 64);
    }

    #[test]
    fn device_info_default_tier() {
        let info = GpuDeviceInfo::default();
        assert_eq!(info.tier, GpuTier::WasmSimd);
        assert_eq!(info.compute_units, 0);
        assert_eq!(info.memory_bytes, 0);
    }

    #[test]
    fn gpu_capabilities_default() {
        let caps = GpuCapabilities::default();
        assert_eq!(caps.max_concurrent_kernels, 1);
        assert_eq!(caps.warp_size, 32);
        assert!(!caps.supports_async_compute);
        assert!(!caps.supports_unified_memory);
    }

    #[test]
    fn gpu_device_default() {
        let dev = GpuDevice::default();
        assert_eq!(dev.info.id, 0);
        assert_eq!(dev.capabilities.warp_size, 32);
    }
}
