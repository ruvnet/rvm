//! # RVM GPU Compute Subsystem
//!
//! Optional GPU compute support for the RVM coherence-native microhypervisor,
//! as specified in ADR-144. This crate provides:
//!
//! - **Device discovery** ([`device`]): GPU hardware enumeration and capability query
//! - **Per-partition context** ([`context`]): isolated GPU state with budget enforcement
//! - **Kernel management** ([`kernel`]): compiled compute kernel lifecycle
//! - **Buffer management** ([`buffer`]): typed GPU memory buffers with usage flags
//! - **Command queues** ([`queue`]): bounded command submission queues
//! - **Budget enforcement** ([`budget`]): GPU-specific per-epoch resource quotas
//! - **Coherence acceleration** ([`accel`]): GPU-accelerated mincut and scoring
//! - **Error types** ([`error`]): unified GPU error enum
//!
//! ## Design Constraints (ADR-144)
//!
//! - DC-GPU-1: GPU access is capability-gated (`CapRights::EXECUTE | WRITE`)
//! - DC-GPU-2: GPU memory isolated via IOMMU page tables
//! - DC-GPU-3: DMA budget enforced per partition per epoch
//! - DC-GPU-4: GPU context saved/restored lazily on partition switch
//! - DC-GPU-5: All GPU operations emit witness records
//! - DC-GPU-6: Feature-gated -- zero cost when disabled
//! - DC-GPU-7: Tiered backends -- `wasm-simd` (Seed), `webgpu`/`cuda` (Appliance)
//!
//! ## Feature Flags
//!
//! | Feature | Backend | Hardware Profile |
//! |---------|---------|-----------------|
//! | `wasm-simd` | WASM SIMD fallback | Seed (64KB-1MB) |
//! | `webgpu` | WebGPU | Appliance (1-32GB) |
//! | `cuda` | CUDA | Appliance (NVIDIA) |
//! | `opencl` | OpenCL | Appliance (cross-vendor) |
//! | `vulkan` | Vulkan compute | Chip (future) |

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_lossless,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::new_without_default,
    clippy::module_name_repetitions
)]

pub mod accel;
pub mod budget;
pub mod buffer;
pub mod context;
pub mod device;
pub mod error;
pub mod kernel;
pub mod queue;

// --- Re-exports ---
pub use accel::{GpuMinCutConfig, GpuMinCutResult, GpuScoringConfig};
pub use budget::GpuBudget;
pub use buffer::{BufferId, BufferUsage, GpuBuffer};
pub use context::GpuContext;
pub use device::{GpuCapabilities, GpuDevice, GpuDeviceInfo};
pub use error::GpuError;
pub use kernel::{GpuKernel, KernelId, LaunchConfig};
pub use queue::{CommandType, GpuQueue, QueueCommand, QueueId};

/// GPU compute tier, determined by hardware profile and feature flags.
///
/// Each tier corresponds to a `cuda-rust-wasm` backend and a target
/// hardware class. Tiers are ordered by capability: [`WasmSimd`](GpuTier::WasmSimd)
/// is the most constrained (CPU fallback), [`Cuda`](GpuTier::Cuda) is
/// the most capable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GpuTier {
    /// WASM SIMD: CPU-side SIMD fallback for Seed-profile hardware (64KB-1MB).
    /// No real GPU hardware required.
    WasmSimd = 0,
    /// WebGPU: browser-compatible GPU compute for Appliance-profile hardware.
    WebGpu = 1,
    /// CUDA: NVIDIA GPU compute for Appliance-profile hardware.
    Cuda = 2,
    /// OpenCL: cross-vendor GPU compute for Appliance-profile hardware.
    OpenCl = 3,
    /// Vulkan: low-level GPU compute for Chip-profile hardware (future).
    Vulkan = 4,
}

/// Runtime status of a GPU device or context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GpuStatus {
    /// No GPU hardware detected or backend not compiled.
    Unavailable = 0,
    /// GPU device is being initialized (driver load, IOMMU setup).
    Initializing = 1,
    /// GPU device is ready for compute operations.
    Ready = 2,
    /// GPU device encountered an unrecoverable error.
    Error = 3,
}

/// Maximum number of GPU devices supported by the hypervisor.
pub const MAX_GPU_DEVICES: usize = 8;

/// Maximum number of compiled kernels per partition.
pub const MAX_KERNELS_PER_PARTITION: usize = 64;

/// Default kernel execution timeout in nanoseconds (100ms).
///
/// Matches the DC-7 deadline model from ADR-132. Kernels exceeding
/// this deadline are terminated and the partition's GPU context is
/// marked as [`GpuStatus::Error`].
pub const DEFAULT_KERNEL_TIMEOUT_NS: u64 = 100_000_000;

#[cfg(test)]
#[path = "tests.rs"]
mod integration_tests;
