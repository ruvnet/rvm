//! GPU buffer management.
//!
//! GPU buffers are typed memory regions allocated on the GPU device.
//! Each buffer has a [`BufferUsage`] that constrains how it can be
//! bound to kernel arguments and copy operations. Buffers are owned
//! by a partition and count against its [`GpuBudget`](crate::GpuBudget)
//! memory quota.
//!
//! All buffer allocations are validated against the device's
//! `max_buffer_size` before submission to prevent oversized requests
//! from reaching the driver layer.

use rvm_types::PartitionId;

use crate::error::GpuError;

/// Unique identifier for a GPU buffer within a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BufferId(u32);

impl BufferId {
    /// Create a new buffer identifier.
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

/// Intended usage of a GPU buffer.
///
/// Usage flags determine how the buffer can be bound in kernel launches
/// and copy operations. The driver may use these hints for placement
/// optimization (e.g., uniform buffers in constant memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BufferUsage {
    /// General-purpose read/write storage (SSBO equivalent).
    Storage = 0,
    /// Read-only uniform data (UBO equivalent, constant memory).
    Uniform = 1,
    /// Vertex attribute data (for rendering workloads).
    Vertex = 2,
    /// Index data (for rendering workloads).
    Index = 3,
    /// Indirect dispatch/draw arguments.
    Indirect = 4,
    /// Source for copy operations.
    CopySrc = 5,
    /// Destination for copy operations.
    CopyDst = 6,
}

/// A GPU memory buffer owned by a partition.
///
/// Buffers are allocated through the GPU context and count against
/// the partition's memory budget. The `host_mapped` flag indicates
/// whether the buffer is accessible from the host CPU (unified memory
/// or staging buffer).
#[derive(Debug, Clone, Copy)]
pub struct GpuBuffer {
    /// Unique identifier for this buffer within its partition.
    pub id: BufferId,
    /// The partition that owns this buffer.
    pub partition_id: PartitionId,
    /// Buffer size in bytes.
    pub size_bytes: u64,
    /// Intended buffer usage.
    pub usage: BufferUsage,
    /// Whether this buffer is host-mapped (CPU-accessible).
    pub host_mapped: bool,
}

/// Validate a buffer allocation request.
///
/// Checks that the size is non-zero and does not exceed the device's
/// maximum buffer size.
///
/// # Errors
///
/// Returns [`GpuError::BufferTooLarge`] if `size_bytes` is zero (invalid size).
/// Returns [`GpuError::BufferTooLarge`] if `size_bytes` exceeds `max_buffer_size`.
pub const fn validate_buffer(size_bytes: u64, max_buffer_size: u64) -> Result<(), GpuError> {
    if size_bytes == 0 {
        return Err(GpuError::BufferTooLarge);
    }
    if size_bytes > max_buffer_size {
        return Err(GpuError::BufferTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_id_round_trip() {
        let id = BufferId::new(99);
        assert_eq!(id.as_u32(), 99);
    }

    #[test]
    fn buffer_usage_repr_values() {
        assert_eq!(BufferUsage::Storage as u8, 0);
        assert_eq!(BufferUsage::Uniform as u8, 1);
        assert_eq!(BufferUsage::Vertex as u8, 2);
        assert_eq!(BufferUsage::Index as u8, 3);
        assert_eq!(BufferUsage::Indirect as u8, 4);
        assert_eq!(BufferUsage::CopySrc as u8, 5);
        assert_eq!(BufferUsage::CopyDst as u8, 6);
    }

    #[test]
    fn validate_buffer_valid() {
        assert!(validate_buffer(4096, 1_073_741_824).is_ok());
    }

    #[test]
    fn validate_buffer_zero_size() {
        assert_eq!(validate_buffer(0, 1024), Err(GpuError::BufferTooLarge));
    }

    #[test]
    fn validate_buffer_too_large() {
        assert_eq!(validate_buffer(2048, 1024), Err(GpuError::BufferTooLarge));
    }

    #[test]
    fn validate_buffer_exact_max() {
        assert!(validate_buffer(1024, 1024).is_ok());
    }

    #[test]
    fn gpu_buffer_struct() {
        let buf = GpuBuffer {
            id: BufferId::new(0),
            partition_id: PartitionId::new(1),
            size_bytes: 4096,
            usage: BufferUsage::Storage,
            host_mapped: false,
        };
        assert_eq!(buf.size_bytes, 4096);
        assert!(!buf.host_mapped);
    }
}
