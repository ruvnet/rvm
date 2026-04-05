//! GPU command queue management.
//!
//! Each partition's GPU context has a bounded [`GpuQueue`] for submitting
//! commands to the GPU. Commands include kernel launches, buffer copies,
//! fills, barriers, and timestamp queries. The queue has a fixed maximum
//! depth to prevent unbounded resource consumption.
//!
//! Commands are submitted via [`enqueue`](GpuQueue::enqueue) and
//! completed asynchronously. The `submitted` and `completed` counters
//! track lifetime command throughput.

use rvm_types::PartitionId;

use crate::buffer::BufferId;
use crate::error::GpuError;
use crate::kernel::KernelId;

/// Maximum queue depth if not otherwise configured.
const DEFAULT_MAX_QUEUE_DEPTH: u32 = 256;

/// Unique identifier for a command queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct QueueId(u32);

impl QueueId {
    /// Create a new queue identifier.
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

/// Type of command in the GPU command queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CommandType {
    /// Launch a compiled GPU kernel.
    KernelLaunch = 0,
    /// Copy data between two GPU buffers.
    BufferCopy = 1,
    /// Fill a GPU buffer with a constant value.
    BufferFill = 2,
    /// Insert a pipeline barrier (execution + memory fence).
    Barrier = 3,
    /// Write a GPU timestamp for profiling.
    TimestampQuery = 4,
}

/// A GPU command queue bound to a partition.
///
/// Queues have a fixed maximum depth. When the queue is full, new
/// commands are rejected with [`GpuError::QueueFull`]. The `submitted`
/// and `completed` counters provide lifetime throughput metrics.
#[derive(Debug, Clone, Copy)]
pub struct GpuQueue {
    /// Unique identifier for this queue.
    pub id: QueueId,
    /// The partition that owns this queue.
    pub partition_id: PartitionId,
    /// Current number of commands in the queue (pending).
    pub depth: u32,
    /// Maximum number of pending commands.
    pub max_depth: u32,
    /// Total commands submitted over the queue's lifetime.
    pub submitted: u64,
    /// Total commands completed over the queue's lifetime.
    pub completed: u64,
}

impl GpuQueue {
    /// Create a new empty queue with the default maximum depth.
    #[must_use]
    pub const fn new(id: QueueId, partition_id: PartitionId) -> Self {
        Self {
            id,
            partition_id,
            depth: 0,
            max_depth: DEFAULT_MAX_QUEUE_DEPTH,
            submitted: 0,
            completed: 0,
        }
    }

    /// Create a new empty queue with a custom maximum depth.
    ///
    /// The minimum allowed depth is 1. If `max_depth` is 0, it is
    /// clamped to 1 to prevent creating an unusable queue.
    #[must_use]
    pub const fn with_max_depth(id: QueueId, partition_id: PartitionId, max_depth: u32) -> Self {
        let effective_depth = if max_depth == 0 { 1 } else { max_depth };
        Self {
            id,
            partition_id,
            depth: 0,
            max_depth: effective_depth,
            submitted: 0,
            completed: 0,
        }
    }

    /// Check whether the queue has reached its depth limit.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.depth >= self.max_depth
    }

    /// Check whether a command can be submitted (queue not full).
    #[must_use]
    pub const fn can_submit(&self) -> bool {
        self.depth < self.max_depth
    }

    /// Enqueue a command, incrementing the depth and submitted count.
    ///
    /// The command is validated before submission. Invalid commands
    /// (e.g., a `KernelLaunch` without a `kernel_id`) are rejected.
    ///
    /// # Errors
    ///
    /// Returns a [`GpuError`] if the command fails validation.
    /// Returns [`GpuError::QueueFull`] if the queue has reached its
    /// maximum depth.
    pub fn enqueue(&mut self, command: &QueueCommand) -> Result<(), GpuError> {
        command.validate()?;
        if self.is_full() {
            return Err(GpuError::QueueFull);
        }
        self.depth += 1;
        self.submitted += 1;
        Ok(())
    }

    /// Mark a command as completed, decrementing the depth.
    ///
    /// # Errors
    ///
    /// Returns [`GpuError::DeviceNotReady`] if the queue has no
    /// pending commands (underflow).
    pub fn complete_one(&mut self) -> Result<(), GpuError> {
        if self.depth == 0 {
            return Err(GpuError::DeviceNotReady);
        }
        self.depth -= 1;
        self.completed += 1;
        Ok(())
    }

    /// Return the number of commands currently in flight.
    #[must_use]
    pub const fn pending(&self) -> u32 {
        self.depth
    }
}

/// A single command to be submitted to a GPU queue.
///
/// The interpretation of `kernel_id`, `buffer_src`, `buffer_dst`, and
/// `size_bytes` depends on the [`CommandType`]:
///
/// - `KernelLaunch`: `kernel_id` is required; buffers and size are unused.
/// - `BufferCopy`: `buffer_src` and `buffer_dst` required; `size_bytes` is the copy length.
/// - `BufferFill`: `buffer_dst` required; `size_bytes` is the fill length.
/// - `Barrier`: all fields unused (pure synchronization).
/// - `TimestampQuery`: all fields unused.
#[derive(Debug, Clone, Copy)]
pub struct QueueCommand {
    /// The type of GPU command.
    pub cmd_type: CommandType,
    /// Kernel to launch (for `KernelLaunch` commands).
    pub kernel_id: Option<KernelId>,
    /// Source buffer (for `BufferCopy` commands).
    pub buffer_src: Option<BufferId>,
    /// Destination buffer (for `BufferCopy` and `BufferFill` commands).
    pub buffer_dst: Option<BufferId>,
    /// Byte count for copy/fill operations.
    pub size_bytes: u64,
}

impl QueueCommand {
    /// Create a kernel launch command.
    #[must_use]
    pub const fn kernel_launch(kernel_id: KernelId) -> Self {
        Self {
            cmd_type: CommandType::KernelLaunch,
            kernel_id: Some(kernel_id),
            buffer_src: None,
            buffer_dst: None,
            size_bytes: 0,
        }
    }

    /// Create a buffer copy command.
    #[must_use]
    pub const fn buffer_copy(src: BufferId, dst: BufferId, size: u64) -> Self {
        Self {
            cmd_type: CommandType::BufferCopy,
            kernel_id: None,
            buffer_src: Some(src),
            buffer_dst: Some(dst),
            size_bytes: size,
        }
    }

    /// Create a buffer fill command.
    #[must_use]
    pub const fn buffer_fill(dst: BufferId, size: u64) -> Self {
        Self {
            cmd_type: CommandType::BufferFill,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: Some(dst),
            size_bytes: size,
        }
    }

    /// Create a barrier command.
    #[must_use]
    pub const fn barrier() -> Self {
        Self {
            cmd_type: CommandType::Barrier,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: None,
            size_bytes: 0,
        }
    }

    /// Create a timestamp query command.
    #[must_use]
    pub const fn timestamp_query() -> Self {
        Self {
            cmd_type: CommandType::TimestampQuery,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: None,
            size_bytes: 0,
        }
    }

    /// Validate that the command's fields are consistent with its type.
    ///
    /// # Errors
    ///
    /// Returns [`GpuError::InvalidLaunchConfig`] if required fields are
    /// missing for the given [`CommandType`].
    pub const fn validate(&self) -> Result<(), GpuError> {
        match self.cmd_type {
            CommandType::KernelLaunch => {
                if self.kernel_id.is_none() {
                    return Err(GpuError::InvalidLaunchConfig);
                }
            }
            CommandType::BufferCopy => {
                if self.buffer_src.is_none() || self.buffer_dst.is_none() || self.size_bytes == 0 {
                    return Err(GpuError::InvalidLaunchConfig);
                }
            }
            CommandType::BufferFill => {
                if self.buffer_dst.is_none() || self.size_bytes == 0 {
                    return Err(GpuError::InvalidLaunchConfig);
                }
            }
            CommandType::Barrier | CommandType::TimestampQuery => {
                // Always valid
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_partition() -> PartitionId {
        PartitionId::new(1)
    }

    #[test]
    fn queue_id_round_trip() {
        let id = QueueId::new(7);
        assert_eq!(id.as_u32(), 7);
    }

    #[test]
    fn new_queue_is_empty() {
        let q = GpuQueue::new(QueueId::new(0), test_partition());
        assert_eq!(q.depth, 0);
        assert_eq!(q.max_depth, DEFAULT_MAX_QUEUE_DEPTH);
        assert!(!q.is_full());
        assert!(q.can_submit());
        assert_eq!(q.pending(), 0);
    }

    #[test]
    fn enqueue_increments_counters() {
        let mut q = GpuQueue::new(QueueId::new(0), test_partition());
        let cmd = QueueCommand::barrier();
        assert!(q.enqueue(&cmd).is_ok());
        assert_eq!(q.depth, 1);
        assert_eq!(q.submitted, 1);
        assert_eq!(q.completed, 0);
    }

    #[test]
    fn complete_decrements_depth() {
        let mut q = GpuQueue::new(QueueId::new(0), test_partition());
        let cmd = QueueCommand::barrier();
        q.enqueue(&cmd).unwrap();
        q.enqueue(&cmd).unwrap();
        q.complete_one().unwrap();
        assert_eq!(q.depth, 1);
        assert_eq!(q.completed, 1);
        assert_eq!(q.submitted, 2);
    }

    #[test]
    fn complete_one_underflow_returns_error() {
        let mut q = GpuQueue::new(QueueId::new(0), test_partition());
        assert_eq!(q.complete_one(), Err(GpuError::DeviceNotReady));
    }

    #[test]
    fn with_max_depth_zero_clamps_to_one() {
        let q = GpuQueue::with_max_depth(QueueId::new(0), test_partition(), 0);
        assert_eq!(q.max_depth, 1);
        assert!(q.can_submit());
    }

    #[test]
    fn queue_full_rejects() {
        let mut q = GpuQueue::with_max_depth(QueueId::new(0), test_partition(), 2);
        let cmd = QueueCommand::barrier();
        assert!(q.enqueue(&cmd).is_ok());
        assert!(q.enqueue(&cmd).is_ok());
        assert!(q.is_full());
        assert!(!q.can_submit());
        assert_eq!(q.enqueue(&cmd), Err(GpuError::QueueFull));
    }

    #[test]
    fn queue_full_then_complete_allows_more() {
        let mut q = GpuQueue::with_max_depth(QueueId::new(0), test_partition(), 1);
        let cmd = QueueCommand::barrier();
        q.enqueue(&cmd).unwrap();
        assert!(q.is_full());
        q.complete_one().unwrap();
        assert!(!q.is_full());
        assert!(q.enqueue(&cmd).is_ok());
    }

    #[test]
    fn command_type_repr_values() {
        assert_eq!(CommandType::KernelLaunch as u8, 0);
        assert_eq!(CommandType::BufferCopy as u8, 1);
        assert_eq!(CommandType::BufferFill as u8, 2);
        assert_eq!(CommandType::Barrier as u8, 3);
        assert_eq!(CommandType::TimestampQuery as u8, 4);
    }

    #[test]
    fn command_constructors() {
        let launch = QueueCommand::kernel_launch(KernelId::new(5));
        assert_eq!(launch.cmd_type, CommandType::KernelLaunch);
        assert_eq!(launch.kernel_id, Some(KernelId::new(5)));

        let copy = QueueCommand::buffer_copy(BufferId::new(1), BufferId::new(2), 4096);
        assert_eq!(copy.cmd_type, CommandType::BufferCopy);
        assert_eq!(copy.buffer_src, Some(BufferId::new(1)));
        assert_eq!(copy.buffer_dst, Some(BufferId::new(2)));
        assert_eq!(copy.size_bytes, 4096);

        let fill = QueueCommand::buffer_fill(BufferId::new(3), 1024);
        assert_eq!(fill.cmd_type, CommandType::BufferFill);
        assert_eq!(fill.buffer_dst, Some(BufferId::new(3)));
        assert_eq!(fill.size_bytes, 1024);

        let barrier = QueueCommand::barrier();
        assert_eq!(barrier.cmd_type, CommandType::Barrier);
        assert!(barrier.kernel_id.is_none());

        let ts = QueueCommand::timestamp_query();
        assert_eq!(ts.cmd_type, CommandType::TimestampQuery);
    }

    #[test]
    fn command_validate_kernel_launch_missing_id() {
        let bad = QueueCommand {
            cmd_type: CommandType::KernelLaunch,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: None,
            size_bytes: 0,
        };
        assert_eq!(bad.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn command_validate_buffer_copy_missing_fields() {
        // Missing src
        let bad = QueueCommand {
            cmd_type: CommandType::BufferCopy,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: Some(BufferId::new(1)),
            size_bytes: 100,
        };
        assert_eq!(bad.validate(), Err(GpuError::InvalidLaunchConfig));

        // Zero size
        let bad2 = QueueCommand::buffer_copy(BufferId::new(0), BufferId::new(1), 0);
        assert_eq!(bad2.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn command_validate_buffer_fill_missing_fields() {
        let bad = QueueCommand {
            cmd_type: CommandType::BufferFill,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: None,
            size_bytes: 100,
        };
        assert_eq!(bad.validate(), Err(GpuError::InvalidLaunchConfig));
    }

    #[test]
    fn enqueue_rejects_invalid_command() {
        let mut q = GpuQueue::new(QueueId::new(0), test_partition());
        let bad = QueueCommand {
            cmd_type: CommandType::KernelLaunch,
            kernel_id: None,
            buffer_src: None,
            buffer_dst: None,
            size_bytes: 0,
        };
        assert_eq!(q.enqueue(&bad), Err(GpuError::InvalidLaunchConfig));
        assert_eq!(q.depth, 0); // Nothing enqueued
    }
}
