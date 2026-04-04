//! Zero-copy inter-partition message passing via `CommEdge`s.
//!
//! Messages are capability-checked and witnessed. Each `CommEdge`
//! has an associated fixed-size `MessageQueue` that provides bounded,
//! no-alloc message passing between partitions.
//!
//! ## Design Constraints
//!
//! - `#![no_std]`, zero heap allocation
//! - Fixed-capacity message queues (const generic `CAPACITY`)
//! - Weight tracking feeds the coherence graph (DC-2)
//! - Each IPC send increments the edge weight for coherence scoring

use rvm_types::{PartitionId, RvmError, RvmResult};

use crate::CommEdgeId;

/// Message header for typed IPC between partitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcMessage {
    /// Sending partition.
    pub sender: PartitionId,
    /// Receiving partition.
    pub receiver: PartitionId,
    /// The `CommEdge` this message traverses.
    pub edge_id: CommEdgeId,
    /// Payload length in bytes (application layer).
    pub payload_len: u16,
    /// Application-defined message type discriminant.
    pub msg_type: u16,
    /// Monotonic sequence number for ordering and dedup.
    pub sequence: u64,
    /// Truncated FNV-1a hash of the capability authorising this send.
    pub capability_hash: u32,
}

/// Fixed-size ring-buffer message queue per `CommEdge`.
///
/// `CAPACITY` must be a power of two for efficient modular arithmetic,
/// but the implementation works correctly for any non-zero capacity.
pub struct MessageQueue<const CAPACITY: usize> {
    buffer: [Option<IpcMessage>; CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
}

/// Sentinel for const array init.
const EMPTY_MSG: Option<IpcMessage> = None;

impl<const CAPACITY: usize> MessageQueue<CAPACITY> {
    /// Create a new empty message queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: [EMPTY_MSG; CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Enqueue a message.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the queue is full.
    pub fn send(&mut self, msg: IpcMessage) -> RvmResult<()> {
        if self.count >= CAPACITY {
            return Err(RvmError::ResourceLimitExceeded);
        }
        self.buffer[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Dequeue a message, returning `None` if the queue is empty.
    pub fn receive(&mut self) -> Option<IpcMessage> {
        if self.count == 0 {
            return None;
        }
        let msg = self.buffer[self.head].take();
        self.head = (self.head + 1) % CAPACITY;
        self.count -= 1;
        msg
    }

    /// Check whether the queue is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.count >= CAPACITY
    }

    /// Check whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the number of messages currently in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<const CAPACITY: usize> Default for MessageQueue<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

/// IPC manager connecting partitions via `CommEdge` channels.
///
/// `MAX_EDGES` is the maximum number of concurrent IPC channels.
/// `QUEUE_SIZE` is the per-channel message queue capacity.
pub struct IpcManager<const MAX_EDGES: usize, const QUEUE_SIZE: usize> {
    /// Per-edge message queues.
    queues: [Option<ChannelMeta<QUEUE_SIZE>>; MAX_EDGES],
    /// Number of active channels.
    edge_count: usize,
    /// Next edge ID to assign.
    next_edge_id: u64,
}

/// Metadata for an active IPC channel.
struct ChannelMeta<const QUEUE_SIZE: usize> {
    edge_id: CommEdgeId,
    #[allow(dead_code)]
    source: PartitionId,
    #[allow(dead_code)]
    dest: PartitionId,
    queue: MessageQueue<QUEUE_SIZE>,
    /// Accumulated weight (number of messages sent) for coherence.
    weight: u64,
}

/// Sentinel for const array init.
const fn none_channel<const Q: usize>() -> Option<ChannelMeta<Q>> {
    None
}

impl<const MAX_EDGES: usize, const QUEUE_SIZE: usize> IpcManager<MAX_EDGES, QUEUE_SIZE> {
    /// Create a new IPC manager with no active channels.
    #[must_use]
    pub fn new() -> Self {
        // Work around const-generic limitations for array init.
        let mut queues: [Option<ChannelMeta<QUEUE_SIZE>>; MAX_EDGES] =
            // SAFETY: MaybeUninit is not needed; we initialise via loop below.
            core::array::from_fn(|_| none_channel::<QUEUE_SIZE>());
        // Redundant but explicit: ensure all slots are None.
        for slot in &mut queues {
            *slot = None;
        }
        Self {
            queues,
            edge_count: 0,
            next_edge_id: 1,
        }
    }

    /// Create a new IPC channel between two partitions.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if no channel slots are available.
    pub fn create_channel(
        &mut self,
        from: PartitionId,
        to: PartitionId,
    ) -> RvmResult<CommEdgeId> {
        if self.edge_count >= MAX_EDGES {
            return Err(RvmError::ResourceLimitExceeded);
        }
        let edge_id = CommEdgeId::new(self.next_edge_id);
        self.next_edge_id += 1;

        for slot in &mut self.queues {
            if slot.is_none() {
                *slot = Some(ChannelMeta {
                    edge_id,
                    source: from,
                    dest: to,
                    queue: MessageQueue::new(),
                    weight: 0,
                });
                self.edge_count += 1;
                return Ok(edge_id);
            }
        }
        Err(RvmError::InternalError)
    }

    /// Send a message on an existing channel.
    ///
    /// Increments the edge weight for coherence scoring on success.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the edge does not exist.
    /// Returns [`RvmError::ResourceLimitExceeded`] if the queue is full.
    pub fn send(&mut self, edge_id: CommEdgeId, msg: IpcMessage) -> RvmResult<()> {
        let channel = self.find_mut(edge_id)?;
        channel.queue.send(msg)?;
        channel.weight = channel.weight.saturating_add(1);
        Ok(())
    }

    /// Receive a message from an existing channel.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the edge does not exist.
    pub fn receive(&mut self, edge_id: CommEdgeId) -> RvmResult<Option<IpcMessage>> {
        let channel = self.find_mut(edge_id)?;
        Ok(channel.queue.receive())
    }

    /// Destroy a channel, releasing its slot.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the edge does not exist.
    pub fn destroy_channel(&mut self, edge_id: CommEdgeId) -> RvmResult<()> {
        for slot in &mut self.queues {
            let matches = slot
                .as_ref()
                .is_some_and(|ch| ch.edge_id == edge_id);
            if matches {
                *slot = None;
                self.edge_count -= 1;
                return Ok(());
            }
        }
        Err(RvmError::PartitionNotFound)
    }

    /// Return the accumulated weight (send count) for a channel.
    ///
    /// This feeds the coherence graph for mincut computation.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the edge does not exist.
    pub fn comm_weight(&self, edge_id: CommEdgeId) -> RvmResult<u64> {
        let channel = self.find(edge_id)?;
        Ok(channel.weight)
    }

    /// Return the number of active channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.edge_count
    }

    fn find(&self, edge_id: CommEdgeId) -> RvmResult<&ChannelMeta<QUEUE_SIZE>> {
        for ch in self.queues.iter().flatten() {
            if ch.edge_id == edge_id {
                return Ok(ch);
            }
        }
        Err(RvmError::PartitionNotFound)
    }

    fn find_mut(&mut self, edge_id: CommEdgeId) -> RvmResult<&mut ChannelMeta<QUEUE_SIZE>> {
        for ch in self.queues.iter_mut().flatten() {
            if ch.edge_id == edge_id {
                return Ok(ch);
            }
        }
        Err(RvmError::PartitionNotFound)
    }
}

impl<const MAX_EDGES: usize, const QUEUE_SIZE: usize> Default
    for IpcManager<MAX_EDGES, QUEUE_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(id: u32) -> PartitionId {
        PartitionId::new(id)
    }

    fn make_msg(sender: u32, receiver: u32, edge_id: CommEdgeId, seq: u64) -> IpcMessage {
        IpcMessage {
            sender: pid(sender),
            receiver: pid(receiver),
            edge_id,
            payload_len: 0,
            msg_type: 1,
            sequence: seq,
            capability_hash: 0xABCD,
        }
    }

    // ---------------------------------------------------------------
    // MessageQueue tests
    // ---------------------------------------------------------------

    #[test]
    fn queue_send_receive() {
        let mut q = MessageQueue::<4>::new();
        let edge = CommEdgeId::new(1);
        let msg = make_msg(1, 2, edge, 1);

        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 0);

        q.send(msg).unwrap();
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());

        let received = q.receive().unwrap();
        assert_eq!(received.sequence, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn queue_fifo_order() {
        let mut q = MessageQueue::<4>::new();
        let edge = CommEdgeId::new(1);

        for i in 1..=3 {
            q.send(make_msg(1, 2, edge, i)).unwrap();
        }

        assert_eq!(q.receive().unwrap().sequence, 1);
        assert_eq!(q.receive().unwrap().sequence, 2);
        assert_eq!(q.receive().unwrap().sequence, 3);
        assert!(q.receive().is_none());
    }

    #[test]
    fn queue_full() {
        let mut q = MessageQueue::<2>::new();
        let edge = CommEdgeId::new(1);

        q.send(make_msg(1, 2, edge, 1)).unwrap();
        q.send(make_msg(1, 2, edge, 2)).unwrap();
        assert!(q.is_full());

        assert_eq!(
            q.send(make_msg(1, 2, edge, 3)),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn queue_empty_receive() {
        let mut q = MessageQueue::<4>::new();
        assert!(q.receive().is_none());
    }

    #[test]
    fn queue_wrap_around() {
        let mut q = MessageQueue::<2>::new();
        let edge = CommEdgeId::new(1);

        // Fill and drain twice to test wrap-around.
        q.send(make_msg(1, 2, edge, 1)).unwrap();
        q.send(make_msg(1, 2, edge, 2)).unwrap();
        assert_eq!(q.receive().unwrap().sequence, 1);
        assert_eq!(q.receive().unwrap().sequence, 2);

        q.send(make_msg(1, 2, edge, 3)).unwrap();
        q.send(make_msg(1, 2, edge, 4)).unwrap();
        assert_eq!(q.receive().unwrap().sequence, 3);
        assert_eq!(q.receive().unwrap().sequence, 4);
    }

    // ---------------------------------------------------------------
    // IpcManager tests
    // ---------------------------------------------------------------

    #[test]
    fn manager_create_and_send() {
        let mut mgr = IpcManager::<4, 8>::new();
        let edge = mgr.create_channel(pid(1), pid(2)).unwrap();

        let msg = make_msg(1, 2, edge, 1);
        mgr.send(edge, msg).unwrap();

        let received = mgr.receive(edge).unwrap().unwrap();
        assert_eq!(received.sequence, 1);
    }

    #[test]
    fn manager_multiple_channels() {
        let mut mgr = IpcManager::<4, 8>::new();
        let e1 = mgr.create_channel(pid(1), pid(2)).unwrap();
        let e2 = mgr.create_channel(pid(2), pid(3)).unwrap();

        assert_ne!(e1, e2);
        assert_eq!(mgr.channel_count(), 2);

        mgr.send(e1, make_msg(1, 2, e1, 10)).unwrap();
        mgr.send(e2, make_msg(2, 3, e2, 20)).unwrap();

        assert_eq!(mgr.receive(e1).unwrap().unwrap().sequence, 10);
        assert_eq!(mgr.receive(e2).unwrap().unwrap().sequence, 20);
    }

    #[test]
    fn manager_channel_limit() {
        let mut mgr = IpcManager::<2, 4>::new();
        mgr.create_channel(pid(1), pid(2)).unwrap();
        mgr.create_channel(pid(2), pid(3)).unwrap();

        assert_eq!(
            mgr.create_channel(pid(3), pid(4)),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn manager_destroy_channel() {
        let mut mgr = IpcManager::<4, 8>::new();
        let edge = mgr.create_channel(pid(1), pid(2)).unwrap();
        assert_eq!(mgr.channel_count(), 1);

        mgr.destroy_channel(edge).unwrap();
        assert_eq!(mgr.channel_count(), 0);

        // Sending to a destroyed channel should fail.
        assert_eq!(
            mgr.send(edge, make_msg(1, 2, edge, 1)),
            Err(RvmError::PartitionNotFound)
        );
    }

    #[test]
    fn manager_destroy_nonexistent() {
        let mut mgr = IpcManager::<4, 8>::new();
        assert_eq!(
            mgr.destroy_channel(CommEdgeId::new(999)),
            Err(RvmError::PartitionNotFound)
        );
    }

    #[test]
    fn manager_weight_tracking() {
        let mut mgr = IpcManager::<4, 8>::new();
        let edge = mgr.create_channel(pid(1), pid(2)).unwrap();

        assert_eq!(mgr.comm_weight(edge).unwrap(), 0);

        mgr.send(edge, make_msg(1, 2, edge, 1)).unwrap();
        assert_eq!(mgr.comm_weight(edge).unwrap(), 1);

        mgr.send(edge, make_msg(1, 2, edge, 2)).unwrap();
        mgr.send(edge, make_msg(1, 2, edge, 3)).unwrap();
        assert_eq!(mgr.comm_weight(edge).unwrap(), 3);
    }

    #[test]
    fn manager_receive_empty() {
        let mut mgr = IpcManager::<4, 8>::new();
        let edge = mgr.create_channel(pid(1), pid(2)).unwrap();
        assert!(mgr.receive(edge).unwrap().is_none());
    }

    #[test]
    fn manager_receive_nonexistent() {
        let mut mgr = IpcManager::<4, 8>::new();
        assert_eq!(
            mgr.receive(CommEdgeId::new(999)),
            Err(RvmError::PartitionNotFound)
        );
    }

    #[test]
    fn manager_reuse_slot_after_destroy() {
        let mut mgr = IpcManager::<2, 4>::new();
        let e1 = mgr.create_channel(pid(1), pid(2)).unwrap();
        let _e2 = mgr.create_channel(pid(2), pid(3)).unwrap();

        // At capacity.
        assert_eq!(
            mgr.create_channel(pid(3), pid(4)),
            Err(RvmError::ResourceLimitExceeded)
        );

        // Destroy one, then create a new one.
        mgr.destroy_channel(e1).unwrap();
        let e3 = mgr.create_channel(pid(3), pid(4)).unwrap();
        assert_ne!(e1, e3);
        assert_eq!(mgr.channel_count(), 2);
    }

    #[test]
    fn manager_queue_full_on_channel() {
        let mut mgr = IpcManager::<4, 2>::new();
        let edge = mgr.create_channel(pid(1), pid(2)).unwrap();

        mgr.send(edge, make_msg(1, 2, edge, 1)).unwrap();
        mgr.send(edge, make_msg(1, 2, edge, 2)).unwrap();
        assert_eq!(
            mgr.send(edge, make_msg(1, 2, edge, 3)),
            Err(RvmError::ResourceLimitExceeded)
        );
    }
}
