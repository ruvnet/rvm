# ADR-145: IPC Protocol Semantics

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core, DC-2 coherence graph), ADR-134 (Witness Schema), ADR-135 (Proof Verifier)

---

## Context

RVM partitions communicate through weighted `CommEdge` channels whose message
activity feeds the coherence graph used for mincut computation (DC-2). The deep
review identified that while `rvm-partition/src/ipc.rs` provides a working IPC
implementation, the protocol semantics -- ordering guarantees, backpressure
behaviour, capability gating, witness integration, and cross-partition delivery
rules -- are not formally specified. Without a specification, integrators
cannot reason about message delivery guarantees, and the coherence engine cannot
rely on weight accuracy.

### Problem Statement

1. **No ordering specification**: FIFO is implemented but not declared as a guarantee.
2. **Backpressure is error-only**: `send()` returns `ResourceLimitExceeded` when the queue is full, but there is no retry protocol or sender notification mechanism.
3. **Capability gating is partial**: `send()` validates `msg.sender == caller_id` and `channel.source == caller_id`, but receive has no caller validation. `send_unchecked()` bypasses all checks.
4. **Witness logging is unspecified**: IPC events are not logged to the witness subsystem.
5. **Coherence weight semantics are implicit**: `ChannelMeta::weight` increments on send but the decay/epoch-reset protocol is not documented.

---

## Decision

### 1. FIFO Per-Queue Ordering Guarantee

Each `MessageQueue<CAPACITY>` provides **strict FIFO** ordering. Messages
enqueued via `send()` are dequeued via `receive()` in the same order. This is
guaranteed by the ring buffer's `head`/`tail` discipline:

```rust
// MessageQueue::send -- tail advances
self.buffer[self.tail] = Some(msg);
self.tail = (self.tail + 1) & (CAPACITY - 1);

// MessageQueue::receive -- head advances
let msg = self.buffer[self.head].take();
self.head = (self.head + 1) & (CAPACITY - 1);
```

**Cross-channel ordering is explicitly NOT guaranteed.** Two messages sent on
different `CommEdge`s may arrive in any order. This matches the partition
isolation model: partitions sharing state must coordinate via sequence numbers
in the `IpcMessage::sequence` field.

### 2. Queue Capacity and Backpressure

Queue capacity is set at compile time via `QUEUE_SIZE` (must be a power of two,
enforced by the const assertion `_CAPACITY_IS_POWER_OF_TWO`). When the queue
is full:

- `MessageQueue::send()` returns `Err(RvmError::ResourceLimitExceeded)`.
- The message is **not enqueued** and the caller must retry or drop.
- The `ChannelMeta::weight` is **not incremented** on failure.

The backpressure policy is **caller-driven**: the sender decides whether to
retry, drop, or escalate. The hypervisor does not buffer overflow messages.
This prevents unbounded memory growth and keeps the IPC path allocation-free.

Recommended queue sizes by deployment tier:

| Tier | `QUEUE_SIZE` | Rationale |
|------|-------------|-----------|
| Seed (64KB MCU) | 4 | Minimal RAM budget |
| Edge (1MB--16MB) | 16 | Moderate IPC load |
| Cloud (>128MB) | 64 | High-throughput partition communication |

### 3. Capability-Gated Send and Receive

**Send path** (`IpcManager::send`): the caller must satisfy two checks:

1. `msg.sender == caller_id` -- the declared sender matches the actual caller.
2. `channel.source == caller_id` -- the caller is the source endpoint.

Violation of either returns `Err(RvmError::InsufficientCapability)`. The
`capability_hash` field in `IpcMessage` records the truncated FNV-1a hash of
the authorising capability token for audit purposes.

**Receive path** (`IpcManager::receive`): currently accepts any caller with a
valid `CommEdgeId`. A future revision should add destination-endpoint
validation (the caller must be the `dest` partition of the channel) to close
the read-side capability gap. Until then, channel identifiers serve as
unforgeable capabilities: only the partition that received the `CommEdgeId`
from `create_channel()` can call `receive()`.

**Kernel bypass** (`IpcManager::send_unchecked`): skips caller validation.
This method is restricted to kernel-internal paths where the caller has already
performed authorization. It must never be exposed through the partition syscall
interface.

### 4. Cross-Partition Delivery Semantics

IPC channels are **unidirectional**: `create_channel(from, to)` creates a
channel where `from` can send and `to` can receive. Bidirectional communication
requires two channels. This simplifies capability reasoning -- each channel
has exactly one writer and one reader.

**Delivery guarantee**: messages enqueued via `send()` will be available to
`receive()` unless the channel is destroyed via `destroy_channel()`. There is
no at-most-once or at-least-once abstraction; delivery is **exactly-once within
the channel lifetime**. If the channel is destroyed, any unread messages are
silently dropped.

### 5. Witness Logging of IPC Events

The following IPC events must be recorded in the witness log (ADR-134):

| Event | Trigger | Witness Fields |
|-------|---------|---------------|
| `ChannelCreated` | `create_channel()` returns `Ok(edge_id)` | edge_id, source, dest, epoch |
| `MessageSent` | `send()` or `send_unchecked()` returns `Ok(())` | edge_id, sequence, msg_type, capability_hash |
| `ChannelDestroyed` | `destroy_channel()` returns `Ok(())` | edge_id, messages_remaining, weight_at_destroy |
| `SendRejected` | `send()` returns any `Err` | edge_id, error_variant, caller_id |

Witness records are batched per epoch (DC-10) rather than per-message. The
IPC manager accumulates event counts per epoch and flushes a summary record
at epoch boundaries.

### 6. Coherence Graph Integration

`ChannelMeta::weight` tracks the cumulative number of successful sends on a
channel. This value is exposed via `IpcManager::comm_weight(edge_id)` and
feeds the coherence graph's `CommEdge::weight` field.

Weight semantics:

- Incremented by 1 on each successful `send()` or `send_unchecked()` call.
- Uses `saturating_add` to prevent overflow.
- Decay is applied externally by the coherence engine at epoch boundaries
  (not by the IPC manager itself).
- The coherence engine reads `comm_weight()` for each active edge when
  computing the mincut partition scoring (DC-2, 50us budget).

---

## Consequences

### Positive

- FIFO guarantee enables deterministic message-passing protocols between partitions.
- Compile-time capacity prevents runtime allocation and bounds worst-case memory.
- Weight tracking provides accurate coherence data without additional instrumentation.
- Unidirectional channels simplify capability reasoning and prevent confused-deputy attacks.

### Negative

- No receive-side capability check: a partition with a stolen `CommEdgeId` can read messages.
- No built-in retry/backpressure protocol: callers must implement their own.
- `send_unchecked` is an escape hatch that bypasses the security model.
- Destroyed channels silently drop unread messages with no notification to the receiver.

### Risks

- If witness batching is not implemented, IPC activity is unauditable.
- Queue sizes that are too small under load cause frequent `ResourceLimitExceeded` errors
  that may cascade into partition stalls.

---

## References

- `rvm-partition/src/ipc.rs` -- `IpcMessage`, `MessageQueue`, `IpcManager`, `ChannelMeta`
- `rvm-partition/src/comm_edge.rs` -- `CommEdge`, `CommEdgeId`
- ADR-132, Section DC-2 -- Coherence graph and mincut computation
- ADR-132, Section DC-10 -- Epoch-based witness batching
- ADR-134 -- Witness schema and log format
