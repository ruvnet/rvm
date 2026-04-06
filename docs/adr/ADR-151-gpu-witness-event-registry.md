# ADR-151: GPU Witness Event Registry

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-134 (Witness Schema and Log Format), ADR-142 (TEE-Backed Cryptographic Verification), ADR-144 (GPU Compute Support)

---

## Context

ADR-144 introduces the `rvm-gpu` crate with capability-gated, budget-enforced GPU compute. Design constraint DC-GPU-5 mandates that every GPU operation emits a `WitnessRecord`. However, the `ActionKind` enum defined in ADR-134 does not include GPU-specific variants. The enum currently occupies ranges 0x01-0x0F (partition), 0x10-0x1F (capability), 0x20-0x2F (memory), 0x30-0x3F (communication), 0x40-0x4F (device), 0x50-0x5F (proof), 0x60-0x6F (scheduler), 0x70-0x7F (recovery), 0x80-0x8F (boot), and 0x90-0x9F (vector/graph). The 0xA0-0xAF range is unallocated and reserved for GPU operations.

### Problem Statement

1. **Audit gap**: GPU kernel launches, buffer allocations, memory transfers, and context switches are privileged operations that mutate partition state and consume shared resources. Without dedicated `ActionKind` variants, these operations either go unwitnessed (violating INV-3: no witness, no mutation) or are logged under generic device lease variants that lose GPU-specific forensic data.
2. **Payload encoding undefined**: The witness record's 8-byte `payload` field (offset 32) and 8-byte `aux` field (offset 56) must encode GPU-specific data (kernel ID, buffer ID, transfer size, compute duration). Without a canonical encoding, audit tools cannot decode GPU witness records.
3. **Forensic query patterns**: Operators need to query the witness log for GPU-specific events -- "show all kernel launches for partition X", "find all budget exceeded events in the last epoch", "trace all memory transfers above 1MB". These queries require filtering by `ActionKind` in the GPU range.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| ADR-134 | Witness record format, ActionKind enum, payload encoding conventions | Direct extension point for GPU variants |
| ADR-142 | SHA-256 chain hashing, signed witness records | GPU witnesses use the same chain and signing infrastructure |
| ADR-144 | GPU architecture, DC-GPU-5 (all GPU ops witnessed) | Defines the GPU operations that require witness coverage |
| NVIDIA nvprof | GPU kernel profiling event schema | Informs which GPU events are forensically valuable |
| ARM Streamline | GPU workload trace events | Validates kernel launch + memory transfer as primary audit events |

---

## Decision

Extend the `ActionKind` enum with 12 GPU-specific variants in the 0xA0-0xAF range. Define canonical payload encodings for each variant. GPU witness records use the same 64-byte format, same hash chain, and same ~17ns emission target as all other witness records.

### New ActionKind Variants

```rust
// --- GPU operations (0xA0-0xAF) ---
GpuContextCreate    = 0xA0,  // Partition creates a GPU context
GpuContextDestroy   = 0xA1,  // Partition destroys a GPU context
GpuKernelLaunch     = 0xA2,  // Kernel submitted to GPU queue
GpuKernelComplete   = 0xA3,  // Kernel execution completed
GpuKernelTimeout    = 0xA4,  // Kernel exceeded deadline (killed)
GpuBufferAlloc      = 0xA5,  // GPU buffer allocated
GpuBufferFree       = 0xA6,  // GPU buffer freed
GpuTransfer         = 0xA7,  // Host<->GPU memory transfer
GpuSync             = 0xA8,  // GPU queue synchronization barrier
GpuBudgetExceeded   = 0xA9,  // GPU budget quota exceeded
GpuIommuViolation   = 0xAA,  // IOMMU fault on GPU memory access
GpuCompileFail      = 0xAB,  // Kernel compilation failed
```

### Payload Encoding by Variant

Each GPU witness record packs operation-specific data into the 8-byte `payload` field and optionally the 8-byte `aux` field. All encodings are little-endian.

| ActionKind | payload (8 bytes) | aux (8 bytes) | flags (2 bytes) |
|------------|------------------|---------------|-----------------|
| `GpuContextCreate` | `context_id: u32 \| backend_id: u32` | `memory_budget_bytes: u64` | backend type in low byte |
| `GpuContextDestroy` | `context_id: u32 \| active_buffers: u32` | `total_compute_ns: u64` | 0 |
| `GpuKernelLaunch` | `kernel_id: u16 \| workgroup_x: u16 \| workgroup_y: u16 \| workgroup_z: u16` | `timeout_ns: u64` | 0 |
| `GpuKernelComplete` | `kernel_id: u16 \| _reserved: u16 \| computation_ns: u32` | `output_bytes: u64` | 0 |
| `GpuKernelTimeout` | `kernel_id: u16 \| _reserved: u16 \| elapsed_ns: u32` | `deadline_ns: u64` | 0 |
| `GpuBufferAlloc` | `buffer_id: u32 \| size_bytes: u32` | `budget_remaining_bytes: u64` | usage flags in low byte |
| `GpuBufferFree` | `buffer_id: u32 \| size_bytes: u32` | `budget_remaining_bytes: u64` | 0 |
| `GpuTransfer` | `buffer_id: u32 \| transfer_bytes: u32` | `direction: u8 \| _pad: [u8; 3] \| bandwidth_remaining: u32` | 0 = H2D, 1 = D2H in flags low byte |
| `GpuSync` | `queue_depth_before: u32 \| queue_depth_after: u32` | `wait_ns: u64` | 0 |
| `GpuBudgetExceeded` | `budget_type: u8 \| _pad: [u8; 3] \| requested: u32` | `limit: u64` | budget_type: 0=compute, 1=memory, 2=transfer, 3=launches |
| `GpuIommuViolation` | `fault_addr_low: u32 \| fault_type: u32` | `fault_addr_high: u32 \| partition_gpu_base: u32` | 0 |
| `GpuCompileFail` | `kernel_id: u16 \| error_code: u16 \| source_hash_low: u32` | `source_hash_high: u64` | 0 |

### Encoding Conventions

The payload encoding follows the same conventions as existing `ActionKind` variants (see ADR-134 Section 7):

1. **IDs in high bits, measurements in low bits**: When a record carries both an identifier and a measurement, the ID occupies the high 32 bits and the measurement occupies the low 32 bits of the `payload` field.
2. **Duration in nanoseconds, truncated to u32**: Compute duration is stored as `u32` nanoseconds, giving a maximum of ~4.29 seconds. Any kernel running longer than this has already been killed by the 100ms deadline (DC-GPU-7 in ADR-144).
3. **Budget remaining after operation**: For allocation and transfer events, the `aux` field carries the budget remaining after the operation. This enables trend analysis without requiring a separate budget query.
4. **Transfer direction in flags**: The `flags` field (offset 18, u16) encodes the transfer direction for `GpuTransfer` records: 0 = host-to-device, 1 = device-to-host.

### Integration with WitnessEmitter

The `GpuQueue` in `rvm-gpu` calls the existing `WitnessEmitter::emit()` method. No new emission API is needed. The GPU crate constructs a `WitnessRecord` with the appropriate `ActionKind` variant and payload encoding, then passes it to the emitter.

```rust
// rvm-gpu/src/queue.rs (sketch)
fn submit_kernel(&mut self, kernel: &GpuKernel, config: LaunchConfig) -> Result<(), GpuError> {
    // ... capability check, budget check ...

    self.witness_emitter.emit(WitnessRecord::new(
        ActionKind::GpuKernelLaunch,
        proof.tier(),
        self.partition_id,
        kernel.id() as u32,
        cap_handle.hash_truncated(),
        encode_kernel_launch_payload(kernel.id(), config),
    ))?;

    // ... submit to hardware queue ...
    Ok(())
}
```

The `target_object_id` field (offset 24, u32) carries the GPU context ID for context operations, the kernel ID for kernel operations, and the buffer ID for memory operations. This enables `scan_by_target()` queries to find all operations on a specific GPU object.

### Audit Query Patterns

GPU forensics uses the existing `scan_by_kind()` function from ADR-134 with GPU-specific `ActionKind` filters:

```rust
/// Find all kernel launches for a given partition.
pub fn query_gpu_kernel_launches(
    log: &WitnessLog,
    partition_id: u32,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r|
        r.action_kind == ActionKind::GpuKernelLaunch
        && r.actor_partition_id == partition_id)
}

/// Find all budget exceeded events in a time range.
pub fn query_gpu_budget_violations(
    log: &WitnessLog,
    start_ns: u64,
    end_ns: u64,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r|
        r.action_kind == ActionKind::GpuBudgetExceeded
        && r.timestamp_ns >= start_ns
        && r.timestamp_ns <= end_ns)
}

/// Find all memory transfers above a size threshold.
pub fn query_gpu_large_transfers(
    log: &WitnessLog,
    min_bytes: u32,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r|
        r.action_kind == ActionKind::GpuTransfer
        && (r.payload as u32) >= min_bytes)
}

/// Trace the full lifecycle of a GPU context.
pub fn query_gpu_context_lifecycle(
    log: &WitnessLog,
    context_id: u32,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r|
        matches!(r.action_kind,
            ActionKind::GpuContextCreate
            | ActionKind::GpuContextDestroy
            | ActionKind::GpuKernelLaunch
            | ActionKind::GpuKernelComplete
            | ActionKind::GpuKernelTimeout
            | ActionKind::GpuBufferAlloc
            | ActionKind::GpuBufferFree
            | ActionKind::GpuTransfer
            | ActionKind::GpuSync
        ) && r.target_object_id == context_id)
}
```

### Performance Budget

GPU witness emission uses the same ring buffer and emission path as all other witness records. The target is ~17ns per emission (well within the 500ns budget from ADR-134). GPU operations themselves are measured in microseconds to milliseconds, so the witness overhead is negligible relative to the GPU operation latency.

| GPU Operation | Typical Latency | Witness Overhead | Overhead Ratio |
|--------------|----------------|-----------------|----------------|
| Kernel launch | 10us | ~17ns | 0.17% |
| Buffer alloc (4KB) | 2us | ~17ns | 0.85% |
| Memory transfer (1MB) | 50us | ~17ns | 0.03% |
| Context create | 100us | ~17ns | 0.02% |

---

## Consequences

### Positive

1. **Complete GPU audit trail**: Every GPU operation is witnessed with forensically decodable payload data. No audit gap for GPU subsystem operations.
2. **Consistent with existing witness infrastructure**: GPU witnesses use the same 64-byte format, same hash chain, same ring buffer, and same emission API. No new infrastructure required.
3. **Efficient forensic queries**: The 0xA0-0xAF range grouping enables efficient range-based filtering for GPU-only audit views.
4. **Budget trend analysis**: The `budget_remaining` field in allocation and transfer records enables operators to detect budget exhaustion patterns without separate monitoring infrastructure.

### Negative

1. **ActionKind enum grows by 12 variants**: The enum now uses ~42 of 256 available slots. This is well within capacity but increases the surface area for audit query implementations.
2. **Payload encoding complexity**: Each GPU variant has a different payload layout. Audit tools must implement per-variant decoders. This is the same pattern used by existing variants (PartitionSplit, RegionTransfer, etc.) and is an inherent consequence of the 8-byte fixed payload constraint.

---

## References

- ADR-134: Witness Schema and Log Format (ActionKind enum, payload encoding conventions)
- ADR-142: TEE-Backed Cryptographic Verification (SHA-256 chain hashing, WitnessSigner)
- ADR-144: GPU Compute Support (DC-GPU-5, GPU operations requiring witness coverage)
- `rvm-witness/src/record.rs`: WitnessRecord struct definition
- `rvm-gpu/src/queue.rs`: GpuQueue command submission (consumer of this registry)
