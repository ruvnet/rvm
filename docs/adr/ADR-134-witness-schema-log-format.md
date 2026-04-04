# ADR-134: Witness Schema and Log Format

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-133 (Partition Object Model)

---

## Context

ADR-132 establishes that RVM is witness-native: every privileged action emits a compact, immutable audit record. ADR-132 specifies this at the architectural level, and the architecture document (Section 8) sketches the record layout and witness kinds. This ADR specifies the exact binary schema, hash-chaining protocol, storage architecture, replay semantics, and performance constraints for the witness subsystem.

### Problem Statement

1. **No witness, no mutation**: This is a core invariant (INV-3). Witness emission is not an afterthought or a logging layer -- it is part of the privileged action itself. If the witness cannot be written, the mutation must not proceed. The schema must be designed so that emission never fails under normal operation.
2. **64-byte cache-line alignment is non-negotiable**: Variable-length records require parsing, allocation, or pointer chasing. In a hypervisor where witness emission happens on every privileged action (including in the scheduler tick path), any allocation or branch misprediction is unacceptable. Fixed 64-byte records aligned to cache lines eliminate these costs.
3. **Tamper evidence requires hash chaining**: The witness log must be tamper-evident. If any record is modified or deleted, the chain breaks. FNV-1a is chosen for its speed (< 50 ns for 64 bytes) and simplicity, not for cryptographic strength. Cryptographic signing is optional (TEE-backed, via the WitnessSigner trait) for high-assurance deployments.
4. **The witness kind enum must cover all privileged actions**: If a privileged action exists that has no witness kind, the system has a gap in its audit trail. The enum must be comprehensive and extensible.
5. **Replay must be deterministic**: Given a checkpoint and a witness log segment, replaying the segment must produce identical state. This requires that the witness record captures enough information to reconstruct the action without ambiguity.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| seL4 kernel log | Minimal tracing for verified kernels | Validates low-overhead kernel event logging; RVM goes further with mandatory chaining |
| TPM 2.0 Event Log | Hash-chained platform event records | Hash-chaining protocol for tamper evidence; RVM adapts this to per-action granularity |
| Linux ftrace | Ring-buffer tracing with per-CPU buffers | Ring buffer overflow strategy; RVM adds hash chaining and mandatory emission |
| Certificate Transparency (RFC 6962) | Append-only Merkle-tree log | Append-only log design; RVM uses linear hash chain (simpler, sufficient for single-node) |
| ARM TrustZone / CCA | Hardware-backed attestation | Informs the optional TEE-backed WitnessSigner for high-assurance deployments |
| FNV-1a | Fast, non-cryptographic hash | Chosen for witness chaining: < 50 ns for 64 bytes, no allocation, deterministic |

---

## Decision

### 1. Record Format: 64-Byte Fixed, Cache-Line Aligned

Every witness record is exactly 64 bytes, matching the cache line width on all target architectures (AArch64, RISC-V, x86-64). The record is `#[repr(C, align(64))]` to guarantee layout and alignment.

```rust
// ruvix-witness/src/record.rs

/// A single witness record. Exactly 64 bytes, cache-line aligned.
///
/// Layout (all fields little-endian):
///
///   Offset  Size  Field                Description
///   ------  ----  -------------------  -----------
///   0       8     sequence             Monotonic sequence number (u64)
///   8       8     timestamp_ns         Nanosecond timestamp from system timer (u64)
///   16      1     action_kind          Privileged action enum (u8)
///   17      1     proof_tier           Which proof tier validated this (u8: 1, 2, or 3)
///   18      2     flags                Action-specific flags (u16)
///   20      4     actor_partition_id   Partition that performed the action (u32)
///   24      4     target_object_id     Object acted upon: partition, region, cap, etc. (u32)
///   28      4     capability_hash      Truncated hash of the capability used (u32)
///   32      8     payload              Action-specific data (u64)
///   40      8     prev_hash            FNV-1a hash of the previous record (u64, chain link)
///   48      8     record_hash          FNV-1a hash of bytes [0..48] of this record (u64)
///   56      8     aux                  Secondary payload or TEE signature fragment (u64)
///
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct WitnessRecord {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub action_kind: ActionKind,
    pub proof_tier: u8,
    pub flags: u16,
    pub actor_partition_id: u32,
    pub target_object_id: u32,
    pub capability_hash: u32,
    pub payload: u64,
    pub prev_hash: u64,
    pub record_hash: u64,
    pub aux: u64,
}

static_assertions::assert_eq_size!(WitnessRecord, [u8; 64]);
```

**Design rationale for each field:**

| Field | Why This Size | What It Captures |
|-------|---------------|------------------|
| `sequence` (u64) | Monotonic counter, never wraps in practice | Global ordering of all privileged actions |
| `timestamp_ns` (u64) | Nanosecond resolution, good for ~584 years | Wall-clock time for time-range audit queries |
| `action_kind` (u8) | 256 possible kinds, ~30 defined in v1 | Which privileged action was performed |
| `proof_tier` (u8) | 3 tiers (P1, P2, P3) | Which proof layer authorized the action |
| `flags` (u16) | Per-action-kind interpretation | E.g., for RegionTierChange: from_tier in high byte, to_tier in low byte |
| `actor_partition_id` (u32) | Up to 4B partitions (256 active, IDs recyclable) | Who performed the action |
| `target_object_id` (u32) | Encodes handle index of the target object | What was acted upon |
| `capability_hash` (u32) | Truncated FNV-1a of the full capability token | Which authority was exercised (not the full token -- that would leak secrets) |
| `payload` (u64) | Action-specific data, packed by kind | E.g., for PartitionSplit: new_id_a in high 32, new_id_b in low 32 |
| `prev_hash` (u64) | Chain link | FNV-1a of the previous record's full 64 bytes |
| `record_hash` (u64) | Self-integrity | FNV-1a of bytes [0..48] of this record |
| `aux` (u64) | Overflow or signature fragment | E.g., for PartitionMigrate: target_node_id; for TEE mode: signature fragment |

### 2. Action Kinds

The `ActionKind` enum covers every privileged action in the system. If a privileged action exists without a corresponding kind, the system has an audit gap.

```rust
/// Privileged actions that produce witness records.
///
/// Organized by subsystem. Hex values allow easy filtering by
/// prefix in audit queries (0x0_ = partition, 0x1_ = capability, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionKind {
    // --- Partition lifecycle (0x01-0x0F) ---
    PartitionCreate       = 0x01,
    PartitionDestroy      = 0x02,
    PartitionSuspend      = 0x03,
    PartitionResume       = 0x04,
    PartitionSplit        = 0x05,
    PartitionMerge        = 0x06,
    PartitionHibernate    = 0x07,
    PartitionReconstruct  = 0x08,
    PartitionMigrate      = 0x09,

    // --- Capability operations (0x10-0x1F) ---
    CapabilityGrant       = 0x10,
    CapabilityRevoke      = 0x11,
    CapabilityDelegate    = 0x12,
    CapabilityEscalate    = 0x13,  // Delegation depth increase

    // --- Memory operations (0x20-0x2F) ---
    RegionCreate          = 0x20,
    RegionDestroy         = 0x21,
    RegionTransfer        = 0x22,
    RegionShare           = 0x23,
    RegionUnshare         = 0x24,
    RegionPromote         = 0x25,  // Tier promotion (colder -> warmer)
    RegionDemote          = 0x26,  // Tier demotion (warmer -> colder)
    RegionMap             = 0x27,  // Stage-2 mapping added
    RegionUnmap           = 0x28,  // Stage-2 mapping removed

    // --- Communication (0x30-0x3F) ---
    CommEdgeCreate        = 0x30,
    CommEdgeDestroy       = 0x31,
    IpcSend               = 0x32,
    IpcReceive            = 0x33,
    ZeroCopyShare         = 0x34,
    NotificationSignal    = 0x35,

    // --- Device operations (0x40-0x4F) ---
    DeviceLeaseGrant      = 0x40,
    DeviceLeaseRevoke     = 0x41,
    DeviceLeaseExpire     = 0x42,
    DeviceLeaseRenew      = 0x43,

    // --- Proof verification (0x50-0x5F) ---
    ProofVerifiedP1       = 0x50,
    ProofVerifiedP2       = 0x51,
    ProofVerifiedP3       = 0x52,
    ProofRejected         = 0x53,
    ProofEscalated        = 0x54,  // P1 -> P2 or P2 -> P3 escalation

    // --- Scheduler decisions (0x60-0x6F) ---
    SchedulerEpoch        = 0x60,  // Epoch boundary (bulk switch summary)
    SchedulerModeSwitch   = 0x61,  // Reflex <-> Flow <-> Recovery
    TaskSpawn             = 0x62,
    TaskTerminate         = 0x63,
    StructuralSplit       = 0x64,  // Scheduler-triggered split
    StructuralMerge       = 0x65,  // Scheduler-triggered merge

    // --- Recovery actions (0x70-0x7F) ---
    RecoveryEnter         = 0x70,
    RecoveryExit          = 0x71,
    CheckpointCreated     = 0x72,
    CheckpointRestored    = 0x73,
    MinCutBudgetExceeded  = 0x74,  // DC-2 fallback triggered

    // --- Boot and attestation (0x80-0x8F) ---
    BootAttestation       = 0x80,
    BootComplete          = 0x81,
    TeeAttestation        = 0x82,  // TEE-backed attestation record

    // --- Vector/Graph mutations (0x90-0x9F) ---
    VectorPut             = 0x90,
    VectorDelete          = 0x91,
    GraphMutation         = 0x92,
    CoherenceRecomputed   = 0x93,
}
```

### 3. Hash-Chaining Protocol

Each record includes the FNV-1a hash of the previous record (`prev_hash`) and a self-hash (`record_hash`). Together these form a tamper-evident chain.

```rust
// ruvix-witness/src/chain.rs

/// FNV-1a hash over a byte slice.
///
/// Chosen for speed (< 50 ns for 64 bytes), not cryptographic strength.
/// For tamper resistance against a capable adversary, use the optional
/// TEE-backed WitnessSigner (see Section 9).
pub fn fnv1a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x00000100000001B3); // FNV prime
    }
    hash
}

/// Compute the record hash for a witness record.
///
/// Hashes bytes [0..48] (everything except prev_hash, record_hash, aux).
/// This allows verification without knowing the chain context.
pub fn compute_record_hash(record: &WitnessRecord) -> u64 {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            record as *const WitnessRecord as *const u8,
            48, // Hash the first 48 bytes only
        )
    };
    fnv1a(bytes)
}

/// Compute the chain hash: FNV-1a of the full 64-byte previous record.
///
/// This is stored in the next record's prev_hash field.
pub fn compute_chain_hash(prev_record: &WitnessRecord) -> u64 {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            prev_record as *const WitnessRecord as *const u8,
            64,
        )
    };
    fnv1a(bytes)
}
```

**Chain construction:**

```
Record 0 (boot attestation):
  prev_hash = 0 (genesis)
  record_hash = fnv1a(record_0[0..48])

Record 1:
  prev_hash = fnv1a(record_0[0..64])
  record_hash = fnv1a(record_1[0..48])

Record N:
  prev_hash = fnv1a(record_{N-1}[0..64])
  record_hash = fnv1a(record_N[0..48])
```

**Verification**: Walk the chain from any starting record. Recompute `fnv1a(record[0..64])` for each record and compare with the next record's `prev_hash`. Any mismatch indicates tampering or corruption.

### 4. Storage Architecture: Ring Buffer with Overflow

```rust
// ruvix-witness/src/log.rs

/// The kernel witness log.
///
/// In-memory: append-only ring buffer backed by physically contiguous
/// pages in Hot tier memory. When the ring buffer wraps, the oldest
/// segment is compressed and moved to Warm tier.
///
/// Overflow to persistent storage: Warm-tier segments are periodically
/// serialized to Cold tier (block device or network).
pub struct WitnessLog {
    /// Ring buffer of witness records.
    /// Capacity: RING_CAPACITY records (power of two for mask indexing).
    ring: *mut WitnessRecord,

    /// Ring buffer capacity in records.
    capacity: usize,

    /// Current write position (monotonically increasing; mask with capacity - 1).
    write_pos: AtomicU64,

    /// Read position for overflow drain (tracks what has been flushed).
    drain_pos: u64,

    /// Running chain hash (hash of the most recently written record).
    chain_hash: AtomicU64,

    /// Sequence counter.
    sequence: AtomicU64,

    /// Physical pages backing the ring buffer.
    pages: ArrayVec<PhysAddr, WITNESS_LOG_MAX_PAGES>,

    /// Overflow segments that have been compressed to Warm tier.
    overflow_segments: ArrayVec<WitnessSegmentHandle, 256>,
}

/// Default ring buffer: 16 MB = 262,144 records of 64 bytes.
///
/// At 100,000 privileged actions per second, this gives ~2.6 seconds
/// of hot storage before overflow drain is needed.
pub const WITNESS_LOG_MAX_PAGES: usize = 4096; // 4096 * 4KB = 16 MB
pub const RING_CAPACITY: usize = 16 * 1024 * 1024 / 64; // 262,144 records
```

**Overflow protocol:**

1. A background drain task runs at low priority in the hypervisor
2. When `write_pos - drain_pos > capacity / 2`, the drain task activates
3. The drain task reads records from `[drain_pos..drain_pos + SEGMENT_SIZE]`
4. Records are LZ4-compressed and written to a Warm-tier region
5. A WitnessSegment handle is recorded for later retrieval
6. `drain_pos` advances
7. If Warm tier is full, segments are serialized to Cold tier (block device)

The ring buffer never blocks the writer. If the drain cannot keep up (catastrophic scenario), the oldest un-drained records are overwritten. This is detected by a sequence gap and recorded as a `RecoveryEnter` witness when the drain catches up.

### 5. Emission Protocol: No Witness, No Mutation

Witness emission is embedded in the privileged action, not called after it. The pattern is:

```rust
/// Example: creating a new partition.
///
/// The witness record is emitted BEFORE the mutation is committed.
/// If witness emission fails (e.g., ring buffer full AND drain dead),
/// the mutation does not proceed.
pub fn create_partition(
    &mut self,
    config: PartitionConfig,
    parent_cap: CapHandle,
    proof: &ProofToken,
) -> Result<PartitionId, PartitionError> {
    // 1. Verify proof (P1 capability check)
    self.proof_engine.verify(parent_cap, CapRights::WRITE, proof)?;

    // 2. Allocate partition ID
    let id = self.partition_mgr.allocate_id()?;

    // 3. Emit witness BEFORE committing
    self.witness_log.emit(WitnessRecord::new(
        ActionKind::PartitionCreate,
        proof.tier(),
        self.current_partition().id.as_u32(),
        id.as_u32(),
        parent_cap.hash_truncated(),
        config.encode_payload(),
    ))?;

    // 4. Now commit the mutation
    self.partition_mgr.commit_create(id, config)?;

    Ok(id)
}
```

If `emit()` returns `Err`, the partition is not created. The invariant **no witness, no mutation** is enforced by control flow: the mutation call is unreachable if emission fails.

### 6. Emission Performance: < 500 ns

Witness emission must not bottleneck the scheduler or any privileged action. The budget is 500 nanoseconds.

**Breakdown:**

| Step | Cost | Notes |
|------|------|-------|
| Populate record fields | ~20 ns | Direct field writes, no allocation |
| Read timestamp (CNTVCT_EL0 / rdtsc) | ~10 ns | Single register read |
| Compute record_hash (FNV-1a of 48 bytes) | ~40 ns | Tight loop, no branches |
| Load prev chain_hash (atomic load) | ~5 ns | Cache-hot atomic |
| Write record to ring buffer | ~10 ns | Single 64-byte store (cache-line write) |
| Update chain_hash (atomic store) | ~5 ns | Release store |
| Increment sequence + write_pos (2x atomic) | ~10 ns | Release stores |
| **Total** | **~100 ns** | Well within 500 ns budget |

No allocation. No lock. No syscall. No branch on the fast path. The ring buffer write is a single cache-line-aligned store.

### 7. Replay Protocol

Given a checkpoint and a witness log segment, the system can deterministically reconstruct state at any point in the log.

```rust
// ruvix-witness/src/replay.rs

/// Replay a witness log segment from a checkpoint.
///
/// Each record is applied in sequence. The record contains enough
/// information to reconstruct the action:
///   - action_kind identifies the operation
///   - actor_partition_id + target_object_id identify the operands
///   - payload + aux carry action-specific data
///   - proof_tier indicates which verification was performed
///
/// Replay is deterministic: same checkpoint + same log = same state.
pub fn replay(
    checkpoint: &Checkpoint,
    segment: &[WitnessRecord],
) -> Result<KernelState, ReplayError> {
    let mut state = checkpoint.restore()?;

    for record in segment {
        // Verify chain integrity during replay
        let expected_prev = state.last_witness_hash();
        if record.prev_hash != expected_prev {
            return Err(ReplayError::ChainBreak {
                sequence: record.sequence,
                expected: expected_prev,
                found: record.prev_hash,
            });
        }

        // Verify record self-integrity
        let computed = compute_record_hash(record);
        if record.record_hash != computed {
            return Err(ReplayError::RecordCorrupted {
                sequence: record.sequence,
            });
        }

        // Apply the witnessed action
        state.apply(record)?;
    }

    Ok(state)
}
```

**What replay requires from each action kind:**

| ActionKind | Payload Encodes | Replay Produces |
|------------|----------------|-----------------|
| PartitionCreate | config flags | New partition in state |
| PartitionSplit | new_id_a (high 32), new_id_b (low 32) | Two partitions from one |
| RegionTransfer | from_partition (high 32), to_partition (low 32) | Ownership change |
| RegionPromote | from_tier (flags high byte), to_tier (flags low byte) | Tier state change |
| CapabilityGrant | rights bitmap in payload | New capability in table |
| CommEdgeCreate | source (high 32), dest (low 32) | New edge in graph |
| SchedulerEpoch | epoch_number | Scheduling state advance |
| CheckpointCreated | checkpoint_id in payload | New recovery point |

### 8. Audit Queries

The witness log supports three query modes:

```rust
/// Scan witness records by partition.
pub fn scan_by_partition(
    log: &WitnessLog,
    partition_id: u32,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r| r.actor_partition_id == partition_id
        || r.target_object_id == partition_id)
}

/// Scan witness records by time range.
pub fn scan_by_time(
    log: &WitnessLog,
    start_ns: u64,
    end_ns: u64,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r|
        r.timestamp_ns >= start_ns && r.timestamp_ns <= end_ns)
}

/// Scan witness records by action kind.
pub fn scan_by_kind(
    log: &WitnessLog,
    kind: ActionKind,
) -> impl Iterator<Item = &WitnessRecord> {
    log.iter().filter(move |r| r.action_kind == kind)
}
```

Because records are fixed-size and sequentially stored, scanning is a linear pass over contiguous memory. For the 16 MB hot ring buffer, a full scan touches 262,144 records and completes in < 1 ms on modern hardware.

### 9. Optional TEE-Backed Signing

For high-assurance deployments (safety-critical, regulatory), the witness log can be signed using a TEE (TrustZone, CCA, or SGX). The `WitnessSigner` trait abstracts the signing backend:

```rust
/// Optional cryptographic signing for witness records.
///
/// In the default configuration, witnesses use FNV-1a chaining only
/// (fast, tamper-evident against accidental corruption, not against
/// a privileged adversary). For high-assurance deployments, a TEE
/// can provide cryptographic non-repudiation.
pub trait WitnessSigner: Send + Sync {
    /// Sign a witness record. The signature is stored in the aux field.
    ///
    /// Implementations must complete in < 10 microseconds to avoid
    /// becoming a bottleneck. ECDSA with hardware acceleration
    /// on ARM CCA achieves ~5 microseconds.
    fn sign(&self, record: &mut WitnessRecord) -> Result<(), SignError>;

    /// Verify a signature on a witness record.
    fn verify(&self, record: &WitnessRecord) -> Result<bool, SignError>;
}

/// No-op signer for deployments without TEE.
pub struct NullSigner;

impl WitnessSigner for NullSigner {
    fn sign(&self, _record: &mut WitnessRecord) -> Result<(), SignError> {
        Ok(()) // aux field remains zero
    }
    fn verify(&self, _record: &WitnessRecord) -> Result<bool, SignError> {
        Ok(true) // No signature to check
    }
}
```

When a TEE signer is active, the `aux` field carries a truncated ECDSA signature (64 bits of a 256-bit signature). The full signature is stored in a parallel side-table for records that require non-repudiation. This keeps the record at 64 bytes while enabling cryptographic verification when needed.

### 10. Integration with the Proof System

Witnesses are inputs to P3 deep proofs. A P3 proof can reference a witness log segment to demonstrate that a sequence of actions occurred in a specific order with specific authorizations:

```
P3 proof structure:
  - Claim: "Partition X was created by actor Y with capability Z"
  - Evidence: witness record at sequence N with:
      action_kind = PartitionCreate
      actor_partition_id = Y
      target_object_id = X
      capability_hash = hash(Z)
  - Chain verification: prev_hash at N matches hash of record N-1
  - Optional: TEE signature in aux field
```

This closes the loop between the proof system and the witness system: proofs authorize mutations, witnesses record that the authorized mutation occurred, and deep proofs can reference witnesses as evidence.

---

## Consequences

### Positive

- **Deterministic replay**: Any system state can be reconstructed from a checkpoint plus the witness log segment since that checkpoint. This enables debugging, forensic analysis, and recovery without global reboots.
- **Tamper-evident by construction**: Hash chaining means any modification to any record is detectable by walking the chain. No separate integrity-checking daemon is needed.
- **Zero-allocation emission**: The 64-byte fixed record and ring buffer design means witness emission never allocates, never locks, and completes in ~100 ns. This is well within the 500 ns budget and cannot bottleneck the scheduler.
- **Comprehensive audit coverage**: The ~30 action kinds cover every privileged operation. Audit queries by partition, time range, or action kind are linear scans over contiguous memory.
- **Extensible without breaking format**: The `ActionKind` enum has 256 slots; v1 uses ~30. New action kinds can be added without changing the record layout. The `flags`, `payload`, and `aux` fields provide per-kind extension points.
- **Optional TEE signing scales security**: The NullSigner costs nothing. TEE signing adds ~5 microseconds per record but provides cryptographic non-repudiation. Deployments choose their assurance level.

### Negative

- **64 bytes per privileged action is not free**: At 100,000 actions per second, the witness log generates ~6 MB/s. The 16 MB ring buffer fills in ~2.6 seconds. The drain task must keep up, and Warm/Cold tier storage must be provisioned.
- **FNV-1a is not cryptographically secure**: A privileged adversary with kernel access can forge records and recompute the chain. FNV-1a provides tamper evidence against accidental corruption, not against sophisticated attack. The TEE signer mitigates this but is optional.
- **Payload is only 8 bytes**: Some actions carry more context than 8 bytes (e.g., a split operation ideally records the full CutResult). The design accepts this limitation: the 8-byte payload encodes the essential identifiers, and the full context can be recovered by replaying the action against the checkpoint state.
- **Ring buffer overflow loses records**: If the drain task falls behind, old records are overwritten. The system detects this via sequence gaps and logs a recovery event, but the overwritten records are gone. Mitigation: size the ring buffer and drain rate for the expected action frequency.
- **No indexing**: Audit queries are linear scans. For the hot ring buffer (262K records) this is fast. For archived segments (potentially millions of records), a secondary index would improve query performance. Deferred to post-v1.

---

## Rejected Alternatives

| Alternative | Reason for Rejection |
|-------------|---------------------|
| **Variable-length records** | Requires allocation or parsing on the emission path. Incompatible with the < 500 ns budget. Breaks cache-line alignment. |
| **JSON or Protobuf encoding** | Serialization overhead (> 1 microsecond) and variable-length output. Inappropriate for a kernel-level audit system. |
| **Cryptographic hash (SHA-256) for chaining** | SHA-256 costs ~300 ns for 64 bytes, consuming the entire emission budget for hashing alone. FNV-1a at ~40 ns leaves room for all other operations. SHA-256 is available via the optional TEE signer for high-assurance needs. |
| **Per-partition separate logs** | Fragments the audit trail. Cross-partition queries require merging N logs. A single global log with partition ID field enables both per-partition and global queries. |
| **Post-hoc logging (log after mutation)** | Violates INV-3 (no witness, no mutation). If the system crashes between mutation and log, the action is unwitnessed. Emit-before-commit ensures the witness exists or the mutation does not happen. |
| **Blocking on log full** | A full log would block privileged actions, including the scheduler. The ring buffer with background drain avoids this. Record loss on overflow is preferable to system deadlock. |

---

## References

- ARM Architecture Reference Manual, Chapter D7: The Performance Monitors Extension.
- Fowler, G., Noll, L.C., Vo, K.-P., "FNV Hash." http://www.isthe.com/chongo/tech/comp/fnv/
- Laurie, B., Langley, A., Kasper, E., "Certificate Transparency." RFC 6962, 2013.
- ARM Confidential Compute Architecture (CCA), Realm Management Extension.
- Klein, G., et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009.
- ADR-132: RVM Hypervisor Core.
- ADR-133: Partition Object Model.
- RVM Architecture Document, Section 8: Witness Subsystem.

---

## Addendum (2026-04-04)

Per ADR-142, the following changes supersede parts of this ADR:

- **Hash chaining upgraded to SHA-256**: FNV-1a is no longer the default for witness chain hashing. SHA-256 is now the default (feature-gated `crypto-sha256`, enabled by default). FNV-1a is retained only behind the `fnv-fallback` feature flag for non-security hash table indexing.
- **`NullSigner` is no longer the default**: The `WitnessSigner` trait now defaults to `HmacSha256WitnessSigner` (HMAC-SHA256, constant-time verify). `NullSigner` is gated behind `#[cfg(any(test, feature = "null-signer"))]` and cannot be instantiated in release builds without the `fnv-fallback` feature.
- **`aux` field carries HMAC signatures**: The `aux` field (offset 56, 8 bytes) is now used to store truncated HMAC-SHA256 signatures from the `WitnessSigner`. `signed_append()` populates this field after chain-hash metadata is set. The field is no longer reserved/unused in default configurations.
- **Ed25519 signer available**: `Ed25519WitnessSigner` (`ed25519-dalek` ^2.1, `verify_strict()`) is available behind the `ed25519` feature flag for cross-partition, publicly verifiable signing.
