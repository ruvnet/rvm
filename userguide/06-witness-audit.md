# Witness Trail: Complete Audit by Construction

RVM does not have an "audit mode" you can toggle on. Every privileged action -- creating a partition, granting a capability, transferring a memory region, sending an IPC message -- emits a fixed 64-byte, hash-chained witness record **before the mutation commits**. If the record cannot be emitted, the mutation does not proceed. The witness trail is not a feature; it is a structural invariant.

> **Prerequisite reading:** [Capabilities and Proofs](05-capabilities-proofs.md) for the proof tiers that authorize mutations. [Core Concepts](02-core-concepts.md) for an overview of the witness invariant.

---

## 1. The Core Invariant

**No witness, no mutation.**

This is INV-3, the non-negotiable audit invariant of RVM. Every privileged action emits a witness record BEFORE the state change is committed. The sequence is:

1. Validate the capability and proof (see [Capabilities and Proofs](05-capabilities-proofs.md)).
2. Construct the witness record with all relevant fields.
3. Append the record to the witness log (this sets the sequence number, chain hashes, and optional signature).
4. Only after successful append: perform the mutation.

If step 3 fails (ring buffer full is handled by overwrite, so this mainly concerns future persistent backends), the mutation is aborted. There is no code path that mutates kernel state without a prior witness emission.

---

## 2. Record Format (64 Bytes)

Each witness record is exactly 64 bytes, cache-line aligned (`#[repr(C, align(64))]`). This is enforced at compile time with a static assertion. The fixed size means no heap allocation, predictable cache behavior, and constant-time emission.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | `sequence` | Auto-incrementing sequence number (global ordering) |
| 8 | 8 | `timestamp_ns` | Nanosecond timestamp (`CNTVCT_EL0` on AArch64, `rdtsc` on x86) |
| 16 | 1 | `action_kind` | Which privileged action was performed (see Action Kinds below) |
| 17 | 1 | `proof_tier` | Which proof tier authorized this action (1 = P1, 2 = P2, 3 = P3) |
| 18 | 1 | `flags` | Action-specific status flags |
| 19 | 1 | `_reserved` | Reserved, must be zero |
| 20 | 4 | `actor_partition_id` | Partition that performed the action |
| 24 | 8 | `target_object_id` | Object acted upon (partition ID, region handle, etc.) |
| 32 | 4 | `capability_hash` | Truncated hash of the capability used (not the full token) |
| 36 | 8 | `payload` | Action-specific data, packed by kind |
| 44 | 4 | `prev_hash` | FNV-1a hash of the previous record (chain link) |
| 48 | 4 | `record_hash` | FNV-1a hash of this record (self-integrity) |
| 52 | 8 | `aux` | Auxiliary data: TEE signature, secondary payload |
| 60 | 4 | `_pad` | Padding to 64 bytes |

The `payload` field is interpreted differently depending on `action_kind`. For example:
- `PartitionSplit`: bytes [0..4] = `new_id_a`, bytes [4..8] = `new_id_b`
- `RegionTransfer`: bytes [0..4] = `from_partition`, bytes [4..8] = `to_partition`

### Action Kinds

Actions are organized by subsystem with hex prefixes for efficient filtering:

| Prefix | Subsystem | Example Actions |
|--------|-----------|-----------------|
| `0x01-0x0F` | Partition lifecycle | Create, Destroy, Suspend, Resume, Split, Merge, Hibernate, Reconstruct, Migrate |
| `0x10-0x1F` | Capability operations | Grant, Revoke, Delegate, Escalate, Attenuated |
| `0x20-0x2F` | Memory operations | RegionCreate, Destroy, Transfer, Share, Promote, Demote, Map, Unmap |
| `0x30-0x3F` | Communication | CommEdgeCreate, Destroy, IpcSend, IpcReceive, ZeroCopyShare, NotificationSignal |
| `0x40-0x4F` | Device operations | LeaseGrant, LeaseRevoke, LeaseExpire, LeaseRenew |
| `0x50-0x5F` | Proof verification | ProofVerifiedP1, P2, P3, ProofRejected, ProofEscalated |
| `0x60-0x6F` | Scheduler decisions | Epoch, ModeSwitch, TaskSpawn, TaskTerminate, StructuralSplit, StructuralMerge |
| `0x70-0x7F` | Recovery actions | RecoveryEnter, Exit, CheckpointCreated, Restored, MinCutBudgetExceeded, DegradedMode |
| `0x80-0x8F` | Boot and attestation | BootAttestation, BootComplete, TeeAttestation |
| `0x90-0x9F` | Vector/Graph | VectorPut, VectorDelete, GraphMutation, CoherenceRecomputed |
| `0xA0-0xAF` | VMID management | VmidReclaim, MigrationTimeout |

Filter by subsystem using `ActionKind::subsystem()`, which returns the upper nibble:

```rust
let kind = ActionKind::PartitionSplit;
assert_eq!(kind.subsystem(), 0); // Partition subsystem
```

---

## 3. Hash Chain

Every record links to the previous one through an FNV-1a hash chain:

```
Record 0: prev_hash = 0 (genesis), record_hash = H(0, seq=0)
Record 1: prev_hash = H(0, seq=0), record_hash = H(H(0, seq=0), seq=1)
Record 2: prev_hash = H(..., seq=1), record_hash = H(H(..., seq=1), seq=2)
...
```

The chain hash is computed as `FNV-1a(prev_chain_hash || sequence)`, then XOR-folded from 64 bits to 32 bits for storage in the record fields (`(h >> 32) ^ (h & 0xFFFF_FFFF)`).

### Tamper Evidence

If an attacker modifies any record, the chain breaks at the next record because its `prev_hash` will no longer match the tampered record's `record_hash`. The `verify_chain()` function walks a slice of records and confirms every link:

```rust
use rvm_witness::verify_chain;

// records: &[WitnessRecord] -- a contiguous snapshot
match verify_chain(&records) {
    Ok(count) => println!("Chain valid: {count} records"),
    Err(ChainIntegrityError::ChainBreak { sequence }) => {
        println!("Chain broken at sequence {sequence}");
    }
    Err(ChainIntegrityError::RecordCorrupted { sequence }) => {
        println!("Record corrupted at sequence {sequence}");
    }
    Err(ChainIntegrityError::EmptyLog) => {
        println!("No records to verify");
    }
}
```

### Limitations

FNV-1a is chosen for speed (under 50 ns for 64 bytes), not cryptographic strength. An adversary with direct memory access could recompute the chain after tampering. For protection against such adversaries, enable the `crypto-sha256` feature and use the `HmacWitnessSigner` or a TEE-backed signer. See [Signing](#4-signing) below.

---

## 4. Signing

Witness records can optionally be **signed** by a `WitnessSigner`. The 8-byte `aux` field in each record stores a truncated signature. Signing occurs during append, after the chain hashes are set, so the signature covers all fields including `prev_hash` and `record_hash`.

### Signer Implementations

| Signer | How It Works | When to Use |
|--------|-------------|-------------|
| `StrictSigner` | FNV-1a over the first 52 bytes of the serialized record | Default fallback (no `crypto-sha256` feature). Non-cryptographic but non-trivial tamper evidence. |
| `HmacWitnessSigner` | HMAC-SHA256 over the first 52 bytes, truncated to 8 bytes. Keyed PRF. | Production without TEE. Requires `crypto-sha256` feature. |
| `NullSigner` | Returns all zeros. Accepts everything. | **Deprecated.** Testing only. Gated behind `null-signer` feature or `#[cfg(test)]`. |

The `DefaultSigner` type alias resolves to `HmacWitnessSigner` when `crypto-sha256` is enabled, or `StrictSigner` otherwise. Use `default_signer()` to get the right one:

```rust
use rvm_witness::{default_signer, WitnessSigner, WitnessLog};
use rvm_types::{WitnessRecord, ActionKind};

let signer = default_signer();
let log = WitnessLog::<256>::new();

let mut record = WitnessRecord::zeroed();
record.action_kind = ActionKind::PartitionCreate as u8;
record.actor_partition_id = 1;
record.target_object_id = 42;

// signed_append fills chain hashes AND signs in one atomic step
log.signed_append(record, &signer);

// Retrieve and verify
let stored = log.get(0).unwrap();
assert!(signer.verify(&stored)); // signature is valid
```

### Signed Append vs Plain Append

| Method | Chain Hashes | Signature | Use When |
|--------|-------------|-----------|----------|
| `log.append(record)` | Set | Not set (`aux` = caller's value) | No signing configured |
| `log.signed_append(record, &signer)` | Set | Set in `aux` after chain hashes | Production deployments |

The key difference: `signed_append` signs the fully-populated record (sequence, prev_hash, record_hash all set), so the signature covers the chain metadata. Signing before append would miss those fields.

### Tampered Records Fail Verification

```rust
let mut stored = log.get(0).unwrap();
stored.actor_partition_id = 999; // tamper
assert!(!signer.verify(&stored)); // fails
```

---

## 5. Querying the Trail

The `rvm_witness::replay` module provides three query functions that filter a snapshot of records:

### By Partition

```rust
use rvm_witness::query_by_partition;

let records = /* snapshot from log.snapshot() */;
for record in query_by_partition(&records, partition_id) {
    // all records where actor_partition_id == partition_id
}
```

### By Action Kind

```rust
use rvm_witness::query_by_action_kind;
use rvm_types::ActionKind;

for record in query_by_action_kind(&records, ActionKind::CapabilityGrant as u8) {
    // all capability grant events
}
```

### By Time Range

```rust
use rvm_witness::query_by_time_range;

for record in query_by_time_range(&records, start_ns, end_ns) {
    // all records with timestamp_ns in [start_ns, end_ns]
}
```

All three return iterators, so they compose naturally:

```rust
// All capability grants by partition 3 in the last second
let grants_by_p3 = query_by_partition(&records, 3)
    .filter(|r| r.action_kind == ActionKind::CapabilityGrant as u8)
    .filter(|r| r.timestamp_ns >= now_ns - 1_000_000_000);
```

---

## 6. The Ring Buffer

The `WitnessLog<N>` is an append-only ring buffer backed by a fixed-size array of `N` witness records, protected by a `spin::Mutex` for thread safety.

### Default Capacity

```
DEFAULT_RING_CAPACITY = 262,144 records
Record size = 64 bytes
Total memory = 262,144 * 64 = 16 MiB
```

At a rate of 100,000 privileged actions per second, this provides approximately 2.6 seconds of hot storage before the oldest records are overwritten.

### Overflow Behavior

When the write position wraps around, the oldest records are silently overwritten. The ring buffer never blocks, never allocates, and never fails to accept a record. The `total_emitted()` counter tracks the total number of records ever written (not just the number currently in the buffer):

```rust
let log = WitnessLog::<4>::new();
for i in 0..10 {
    log.append(make_record(i));
}
assert_eq!(log.total_emitted(), 10); // 10 records written
assert_eq!(log.len(), 4);            // only 4 in the buffer
```

### Snapshots

To extract records for analysis, use `snapshot()`:

```rust
let mut buf = [WitnessRecord::zeroed(); 64];
let copied = log.snapshot(&mut buf);
// buf[0..copied] contains the most recent `copied` records
```

The snapshot is taken under the lock, so it is consistent. Records are returned in chronological order (oldest first within the copied range).

---

## 7. Deterministic Replay

Because every mutation is witnessed, the witness trail combined with a checkpoint forms a **reconstructable execution history**. Given:

1. A checkpoint of partition state at sequence S, and
2. All witness records from sequence S onward,

you can reconstruct the exact state at any later sequence number by replaying the mutations in order.

### Chain Integrity as a Prerequisite

Before replay, verify the chain:

```rust
use rvm_witness::verify_chain;

let result = verify_chain(&records);
match result {
    Ok(count) => {
        // Safe to replay: chain is intact
    }
    Err(e) => {
        // Chain is compromised: do not trust replay
        panic!("Chain integrity error: {e}");
    }
}
```

### Applications

- **Memory reconstruction** -- Dormant memory regions are stored as a checkpoint plus delta-compressed witness trail. When a region is promoted back to Hot, the reconstruction pipeline replays the witness records to rebuild state. See [Memory Model: Memory Time Travel](08-memory-model.md).

- **Forensic analysis** -- After an incident, the witness trail provides a complete record of who did what, when, with which capability, at which proof tier. See [Advanced: Forensics](13-advanced-exotic.md).

- **Migration verification** -- When a partition migrates to another node, the receiving node can verify the witness chain to confirm the partition's history is untampered.

- **Debugging** -- The witness trail provides a total ordering of all privileged actions, making it possible to reconstruct race conditions and timing-dependent bugs.

---

## Cross-References

- **Proof tiers that authorize mutations** -- P1/P2/P3 and how they connect to witness emission: [Capabilities and Proofs](05-capabilities-proofs.md)
- **The Security Gate pipeline** -- How capability check + proof + witness emission form the unified entry point: [Security Architecture](10-security.md)
- **Memory time travel** -- Using the witness trail for dormant memory reconstruction: [Memory Model](08-memory-model.md)
- **Partition lifecycle events** -- Which partition actions produce which witness records: [Partitions and Scheduling](07-partitions-scheduling.md)
- **Forensic queries and advanced replay** -- Deeper analysis techniques: [Advanced and Exotic](13-advanced-exotic.md)
- **Bare-metal boot attestation** -- The genesis witness record and boot sequence: [Bare Metal](12-bare-metal.md)
- **Performance** -- Witness emission latency benchmarks (~17 ns target): [Performance](11-performance.md)
- **Crate API surface** -- `rvm-witness`, `rvm-types`: [Crate Reference](04-crate-reference.md)
- **Glossary** -- Definitions of witness record, hash chain, ring buffer, signer: [Glossary](15-glossary.md)
