# ADR-148: Error Model and Recovery State Machine

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core, DC-14 escalation), ADR-134 (Witness Schema), ADR-142 (TEE Crypto)

---

## Context

RVM's error model spans 34 error variants across 9 subsystems, a 4-level failure
classification, and recovery primitives (checkpoints and reconstruction receipts).
The deep review found that while the types are well-defined, the escalation
chain between failure classes, the mapping from `RvmError` variants to failure
classes, and the recovery state machine are not specified. Without this
specification, recovery logic cannot be implemented consistently across crates.

### Problem Statement

1. **No error-to-failure-class mapping**: which `RvmError` variants are Transient vs Permanent?
2. **No escalation protocol**: when does a Transient failure become Recoverable? When does Recoverable become Permanent?
3. **No recovery state machine**: how does a partition transition from error detection to checkpoint restore to resumed execution?
4. **No witness integration**: error events and recovery actions are not witnessed.
5. **Retryability is ambiguous**: callers cannot determine which errors are safe to retry.

---

## Decision

### 1. Failure Classes (F1--F4)

The `FailureClass` enum defines four severity levels with ordered discriminants
(`#[repr(u8)]`, `PartialOrd` + `Ord` derived). Severity can only escalate, never
de-escalate.

| Class | Enum | Value | Recovery Action | Scope |
|-------|------|-------|----------------|-------|
| F1 | `Transient` | 0 | Agent restart / retry | Single operation |
| F2 | `Recoverable` | 1 | Partition reconstruct from checkpoint | Single partition |
| F3 | `Permanent` | 2 | Memory rollback, partition destroy + recreate | Partition + dependents |
| F4 | `Catastrophic` | 3 | Kernel reboot | System-wide |

### 2. Error-to-Failure-Class Mapping

Each `RvmError` variant maps to a default `FailureClass`. Context may escalate
the class (e.g., repeated Transient failures escalate to Recoverable).

- **F1 (Transient)**: `ResourceLimitExceeded`, `WitnessLogFull`, `ProofBudgetExceeded`, `MinCutBudgetExceeded`, `MigrationTimeout`, `DeviceLeaseExpired` -- temporary conditions; retry after release or budget reset.
- **F2 (Recoverable)**: `InvalidPartitionState`, `SplitPreconditionFailed`, `MergePreconditionFailed`, `CoherenceBelowThreshold`, `StaleCapability`, `InvalidTierTransition`, `DeviceLeaseConflict` -- state corruption that checkpoint restore can fix.
- **F3 (Permanent)**: `PartitionNotFound`, `PartitionLimitExceeded`, `VcpuNotFound`, `VcpuLimitReached`, all Capability errors (`InsufficientCapability`, `CapabilityTypeMismatch`, `DelegationDepthExceeded`, `CapabilityConsumed`), `WitnessVerificationFailed`, `WitnessChainBroken`, `ProofInvalid`, `ProofTierInsufficient`, `MemoryOverlap`, `AlignmentError`, `OutOfMemory`, `DeviceLeaseNotFound`, `Unsupported` -- unrecoverable without partition destroy and recreate.
- **F4 (Catastrophic)**: `CheckpointNotFound`, `CheckpointCorrupted`, `FailureEscalated`, `InternalError` -- recovery infrastructure itself is compromised; kernel reboot required.

### 3. Witnessed Escalation Chain

Failure escalation follows a strict witnessed protocol:

```
F1 (Transient)
  │  retry count > 3
  ▼
F2 (Recoverable)
  │  checkpoint restore fails
  ▼
F3 (Permanent)
  │  reconstruction receipt cannot be created
  ▼
F4 (Catastrophic)
```

Each escalation step generates a witness record (ADR-134) containing:

- `original_error: RvmError` -- the triggering error variant.
- `from_class: FailureClass` -- the class before escalation.
- `to_class: FailureClass` -- the class after escalation.
- `partition_id: PartitionId` -- the affected partition.
- `epoch: u32` -- the epoch at escalation time.
- `retry_count: u32` -- number of retries attempted (F1 only).

Escalation is monotonic: once a failure reaches F3, it cannot return to F2.
The `FailureClass` enum's `Ord` implementation (`Transient < Recoverable <
Permanent < Catastrophic`) enforces this.

### 4. Recovery Checkpoint and Reconstruction Receipt

`RecoveryCheckpoint` captures a partition's restorable state: `partition: PartitionId`, `witness_sequence: u64`, `timestamp_ns: u64`, `epoch: u32`. Checkpoints are taken periodically (every N epochs), before risky operations (split, merge, migration), and on demand. Recovery restores the partition to the checkpoint state and replays witnessed events from `witness_sequence` forward, skipping the events that caused the failure.

`ReconstructionReceipt` provides an audit trail: `original_id: PartitionId`, `checkpoint: RecoveryCheckpoint`, `was_hibernated: bool`. The `was_hibernated` flag distinguishes Dormant-tier reactivation (`true`) from F3 failure recreation (`false`). The receipt is itself witnessed, creating an unbroken audit chain from failure detection through recovery completion.

### 5. Error Propagation Rules

| Property | Rule |
|----------|------|
| Retryability | F1 errors are safe to retry (up to 3 times). F2+ errors must not be retried without recovery. |
| Propagation | Errors propagate upward via `RvmResult<T>`. Callers must not silently discard errors. |
| Conversion | Lower-level errors may be wrapped in higher-level variants (e.g., `OutOfMemory` from the allocator becomes `InvalidPartitionState` at the partition layer if it prevents state transition). |
| Logging | All F2+ errors must be witness-logged before propagation. F1 errors are logged only on escalation. |
| Idempotency | Recovery actions (checkpoint restore, partition destroy) must be idempotent. Re-executing a recovery action on an already-recovered partition is a no-op. |

---

## Consequences

### Positive

- Clear mapping from error variants to failure classes enables automated recovery.
- Witnessed escalation creates an auditable chain from error to resolution.
- Monotonic escalation prevents recovery loops (bouncing between F1 and F2).
- `RecoveryCheckpoint` and `ReconstructionReceipt` provide complete audit trail.
- Retryability rules prevent callers from retrying non-retryable errors.

### Negative

- 34 error variants make exhaustive matching verbose.
- The 3-retry threshold for F1->F2 escalation is fixed; some errors may benefit from more retries.
- Checkpoint storage is not specified (this ADR covers the data model, not persistence).

### Risks

- If checkpoint frequency is too low, recovery may lose significant state.
- If witness logging of escalation events fails (e.g., `WitnessLogFull`), the
  escalation itself becomes an F4 event, potentially causing cascading failure.
- F3 recovery (partition destroy + recreate) loses all non-checkpointed state.

---

## References

- `rvm-types/src/error.rs` -- `RvmError` (34 variants), `RvmResult<T>`
- `rvm-types/src/recovery.rs` -- `FailureClass`, `RecoveryCheckpoint`, `ReconstructionReceipt`
- ADR-132, Section DC-14 -- Failure escalation protocol
- ADR-134 -- Witness schema and log format
- ADR-142 -- TEE-backed cryptographic verification (witness chain integrity)
