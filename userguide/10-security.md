# Security Architecture: Defense in Depth

RVM's security model is not a layer bolted on top. It is the system's structure. Every hypercall passes through a three-stage gate. Every mutation is proof-gated. Every decision is witnessed. This chapter describes the gate pipeline, the policy evaluation logic, attestation, resource budgets, input validation, and the results of the security audit.

> **Prerequisite reading:** [Capabilities and Proofs](05-capabilities-proofs.md) for the trust model and proof tiers. [Witness and Audit](06-witness-audit.md) for the witness trail.

---

## 1. The Three-Stage Security Gate

Every privileged operation in RVM enters through the **Security Gate** (`rvm_security::gate`). The gate is the single entry point -- there is no bypass. The pipeline has three mandatory stages:

```
Hypercall
  |
  v
[Stage 1: Capability Check]  -- Does the caller hold the right type and rights?
  |
  v
[Stage 2: Proof Verification] -- Is the proof commitment valid?
  |
  v
[Stage 3: Witness Logging]   -- Record the decision for audit
  |
  v
Operation proceeds (or is denied)
```

If any stage fails, a `ProofRejected` witness record is emitted and the operation is denied. Even denials are witnessed -- you can audit who tried what and failed.

### `SecurityGate`

The basic gate wraps a `WitnessLog` reference:

```rust
use rvm_security::gate::{SecurityGate, GateRequest, GateResponse};
use rvm_witness::WitnessLog;

let log = WitnessLog::<256>::new();
let gate = SecurityGate::new(&log);
```

### `GateRequest`

A request to the gate carries everything needed for evaluation:

```rust
pub struct GateRequest {
    pub token: CapToken,              // The capability presented by the caller
    pub required_type: CapType,       // Expected capability type
    pub required_rights: CapRights,   // Required rights bitmask
    pub proof_commitment: Option<WitnessHash>, // P2 proof commitment (if needed)
    pub require_p3: bool,             // Whether P3 deep proof is required
    pub p3_chain_valid: bool,         // Advisory only -- gate ignores this
    pub p3_witness_data: Option<P3WitnessChain>, // Actual chain data for P3
    pub action: ActionKind,           // What operation is being attempted
    pub target_object_id: u64,        // Object being acted upon
    pub timestamp_ns: u64,            // Current timestamp
}
```

**Important:** The `p3_chain_valid` field is **advisory only**. The gate does not trust it. When `require_p3` is true, the gate calls its own `verify_p3_chain()` function on the `p3_witness_data`. A caller that sets `p3_chain_valid = true` but supplies a broken chain will be rejected. This was a security fix -- see [Audit Finding: P3 bypass](#security-audit-results).

### `GateResponse`

On success, the gate returns the witness sequence number and the proof tier that was satisfied:

```rust
pub struct GateResponse {
    pub witness_sequence: u64,  // Sequence number of the emitted witness record
    pub proof_tier: u8,         // 1 = P1 only, 2 = P2, 3 = P3
}
```

### Gate Pipeline in Detail

1. **P1 Capability Check -- Type Match.** The token's `cap_type()` must equal `required_type`. If not: emit `ProofRejected`, return `CapabilityTypeMismatch`.

2. **P1 Capability Check -- Rights Subset.** The token must carry all `required_rights`. If not: emit `ProofRejected`, return `InsufficientRights`.

3. **P2 Policy Validation -- Proof Commitment.** If `proof_commitment` is `Some`, it must not be the zero hash. A zero commitment is rejected as `PolicyViolation`. If no commitment is required (`None`), the gate reports P1-only (tier = 1).

4. **P3 Deep Proof (if required).** If `require_p3` is true, the gate verifies the `P3WitnessChain` by walking its links and confirming that each link's `record_hash` equals the next link's `prev_hash`. Empty or broken chains are rejected as `DerivationChainBroken`.

5. **Witness Emission.** On success, an allowed-action witness record is appended. On failure at any stage, a `ProofRejected` witness is appended first, then the error is returned.

### `SignedSecurityGate`

The `SignedSecurityGate` extends the basic gate with a `WitnessSigner`. It behaves identically except:

- All witness records (both allowed and rejected) are signed via `signed_append`.
- P3 chain verification also checks auxiliary signatures on each chain link, providing cryptographic tamper evidence beyond hash-chain continuity.

```rust
use rvm_security::gate::SignedSecurityGate;
use rvm_witness::default_signer;

let log = WitnessLog::<256>::new();
let signer = default_signer();
let gate = SignedSecurityGate::new(&log, &signer);

let response = gate.check_and_execute(&request)?;
// Emitted witness record has a non-zero aux field (signed)
```

Links with all-zero signatures are skipped during verification, maintaining backwards compatibility with unsigned chains.

---

## 2. PolicyRequest and Evaluation

For code paths that need a quick capability check without the full gate pipeline (e.g., internal kernel paths that handle their own witness logging), RVM provides a lightweight `PolicyRequest` evaluator.

### PolicyRequest Fields

```rust
pub struct PolicyRequest<'a> {
    pub token: &'a CapToken,               // Capability token
    pub required_type: CapType,            // Expected type
    pub required_rights: CapRights,        // Required rights
    pub proof_commitment: Option<&'a WitnessHash>, // Optional proof commitment
    pub current_epoch: Option<u32>,        // Optional epoch for staleness check
}
```

### Evaluation Stages

The `evaluate()` function checks four stages in order:

| Stage | Check | Error on Failure |
|-------|-------|-----------------|
| 0 | **Epoch freshness** -- If `current_epoch` is provided, the token's epoch must match | `InsufficientCapability` |
| 1 | **Capability type** -- Token type must equal `required_type` | `CapabilityTypeMismatch` |
| 2 | **Rights** -- Token must contain all `required_rights` | `InsufficientCapability` |
| 3 | **Proof commitment** -- If provided, must not be the zero hash | `ProofInvalid` |

```rust
use rvm_security::{PolicyRequest, evaluate, enforce, PolicyDecision};
use rvm_types::{CapToken, CapType, CapRights};

let token = CapToken::new(1, CapType::Partition, CapRights::READ | CapRights::WRITE, 5);

let request = PolicyRequest {
    token: &token,
    required_type: CapType::Partition,
    required_rights: CapRights::READ,
    proof_commitment: None,
    current_epoch: Some(5),
};

// evaluate() returns Allow or Deny
match evaluate(&request) {
    PolicyDecision::Allow => { /* proceed */ }
    PolicyDecision::Deny(err) => { /* handle */ }
}

// enforce() returns RvmResult<()> for ergonomic use
enforce(&request)?;
```

### P2 Policy Rules (Proof Engine)

The `ProofEngine` uses a separate `PolicyEvaluator` (in `rvm_proof::policy`) that evaluates six P2 rules in **constant time** to prevent timing side-channel leakage. Every rule is evaluated regardless of intermediate failures:

| Rule | What It Checks |
|------|---------------|
| `OwnershipChain` | Partition ID is within the valid range (0..=4096) |
| `RegionBounds` | Region base < region limit (no inverted bounds) |
| `LeaseExpiry` | Current time <= lease expiry time |
| `DelegationDepth` | Depth <= 8 |
| `NonceReplay` | Nonce has not been used before (4096-entry ring + watermark) |
| `TimeWindow` | Current time <= lease expiry (time-bounded operation) |

The nonce replay ring buffer holds 4096 entries (upgraded from 64 after audit) with a monotonic watermark that rejects any nonce at or below the low-water mark, even if it has been evicted from the ring.

---

## 3. Attestation

The attestation subsystem (`rvm_security::attestation`) builds a tamper-evident chain of boot measurements and runtime witness hashes.

### `AttestationChain`

The chain accumulates up to 64 entries, each tagged as either boot (tag=0) or runtime (tag=1):

```rust
use rvm_security::AttestationChain;

let mut chain = AttestationChain::new();
chain.add_boot_measurement([0xAA; 32]);     // e.g., kernel image hash
chain.add_boot_measurement([0xBB; 32]);     // e.g., device tree hash
chain.add_runtime_witness([0xCC; 32]);      // e.g., witness log digest
```

Each entry extends the running chain hash. When `crypto-sha256` is enabled, the extension uses `SHA-256(current_chain_hash || measurement)`. Without it, a legacy FNV-1a overlapping-window scheme is used.

### `AttestationReport`

Generate a report summarizing the chain state:

```rust
let report = chain.generate_attestation_report();
// report.entry_count, report.chain_root, 
// report.boot_measurement_count, report.runtime_witness_count
```

### Verification

Verify a report against an expected chain root:

```rust
use rvm_security::verify_attestation;

let expected_root = /* computed independently or received from a trusted source */;
assert!(verify_attestation(&report, &expected_root));
```

Verification uses constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing side-channel attacks when the chain root is derived from secrets.

For TEE-backed attestation (binding the chain to a hardware measurement), see [Capabilities and Proofs: TEE-Backed Verification](05-capabilities-proofs.md#5-tee-backed-verification-adr-142).

---

## 4. Resource Budgets

Resource budgets prevent a single partition from starving others by exhausting shared resources.

### DMA Budget

The `DmaBudget` tracks DMA bandwidth per epoch:

```rust
use rvm_security::DmaBudget;

let mut budget = DmaBudget::new(1_000_000); // 1 MB per epoch

budget.check_dma(500_000)?;  // OK, 500 KB remaining
budget.check_dma(600_000)?;  // Err(ResourceLimitExceeded) -- over budget

budget.reset(); // New epoch: budget restored
```

The check uses `checked_add` to prevent integer overflow exploits.

### Resource Quota

The `ResourceQuota` combines four limits per partition:

| Resource | Field | Reset per Epoch? |
|----------|-------|-----------------|
| CPU time (ns) | `cpu_time_ns` | Yes |
| Memory (bytes) | `memory_bytes` | **No** (persistent allocation) |
| IPC rate (messages) | `ipc_rate` | Yes |
| DMA bandwidth (bytes) | `dma` | Yes |

```rust
use rvm_security::ResourceQuota;

let mut quota = ResourceQuota::new(
    1_000_000,    // 1 ms CPU per epoch
    4096,         // 4 KiB memory
    100,          // 100 IPC messages per epoch
    1_000_000,    // 1 MB DMA per epoch
);

quota.check_cpu_time(500_000)?;  // OK
quota.check_memory(2048)?;       // OK
quota.check_ipc()?;              // OK
quota.dma.check_dma(100_000)?;   // OK

// At epoch boundary:
quota.reset_epoch(); // Resets CPU, IPC, DMA. Memory is NOT reset.
```

Memory is not reset at epoch boundaries because it represents persistent allocation. Use `release_memory(bytes)` to return memory explicitly.

---

## 5. Input Validation

The `rvm_security::validation` module provides boundary validation functions used throughout the kernel.

### Partition ID Validation

```rust
use rvm_security::validation::validate_partition_id;

validate_partition_id(0)?;     // Err(InvalidPartitionState) -- reserved for hypervisor
validate_partition_id(1)?;     // Ok
validate_partition_id(4096)?;  // Ok (maximum)
validate_partition_id(4097)?;  // Err(PartitionLimitExceeded)
```

### Region Bounds Validation

Validates page alignment (4 KiB), non-zero size, and overflow safety:

```rust
use rvm_security::validation::validate_region_bounds;

validate_region_bounds(0x1000, 0x1000)?; // Ok: aligned, no overflow
validate_region_bounds(0x1001, 0x1000)?; // Err(AlignmentError): unaligned address
validate_region_bounds(0x1000, 0)?;      // Err(AlignmentError): zero size
validate_region_bounds(u64::MAX - 0xFFF, 0x2000)?; // Err(MemoryOverlap): overflow
```

### Capability Rights Validation

Ensures requested rights are a subset of held rights:

```rust
use rvm_security::validation::validate_capability_rights;
use rvm_types::CapRights;

let held = CapRights::READ | CapRights::WRITE;
validate_capability_rights(CapRights::READ, held)?;  // Ok
validate_capability_rights(CapRights::EXECUTE, held)?; // Err(InsufficientCapability)
```

### Lease Expiry Validation

```rust
use rvm_security::validation::validate_lease_expiry;

validate_lease_expiry(100, 50)?;  // Ok: current epoch 50 < expiry 100
validate_lease_expiry(100, 100)?; // Err(DeviceLeaseExpired): expired
```

---

## 6. Security Audit Results

RVM underwent a comprehensive security audit. 11 findings were identified, 8 have been fixed.

| Severity | Finding | Fix Applied |
|----------|---------|-------------|
| **Critical** | P1 timing side channel in capability bitmask comparison | Constant-time bitmask comparison (`rvm_proof::constant_time`) |
| **High** | Revocation did not propagate through the full derivation subtree | Iterative subtree walk with explicit stack (replaces recursive descent) |
| **High** | Cross-partition host memory overlap allowed | Global overlap check before region mapping |
| **Medium** | Generation counter wrap-around at 0 reuses sentinel | Skip generation 0 on wrap (0 is the invalid sentinel) |
| **Medium** | `next_id` overflow in capability manager | `checked_add` with `TableFull` error on overflow |
| **Medium** | Recursive revoke could stack overflow on deep trees | Replaced with iterative stack-based walk |
| **Medium** | Incomplete merge preconditions allowed invalid merges | Full validation of both partitions before merge |
| **Low** | Terminated WASM agent slots never freed | Set slot to `None` on agent termination |
| **Medium** | Nonce ring buffer too small (64 entries) | Upgraded to 4096 entries with monotonic watermark |
| **Medium** | TOCTOU race in quota check-then-record | Atomic `check_and_record` in single lock hold |
| **Low** | `NullSigner` always returns true | `StrictSigner` as default; `NullSigner` deprecated and gated behind feature flag |

### Remaining Open Items

Three findings from the audit are deferred or accepted:

- **P3 ZK verification** -- Requires TEE hardware integration. Deferred.
- **u32 generation counter forgery window** -- Requires 2^32 allocate/free cycles on a single slot to exploit. Accepted as residual risk. Widening to u64 would double `CapSlot` size.
- **FNV-1a hash chain** -- Not cryptographically strong. Mitigated by `HmacWitnessSigner` when `crypto-sha256` is enabled.

---

## 7. Security Best Practices

### Production Configuration

1. **Always use `StrictSigner` or `HmacWitnessSigner` in production.** Never ship with `NullSigner`. The `null-signer` feature flag exists only for testing.

2. **Enable the `crypto-sha256` feature.** This activates HMAC-SHA256 signing for witness records and SHA-256 for attestation chain extension. Without it, you get FNV-1a (fast but not cryptographically strong).

3. **Replace the default signing key.** The compile-time default key `SHA-256(b"rvm-witness-default-key-v1")` is public. In production, derive keys from the TEE hardware measurement using `derive_key_bundle()`.

4. **Use `SignedSecurityGate` instead of `SecurityGate`.** The signed variant signs every witness record (including rejections) and verifies P3 chain signatures.

### Input Validation

5. **Validate all inputs at system boundaries.** Use the `rvm_security::validation` functions before any state mutation. Never trust partition IDs, region bounds, or rights bitmasks from untrusted callers.

6. **Never skip P2 policy evaluation.** Even if P1 passes, P2 catches structural violations (inverted region bounds, nonce replay, expired leases, excessive delegation depth).

### Capability Hygiene

7. **Grant minimum necessary rights.** Follow the principle of least privilege. If a partition only needs to read a region, grant `READ` only.

8. **Use `GRANT_ONCE` for non-transitive delegation.** Prevents authority from propagating beyond the intended recipient.

9. **Use epoch-based revocation for bulk invalidation.** When you need to revoke all capabilities issued before a certain point, increment the epoch. All tokens from prior epochs become stale.

10. **Keep delegation depth shallow.** The 8-level limit exists for a reason. Deep chains are harder to audit and slower to revoke.

### Monitoring

11. **Monitor `ManagerStats`.** Watch `caps_created`, `caps_granted`, `caps_revoked`, and `max_depth_reached` for anomalies.

12. **Periodically verify the witness chain.** Run `verify_chain()` on snapshots to detect tampering.

13. **Set resource quotas.** Every partition should have a `ResourceQuota` with meaningful limits for CPU, memory, IPC, and DMA.

---

## Cross-References

- **Capability types, rights, and delegation** -- The trust model this gate enforces: [Capabilities and Proofs](05-capabilities-proofs.md)
- **Witness trail format and signing** -- What the gate emits on every decision: [Witness and Audit](06-witness-audit.md)
- **TEE-backed verification** -- Hardware attestation for stronger signing: [Capabilities and Proofs: TEE](05-capabilities-proofs.md#5-tee-backed-verification-adr-142)
- **Partition lifecycle security** -- How split, merge, and migration interact with the gate: [Partitions and Scheduling](07-partitions-scheduling.md)
- **Memory isolation** -- How region capabilities prevent cross-partition access: [Memory Model](08-memory-model.md)
- **WASM agent sandboxing** -- How agent quotas and capabilities are enforced: [WASM Agents](09-wasm-agents.md)
- **Performance impact of security checks** -- Latency budgets for P1/P2/P3: [Performance](11-performance.md)
- **Bare-metal boot security** -- Measured boot and attestation chain initialization: [Bare Metal](12-bare-metal.md)
- **Crate API surface** -- `rvm-security`, `rvm-proof`, `rvm-cap`: [Crate Reference](04-crate-reference.md)
- **Glossary** -- Definitions of security gate, attestation, policy decision, DMA budget: [Glossary](15-glossary.md)
