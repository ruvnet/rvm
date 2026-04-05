# Capabilities and Proofs: RVM's Trust Model

Every resource in RVM -- a partition, a memory region, a device lease, a communication edge -- is accessed through an **unforgeable capability token**. No pointer, no file descriptor, no ambient authority. If you do not hold a capability with the right bits set, the kernel will not let you touch the object. This chapter explains what capabilities are, how they propagate, and how the three-tier proof system binds every mutation to a verifiable commitment.

> **Prerequisite reading:** [Core Concepts](02-core-concepts.md) for an overview of the trust model. [Architecture](03-architecture.md) for crate layering.

---

## 1. Understanding Capabilities

A **capability** is a kernel-managed, unforgeable token that grants specific rights over a specific object. Unlike traditional permission checks ("is this user in group X?"), capabilities are explicit: you either hold one, or you do not. They cannot be forged, guessed, or manufactured outside the kernel.

### The 7 Rights

Every capability carries a **rights bitmask** (`CapRights`). The seven possible rights are:

| Right | Bit | Meaning |
|-------|-----|---------|
| `READ` | `0x01` | Inspect or read the resource |
| `WRITE` | `0x02` | Mutate the resource |
| `GRANT` | `0x04` | Copy (delegate) this capability to another partition |
| `REVOKE` | `0x08` | Revoke capabilities derived from this one |
| `EXECUTE` | `0x10` | Execute code within the resource's context |
| `PROVE` | `0x20` | Create a proof referencing this capability |
| `GRANT_ONCE` | `0x40` | One-time grant: consumed after a single delegation |

Rights are combined with bitwise OR. A partition that holds `READ | WRITE` on a region can read and write it, but cannot delegate it (no `GRANT`), cannot revoke children (no `REVOKE`), and cannot use it as evidence in a proof (no `PROVE`).

### Capability Types (`CapType`)

Each capability targets a specific kind of kernel object:

| CapType | Discriminant | Controls |
|---------|-------------|----------|
| `Partition` | 0 | Create, destroy, split, merge partitions |
| `Region` | 1 | Map, transfer, tier-change memory regions |
| `CommEdge` | 2 | Create, destroy, send on communication edges |
| `Device` | 3 | Grant, revoke, renew device leases |
| `Scheduler` | 4 | Mode switch, priority override |
| `WitnessLog` | 5 | Query, export the witness trail |
| `Proof` | 6 | Escalation, deep proof verification |
| `Vcpu` | 7 | Virtual CPU control |
| `Coherence` | 8 | Coherence observer operations |

### The `CapToken` Struct

A `CapToken` is the user-visible handle. It holds four fields:

```rust
pub struct CapToken {
    id: u64,           // Globally unique identifier
    cap_type: CapType, // What kind of object this targets
    rights: CapRights, // What operations are permitted
    epoch: u32,        // Monotonic epoch for staleness detection
}
```

Create one like this:

```rust
let token = CapToken::new(
    1,                                        // capability ID
    CapType::Partition,                       // targets a partition
    CapRights::READ | CapRights::WRITE,       // can read and write
    0,                                        // epoch 0
);

assert!(token.has_rights(CapRights::READ));   // true
assert!(!token.has_rights(CapRights::GRANT)); // false -- not granted
```

The `epoch` field is critical for revocation: when the kernel advances its epoch counter, any token minted in a prior epoch becomes stale and is rejected at P1 verification.

---

## 2. Delegation and Derivation Trees

Capabilities propagate through **delegation**. When Partition A holds a capability and grants it to Partition B, a new derived capability is created. The derivation forms a tree:

```
Root (owner: Hypervisor, rights: ALL, depth: 0)
  |
  +-- Child A (owner: Partition 1, rights: READ|WRITE|GRANT, depth: 1)
  |     |
  |     +-- Grandchild (owner: Partition 2, rights: READ, depth: 2)
  |
  +-- Child B (owner: Partition 3, rights: READ, depth: 1)
```

### Monotonic Attenuation

A child capability can only have **equal or fewer** rights than its parent. You cannot escalate. If a parent holds `READ | WRITE | GRANT`, it can grant `READ` or `READ | WRITE`, but never `EXECUTE` (which it does not hold).

This is enforced in the `validate_grant` function during every delegation.

### Maximum Delegation Depth

The delegation depth is bounded at **8 levels** (`MAX_DELEGATION_DEPTH = 8`). Each derivation increments the depth counter. When depth reaches the limit, further grants are rejected with `CapError::DelegationDepthExceeded`. This prevents unbounded authority chains that would complicate revocation and audit.

### `GRANT_ONCE` for Non-Transitive Delegation

The `GRANT_ONCE` right enables a single delegation and is then consumed from the source. After Partition A grants a `GRANT_ONCE` capability to Partition B, the `GRANT_ONCE` bit is cleared from A's copy. B cannot re-delegate it further (unless B's copy also carries `GRANT` or `GRANT_ONCE`).

This provides a clean non-transitive delegation pattern: "I give you this right, but you cannot pass it on."

### Epoch-Based Invalidation

Every capability records the epoch in which it was minted. When the kernel calls `increment_epoch()`, any token whose epoch does not match the new global epoch is considered stale. P1 verification rejects it immediately:

```rust
// Create a capability at epoch 0
let (idx, gen) = mgr.create_root_capability(
    CapType::Region, CapRights::READ, 0, owner,
).unwrap();

// Verification passes at epoch 0
assert!(mgr.verify_p1(idx, gen, CapRights::READ).is_ok());

// Advance epoch
mgr.increment_epoch();

// Now the same capability is stale
assert_eq!(
    mgr.verify_p1(idx, gen, CapRights::READ),
    Err(ProofError::StaleCapability),
);
```

### Code Example: Capability Derivation

```rust
use rvm_cap::{CapabilityManager, CapManagerConfig};
use rvm_types::{CapType, CapRights, PartitionId};

let mut mgr = CapabilityManager::<64>::with_defaults();
let owner = PartitionId::new(1);
let target = PartitionId::new(2);

// Create a root capability with broad rights
let (root_idx, root_gen) = mgr.create_root_capability(
    CapType::Region,
    CapRights::READ | CapRights::WRITE | CapRights::GRANT,
    0,     // badge
    owner,
).unwrap();

// Grant a read-only copy to another partition (attenuated)
let (child_idx, child_gen) = mgr.grant(
    root_idx, root_gen,
    CapRights::READ,  // fewer rights than parent
    42,               // badge for identifying this grant
    target,
).unwrap();

// The child has depth 1 and read-only rights
let child = mgr.table().lookup(child_idx, child_gen).unwrap();
assert_eq!(child.token.rights(), CapRights::READ);
assert_eq!(child.depth, 1);
```

---

## 3. The Capability Manager

The `CapabilityManager` is the single integration point for all capability operations. It coordinates three internal structures:

- **`CapabilityTable<N>`** -- A fixed-size array (default N = 256) of `CapSlot` entries. Each slot holds a capability token, its owner, delegation depth, parent index, badge, and a generation counter for stale-handle detection.

- **`DerivationTree<N>`** -- A first-child / next-sibling linked list tracking parent-child relationships. Used for revocation propagation.

- **`ProofVerifier<N>`** -- Implements P1, P2, and P3 verification against the table and tree.

### Core Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Create | `create_root_capability()` | Allocates a root capability (no parent) |
| Grant | `grant()` | Derives a child capability with attenuated rights |
| Revoke | `revoke()` | Invalidates a capability and all its descendants |
| P1 Verify | `verify_p1()` | Checks existence, epoch freshness, and rights |
| P2 Verify | `verify_p2()` | Structural invariant validation |
| P3 Verify | `verify_p3()` | Deep derivation chain walk to root |

### Revocation Propagation

When you revoke a capability, all its descendants are also invalidated. The implementation uses an **iterative** subtree walk (not recursive) to avoid stack overflow on deep derivation trees -- this was a security fix for a stack-overflow vulnerability found during audit.

```rust
let result = mgr.revoke(root_idx, root_gen).unwrap();
// result.revoked_count includes the root and all descendants
```

The `RevokeResult` reports how many capabilities were invalidated. The `ManagerStats` struct tracks cumulative statistics:

```rust
let stats = mgr.stats();
println!("Created: {}, Granted: {}, Revoked: {}", 
    stats.caps_created, stats.caps_granted, stats.caps_revoked);
```

---

## 4. The Three-Tier Proof System

Every state mutation in RVM requires a **proof**. Proofs trade off verification cost against assurance level:

| Tier | Name | Budget | Mechanism | Use Case |
|------|------|--------|-----------|----------|
| **P1** | Hash | < 1 us | FNV-1a preimage / capability check | Routine transitions |
| **P2** | Witness | < 100 us | Witness chain + policy validation | Cross-partition ops |
| **P3** | Zk | < 10 ms | Deep proof / deferred ZK | Privacy-preserving (deferred) |

### P1: Hash Proof

The cheapest tier. A SHA-256 preimage or FNV-1a hash is computed over the proof data and compared against a commitment. Under 1 microsecond.

```rust
use rvm_proof::{Proof, compute_data_hash, verify};

// The prover commits to data by hashing it
let data = b"partition-create-request";
let commitment = compute_data_hash(data);

// Later, the prover submits the preimage as proof
let proof = Proof::hash_proof(commitment, data);

// The verifier checks the proof against the commitment
assert!(verify(&proof, &commitment).is_ok());
```

`compute_data_hash` produces a 32-byte `WitnessHash` from FNV-1a, placed in the first 8 bytes (little-endian) with the remaining 24 bytes zeroed.

### P2: Witness Chain Proof

A more expensive tier that validates witness chain linkage. The proof data contains one or more 16-byte links, each a `(prev_hash: u64, record_hash: u64)` pair. The verifier walks the chain and confirms that each record's `prev_hash` equals the preceding record's `record_hash`.

```rust
// Witness chain data: two 16-byte links
// Link 0: prev_hash=0, record_hash=0xAABB
// Link 1: prev_hash=0xAABB, record_hash=0xCCDD
// The chain is valid because link[0].record_hash == link[1].prev_hash
```

The `ProofEngine` orchestrates the full pipeline: P1 capability check, then P2 policy validation, then witness emission. See the [Unified Proof Engine](#unified-proof-engine) section below.

### P3: Deep Proof (Deferred)

P3 walks the entire derivation chain from a capability back to its root, verifying that every ancestor is valid, depth is monotonic, and epochs are non-decreasing. Full zero-knowledge proof support requires TEE integration and is deferred to a future release.

```rust
// P3 verification walks the derivation tree
mgr.verify_p3(cap_index, cap_generation, max_depth)?;
```

### Capability-Gated Proof Submission

To submit a proof, the caller must hold a capability with the `PROVE` right:

```rust
use rvm_proof::verify_with_cap;

// This checks PROVE right first, then verifies the proof
verify_with_cap(&proof, &commitment, &token)?;
// Returns Err(InsufficientCapability) if PROVE is missing
```

### Unified Proof Engine

The `ProofEngine` ties P1 + P2 + witness emission into one call:

```rust
use rvm_proof::engine::ProofEngine;

let mut engine = ProofEngine::<64>::new();
engine.verify_and_witness(
    &proof_token,   // which tier is being claimed
    &context,       // proof context (partition, region, nonce, etc.)
    &cap_manager,   // for P1 capability lookup
    &witness_log,   // for witness emission
)?;
```

If P1 fails, a `ProofRejected` witness is emitted and the error is returned. If P2 policy evaluation fails, same. Only on full success is a tier-specific success witness emitted.

---

## 5. TEE-Backed Verification (ADR-142)

For environments with hardware attestation (Intel SGX, AMD SEV-SNP, Intel TDX, Arm CCA), RVM provides a TEE signing pipeline.

### Software TEE Components

RVM ships software-emulated TEE components for development and testing:

| Component | Role |
|-----------|------|
| `SoftwareTeeProvider` | Generates attestation quotes using HMAC-SHA256 |
| `SoftwareTeeVerifier` | Validates quotes against expected measurements |
| `TeeWitnessSigner` | Combines quote generation + verification + HMAC signing |

### The `TeeWitnessSigner` Pipeline

The signing flow for every witness record is:

1. **Generate** a TEE attestation quote binding the digest to the enclave measurement.
2. **Verify** the quote against the expected measurement (self-attestation).
3. **Sign** the digest with the inner HMAC-SHA256 signer.

If self-attestation fails, the signer returns a zero signature, which will fail verification. This fail-closed design ensures that a compromised TEE environment cannot produce valid witness records.

### Witness Signer Hierarchy

| Signer | Strength | Feature Gate | Use Case |
|--------|----------|--------------|----------|
| `NullSigner` | None (always true) | `null-signer` or test | **Deprecated.** Testing only. |
| `StrictSigner` | FNV-1a | Always available | Non-TEE deployments, lightweight tamper evidence |
| `HmacWitnessSigner` | HMAC-SHA256 | `crypto-sha256` | Production without TEE |
| `HmacSha256WitnessSigner` | HMAC-SHA256 (64-byte sig) | `crypto-sha256` | Proof-crate signer trait |
| `Ed25519WitnessSigner` | Ed25519 (`verify_strict`) | `ed25519` | Asymmetric signing |
| `DualHmacSigner` | Dual HMAC-SHA256 | `crypto-sha256` | Strong symmetric, 64-byte signatures |
| `TeeWitnessSigner` | TEE-bound HMAC | `crypto-sha256` | Full attestation-backed signing |

### Key Derivation

The `KeyBundle` type and `derive_key_bundle` function (gated behind `crypto-sha256`) derive signing keys from a platform measurement and a salt. In production, the measurement comes from the TEE hardware. The compile-time default key (`SHA-256(b"rvm-witness-default-key-v1")`) is public and must be replaced.

---

## 6. Practical Examples

### Creating a Capability and Checking Rights

```rust
use rvm_types::{CapToken, CapType, CapRights};

let token = CapToken::new(
    42, CapType::Region,
    CapRights::READ | CapRights::WRITE | CapRights::PROVE,
    0,
);

// Check individual rights
assert!(token.has_rights(CapRights::READ));
assert!(token.has_rights(CapRights::PROVE));
assert!(!token.has_rights(CapRights::GRANT));

// Truncated hash for witness embedding (32-bit, NOT the full token)
let hash = token.truncated_hash();
```

### Submitting and Verifying a Hash Proof

```rust
use rvm_proof::{Proof, compute_data_hash, verify, verify_with_cap};
use rvm_types::{CapToken, CapType, CapRights};

let data = b"region-transfer-payload";
let commitment = compute_data_hash(data);
let proof = Proof::hash_proof(commitment, data);

// Standalone verification (no capability check)
verify(&proof, &commitment).expect("proof is valid");

// Capability-gated verification
let token = CapToken::new(1, CapType::Proof, CapRights::PROVE, 0);
verify_with_cap(&proof, &commitment, &token).expect("cap + proof valid");
```

### End-to-End: Capability + Proof Engine + Witness

```rust
use rvm_cap::CapabilityManager;
use rvm_proof::engine::ProofEngine;
use rvm_proof::context::ProofContextBuilder;
use rvm_types::{CapType, CapRights, PartitionId, ProofTier, ProofToken};
use rvm_witness::WitnessLog;

// Set up infrastructure
let witness_log = WitnessLog::<256>::new();
let mut cap_mgr = CapabilityManager::<64>::with_defaults();
let owner = PartitionId::new(1);

// Create a capability with PROVE rights
let (idx, gen) = cap_mgr.create_root_capability(
    CapType::Region,
    CapRights::READ | CapRights::WRITE | CapRights::PROVE,
    0, owner,
).unwrap();

// Build a proof context
let context = ProofContextBuilder::new(owner)
    .target_object(42)
    .capability_handle(idx)
    .capability_generation(gen)
    .current_epoch(0)
    .region_bounds(0x1000, 0x2000)
    .time_window(500, 1000)
    .nonce(1)
    .build();

let token = ProofToken { tier: ProofTier::P2, epoch: 0, hash: 0xABCD };

// Run the full pipeline: P1 check -> P2 validate -> witness emit
let mut engine = ProofEngine::<64>::new();
engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log)
    .expect("pipeline passes");

// A witness record was emitted
assert!(witness_log.total_emitted() > 0);
```

---

## Cross-References

- **Security Gate** -- The unified gate that wraps capability check + proof + witness into a single pipeline: [Security Architecture](10-security.md)
- **Witness Record format** -- How proof results are recorded in the audit trail: [Witness and Audit](06-witness-audit.md)
- **Partition split and capability attenuation** -- How capabilities are attenuated during splits (DC-8): [Partitions and Scheduling](07-partitions-scheduling.md)
- **Memory region capabilities** -- How region capabilities interact with memory tiers: [Memory Model](08-memory-model.md)
- **WASM agent capabilities** -- How agents acquire and use capabilities: [WASM Agents](09-wasm-agents.md)
- **Crate API surface** -- `rvm-cap`, `rvm-proof`, `rvm-types`: [Crate Reference](04-crate-reference.md)
- **Glossary** -- Definitions of capability, proof tier, epoch, derivation depth: [Glossary](15-glossary.md)
