# ADR-135: Proof Verifier Design — Three-Layer Verification for Capability-Gated Mutation

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-134 (Witness Schema and Log Format), ADR-133 (Partition Object Model)

---

## Context

ADR-132 establishes that RVM is a proof-gated hypervisor: no privileged mutation proceeds without valid authority. The proof system is called out as design constraint DC-3 with an explicit warning that conflating its three layers is a design error. The security model document (`docs/research/ruvm/security-model.md`) specifies six verification steps, three proof tiers, constant-time verification, and nonce-based replay prevention.

### Problem Statement

1. **Conflation risk**: Early prototypes and reviews identified a recurring tendency to treat "the proof system" as one monolithic verifier. This collapses three fundamentally different concerns (token validity, structural invariant checking, cryptographic attestation) into a single code path with incompatible latency budgets.
2. **Latency budgets differ by four orders of magnitude**: P1 must complete in under 1 microsecond (bitmap comparison on the syscall hot path). P3 may take up to 10 milliseconds (hash chain validation, cross-partition attestation). Forcing both through the same code path either makes the fast path slow or the deep path shallow.
3. **v1 scope must be bounded**: The full deep proof layer (P3) requires cryptographic infrastructure (signing keys, attestation protocols, cross-node trust) that depends on hardware bring-up (Phase D in the security model roadmap). Shipping P1 + P2 first and deferring P3 is the correct phasing.
4. **seL4 capability model provides a proven foundation**: The derivation tree with monotonic attenuation, epoch-based revocation, and bounded delegation depth (max 8) is well-understood. RVM should adopt this model rather than invent a new one.
5. **Timing side channels in verification**: A naive verifier that short-circuits on the first failing check leaks information about which check failed. The security model mandates constant-time verification at P2 and above.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| seL4 | Formally verified capability derivation tree | Direct model for RVM capability derivation; mint, derive (attenuate), revoke |
| CHERI | Hardware-enforced capability pointers | Validates capability-as-unforgeable-token approach; RVM uses software capabilities |
| Capsicum (FreeBSD) | Capability mode for POSIX processes | Demonstrates capability discipline in practical systems |
| ARM CCA (Confidential Compute) | Realm attestation tokens | Informs P3 attestation design (deferred to post-v1) |
| Dennis & Van Horn (1966) | Original capability concept | Foundational reference for authority-is-the-token principle |
| RVM security model | 6-step verification, 3 tiers, constant-time | Direct specification for this implementation |

---

## Decision

Implement the proof verifier as **three distinct layers** with separate traits, separate latency budgets, and separate compilation units. v1 ships P1 + P2 only. P3 is explicitly deferred to post-v1.

### The Three Layers

| Layer | Name | Budget | What It Does | v1 Status |
|-------|------|--------|-------------|-----------|
| **P1** | Capability Check | < 1 us | Validates that an unforgeable token exists and carries the required right. Bitmap comparison. No allocation, no branching on secret data. | **Ship** |
| **P2** | Policy Validation | < 100 us | Validates structural invariants: ownership chain valid? Region bounds legal? Lease not expired? Delegation depth within limit (max 8)? Nonce not replayed? Time window not exceeded? | **Ship** |
| **P3** | Deep Proof | < 10 ms | Cryptographic verification: hash chain validation, cross-partition attestation, semantic proofs, coherence certificates. Only for high-stakes mutations (migration, merge, device lease to untrusted partition). | **Deferred** |

### Design Principles

- **Proof tokens are unforgeable kernel objects**: User space holds an opaque `ProofHandle`. The kernel resolves it to the actual `ProofToken` through a per-task table, same pattern as capability handles.
- **Proof verification is synchronous and inline**: The verifier runs in the syscall path. It does not use async callbacks, deferred work queues, or interrupt-driven completion. The caller blocks until verification completes.
- **Failed proof = mutation rejected + witness emitted**: A `PROOF_REJECTED` witness record is emitted for every failed verification. This is non-negotiable for auditability.
- **Capability model follows seL4 derivation tree**: Three operations on capabilities: `mint` (create from kernel authority), `derive` (attenuate rights, child of parent), `revoke` (epoch-based propagation through derivation tree).
- **Monotonic attenuation**: Derived capabilities can ONLY lose rights, never gain. Enforced at the type level in `Capability::derive()`.
- **Constant-time at P2**: All P2 checks execute regardless of early failures. The result is a single boolean computed from the conjunction of all checks.

---

## Architecture

### Crate Structure

```
crates/ruvix/crates/proof/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Module root, feature-gated exports
│   ├── traits.rs           # ProofVerifier trait with verify_p1(), verify_p2(), verify_p3()
│   ├── p1_capability.rs    # P1: bitmap rights check, token existence
│   ├── p2_policy.rs        # P2: structural invariant validation (constant-time)
│   ├── p3_deep.rs          # P3: stub in v1, cryptographic verification post-v1
│   ├── capability.rs       # Capability struct, derive(), mint(), revoke()
│   ├── derivation_tree.rs  # seL4-style derivation tree with depth tracking
│   ├── nonce_tracker.rs    # Ring buffer of 64 nonces for replay prevention
│   ├── token.rs            # ProofToken, ProofHandle, ProofAttestation types
│   ├── rights.rs           # CapRights bitmap (7 rights)
│   ├── error.rs            # ProofError variants
│   └── witness.rs          # PROOF_REJECTED witness emission
└── tests/
    ├── p1_tests.rs         # P1 unit tests
    ├── p2_tests.rs         # P2 unit tests
    ├── derivation_tests.rs # Derivation tree tests
    └── integration.rs      # Cross-layer integration tests
```

### Trait Definition

```rust
/// The proof verifier trait. Each layer has its own method with its own
/// latency contract. Implementations MUST NOT call a higher layer from
/// a lower layer (P1 must not invoke P2 logic).
pub trait ProofVerifier {
    /// P1: Capability check (< 1 us).
    /// Does the token exist? Does it carry the required right?
    /// Pure bitmap comparison. No allocation, no I/O.
    fn verify_p1(
        &self,
        handle: CapHandle,
        required_rights: CapRights,
    ) -> Result<&Capability, ProofError>;

    /// P2: Policy validation (< 100 us, constant-time).
    /// Ownership chain valid? Region bounds legal? Lease not expired?
    /// Delegation depth within limit? Nonce not replayed? Time window valid?
    /// All checks execute regardless of intermediate failures.
    fn verify_p2(
        &mut self,
        proof: &ProofToken,
        capability: &Capability,
        expected_mutation_hash: &[u8; 32],
        current_time_ns: u64,
    ) -> Result<ProofAttestation, ProofError>;

    /// P3: Deep proof (< 10 ms, OPTIONAL).
    /// Cryptographic verification, hash chain validation, cross-partition
    /// attestation. Returns ProofError::P3NotImplemented in v1.
    fn verify_p3(
        &mut self,
        proof: &ProofToken,
        attestation: &ProofAttestation,
        context: &DeepProofContext,
    ) -> Result<DeepProofResult, ProofError>;
}
```

### Capability Rights (7 Rights)

| Right | Bit | Authorizes |
|-------|-----|------------|
| `READ` | 0 | `vector_get`, `queue_recv`, region read |
| `WRITE` | 1 | `queue_send`, region append/slab write |
| `GRANT` | 2 | `cap_grant` to another task (transitive delegation) |
| `REVOKE` | 3 | Revoke capabilities derived from this one |
| `EXECUTE` | 4 | Task entry point, RVF component execution |
| `PROVE` | 5 | Generate proof tokens (`vector_put_proved`, `graph_apply_proved`) |
| `GRANT_ONCE` | 6 | Non-transitive grant (derived capability cannot re-grant) |

Implementation as a `u8` bitmap:

```rust
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CapRights(u8);

impl CapRights {
    pub const READ:       Self = Self(1 << 0);
    pub const WRITE:      Self = Self(1 << 1);
    pub const GRANT:      Self = Self(1 << 2);
    pub const REVOKE:     Self = Self(1 << 3);
    pub const EXECUTE:    Self = Self(1 << 4);
    pub const PROVE:      Self = Self(1 << 5);
    pub const GRANT_ONCE: Self = Self(1 << 6);

    /// Check if all bits in `required` are set in self.
    #[inline(always)]
    pub fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Returns true if self is a subset of (or equal to) other.
    #[inline(always)]
    pub fn is_subset_of(self, other: Self) -> bool {
        (self.0 & !other.0) == 0
    }

    /// Remove specified rights.
    #[inline(always)]
    pub fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}
```

### P1 Implementation Detail

P1 is the hot path. It runs on every syscall that requires authorization. The implementation is a single table lookup plus a bitmap AND:

```rust
/// P1: Capability existence + rights check.
/// Budget: < 1 us. No allocation. No branching on secret data.
pub fn verify_p1(
    &self,
    handle: CapHandle,
    required_rights: CapRights,
) -> Result<&Capability, ProofError> {
    // Bounds-checked table lookup (Spectre-safe with CSDB barrier)
    let cap = self.cap_table.lookup(handle)
        .ok_or(ProofError::InvalidHandle)?;

    // Epoch check: detect stale handles after revocation
    if cap.epoch != self.current_epoch(cap.object_id) {
        return Err(ProofError::StaleCapability);
    }

    // Bitmap comparison: does the capability carry the required rights?
    if !cap.rights.contains(required_rights) {
        return Err(ProofError::InsufficientRights);
    }

    Ok(cap)
}
```

### P2 Implementation Detail (Constant-Time)

P2 validates structural invariants. All checks execute unconditionally to prevent timing side channels:

```rust
/// P2: Structural invariant validation.
/// Budget: < 100 us. Constant-time: all checks execute regardless of failures.
pub fn verify_p2(
    &mut self,
    proof: &ProofToken,
    capability: &Capability,
    expected_mutation_hash: &[u8; 32],
    current_time_ns: u64,
) -> Result<ProofAttestation, ProofError> {
    let mut valid = true;

    // 1. PROVE right on the capability
    valid &= capability.rights.contains(CapRights::PROVE);

    // 2. Mutation hash match (proof authorizes exactly this mutation)
    valid &= constant_time_eq(&proof.mutation_hash, expected_mutation_hash);

    // 3. Tier satisfaction (proof tier >= policy required tier)
    valid &= proof.tier >= self.policy.required_tier;

    // 4. Not expired
    valid &= current_time_ns <= proof.valid_until_ns;

    // 5. Validity window not exceeded (prevents pre-computed proofs)
    valid &= proof.valid_until_ns.saturating_sub(current_time_ns)
        <= self.policy.max_validity_window_ns;

    // 6. Nonce uniqueness (single-use, ring buffer of 64)
    let nonce_ok = self.nonce_tracker.check_and_mark(proof.nonce);
    valid &= nonce_ok;

    // 7. Delegation depth within limit (max 8)
    valid &= self.derivation_tree.depth(capability) <= MAX_DELEGATION_DEPTH;

    // 8. Ownership chain: capability's object_id matches proof's target
    valid &= capability.object_id == proof.target_object_id;

    if valid {
        Ok(self.create_attestation(proof, current_time_ns))
    } else {
        // Roll back nonce if overall verification failed
        if nonce_ok {
            self.nonce_tracker.unmark(proof.nonce);
        }
        // Emit PROOF_REJECTED witness
        self.emit_witness(WitnessRecordKind::ProofRejected, proof);
        Err(ProofError::PolicyViolation)
    }
}
```

### P3 Stub (v1)

```rust
/// P3: Deep proof verification.
/// v1: Returns P3NotImplemented. Post-v1: cryptographic verification.
pub fn verify_p3(
    &mut self,
    _proof: &ProofToken,
    _attestation: &ProofAttestation,
    _context: &DeepProofContext,
) -> Result<DeepProofResult, ProofError> {
    Err(ProofError::P3NotImplemented)
}
```

Post-v1, P3 will handle:
- Hash chain validation (Merkle witness: root + path)
- Cross-partition attestation (mutual node authentication)
- Coherence certificates (scores + partition ID + signature)
- Semantic proofs (application-defined invariants)

### Capability Derivation Tree

The derivation tree follows seL4's model with three operations:

| Operation | Description | Constraint |
|-----------|-------------|------------|
| **Mint** | Create a new root capability from kernel authority | Kernel-only; establishes a derivation tree root |
| **Derive** | Create a child capability with attenuated rights | Child rights must be a subset of parent rights; depth <= 8 |
| **Revoke** | Invalidate a capability and all its descendants | Epoch-based propagation; O(d) where d = tree descendants |

```rust
/// Derive a child capability with equal or fewer rights.
/// Returns None if rights escalation is attempted, GRANT right
/// is absent, or delegation depth limit (8) would be exceeded.
pub fn derive(
    &self,
    parent: &Capability,
    new_rights: CapRights,
    new_badge: u64,
    tree: &DerivationTree,
) -> Option<Capability> {
    // Must hold GRANT right to delegate
    if !parent.rights.contains(CapRights::GRANT) {
        return None;
    }

    // Monotonic attenuation: new rights must be a subset
    if !new_rights.is_subset_of(parent.rights) {
        return None;
    }

    // Delegation depth check
    if tree.depth(parent) >= MAX_DELEGATION_DEPTH {
        return None;
    }

    // GRANT_ONCE strips GRANT from the derived capability
    let final_rights = if parent.rights.contains(CapRights::GRANT_ONCE) {
        new_rights
            .difference(CapRights::GRANT)
            .difference(CapRights::GRANT_ONCE)
    } else {
        new_rights
    };

    Some(Capability {
        object_id: parent.object_id,
        object_type: parent.object_type,
        rights: final_rights,
        badge: new_badge,
        epoch: parent.epoch,
    })
}
```

### Nonce Tracker

Ring buffer of 64 entries prevents proof replay:

```rust
pub struct NonceTracker {
    ring: [u64; 64],
    write_pos: usize,
}

impl NonceTracker {
    /// Check if nonce has been used recently; if not, mark it as used.
    /// Returns false if the nonce is a replay.
    pub fn check_and_mark(&mut self, nonce: u64) -> bool {
        for entry in &self.ring {
            if *entry == nonce {
                return false; // Replay detected
            }
        }
        self.ring[self.write_pos] = nonce;
        self.write_pos = (self.write_pos + 1) % 64;
        true
    }

    /// Roll back a nonce mark (used when overall verification fails).
    pub fn unmark(&mut self, nonce: u64) {
        let prev = if self.write_pos == 0 { 63 } else { self.write_pos - 1 };
        if self.ring[prev] == nonce {
            self.ring[prev] = 0;
            self.write_pos = prev;
        }
    }
}
```

### Syscall Integration

The verifier integrates into the syscall path as follows:

```
EL0: task issues SVC with syscall number + arguments
        |
EL1: exception handler
        |
        +-- P1: verify_p1(cap_handle, required_rights)
        |       < 1 us, always runs for mutation syscalls
        |       FAIL -> ProofError -> PROOF_REJECTED witness -> return error to EL0
        |
        +-- P2: verify_p2(proof_token, capability, mutation_hash, time)
        |       < 100 us, constant-time, runs for proof-gated mutations
        |       FAIL -> ProofError -> PROOF_REJECTED witness -> return error to EL0
        |
        +-- [v1: skip P3]
        |
        +-- Execute mutation
        |
        +-- Emit success witness
        |
        +-- ERET to EL0
```

### Error Types

```rust
pub enum ProofError {
    /// P1: Handle does not resolve to a valid capability
    InvalidHandle,
    /// P1: Capability epoch does not match (revoked)
    StaleCapability,
    /// P1: Capability does not carry the required rights
    InsufficientRights,
    /// P2: One or more structural invariant checks failed (constant-time,
    /// does not specify which check failed to prevent side-channel leakage)
    PolicyViolation,
    /// P3: Deep proof verification not implemented in v1
    P3NotImplemented,
    /// P3: Cryptographic verification failed (post-v1)
    CryptographicFailure,
}
```

Note that `PolicyViolation` deliberately does not indicate which of the P2 checks failed. This is intentional: reporting the specific failure would enable an attacker to enumerate valid proofs by observing which check they pass.

---

## Consequences

### Positive

- **Clean separation prevents the "proof system is one monolith" failure mode**: Three layers with distinct latency budgets, distinct trait methods, and distinct compilation units. A contributor working on P3 cannot accidentally slow down P1.
- **v1 ships faster with bounded scope**: P1 + P2 provide complete capability-based authorization and structural invariant enforcement. P3's cryptographic machinery can be developed and tested independently without blocking v1.
- **seL4-proven capability model**: Monotonic attenuation, derivation trees, and epoch-based revocation are well-understood from 15+ years of seL4 deployment. RVM benefits from this proven design without adopting seL4's full verification overhead.
- **Constant-time P2 eliminates timing side channels**: An attacker observing verification latency cannot determine which check failed or how close a forged proof came to passing.
- **Audit completeness via PROOF_REJECTED witnesses**: Every failed verification attempt is logged, enabling forensic analysis of attack patterns and misconfigurations.
- **Replay prevention with bounded memory**: The 64-entry nonce ring buffer prevents replay attacks without unbounded memory growth.

### Negative

- **Larger API surface**: Three distinct trait methods (plus supporting types for each layer) create more API surface than a single `verify()` method. Contributors must understand which layer to invoke and when.
- **P3 deferral means no cryptographic attestation in v1**: High-stakes mutations (migration, merge, device lease to untrusted partition) rely on P1 + P2 only. This is acceptable for single-node v1 operation but must be addressed before multi-node mesh deployment.
- **Constant-time P2 is slower than short-circuit**: Executing all checks unconditionally adds a small overhead compared to early-return verification. The overhead is bounded (< 100 us budget) and the security benefit (side-channel resistance) justifies it.
- **Delegation depth limit (8) may be restrictive**: Some agent runtime patterns may want deeper delegation chains. The limit is configurable per-manifest but the default is intentionally conservative.

### Risks

| Risk | Mitigation |
|------|------------|
| P1 exceeds 1 us budget on constrained hardware | Benchmark on Seed target early; P1 is a table lookup + bitmap AND, should be well within budget |
| Nonce ring buffer wraparound allows replay of old proofs | 64 entries with single-use semantics; proofs also expire (time bound), so wrapped-around nonces reference expired proofs |
| P3 deferral blocks multi-node deployment | Multi-node mesh is Phase D; P3 implementation tracks with that phase |
| Constant-time implementation is subtly broken by compiler optimization | Use `core::hint::black_box` on intermediate results; audit generated assembly for the P2 path |

---

## Testing Strategy

| Category | Tests | Coverage |
|----------|-------|----------|
| P1 unit | Valid handle + sufficient rights succeeds; invalid handle fails; stale epoch fails; insufficient rights fails | All P1 error paths |
| P2 unit | All 8 checks pass -> success; each check individually failing -> PolicyViolation; nonce replay detected; nonce rollback on failure | All P2 invariants |
| Derivation tree | Mint creates root; derive attenuates; derive with GRANT_ONCE strips GRANT; depth > 8 rejected; revoke propagates to descendants | Full derivation lifecycle |
| Constant-time | Measure verification latency for passing vs failing proofs; variance must be < 1 us | Timing side-channel resistance |
| Integration | Full syscall path: P1 -> P2 -> mutation -> witness; failed P2 -> PROOF_REJECTED witness emitted | End-to-end verification |
| Fuzz | Random ProofToken fields against random Capability fields; verifier must never panic | Robustness |

---

## References

- Klein, G., et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009.
- Dennis, J.B. & Van Horn, E.C. "Programming Semantics for Multiprogrammed Computations." CACM 1966.
- Woodruff, J., et al. "The CHERI Capability Model." IEEE S&P 2014.
- Watson, R.N.M., et al. "Capsicum: Practical Capabilities for UNIX." USENIX Security 2010.
- ARM Confidential Compute Architecture (CCA) Specification.
- RVM security model: `docs/research/ruvm/security-model.md`
- ADR-132: RVM Hypervisor Core

---

## Addendum (2026-04-04)

P3 (Deep Proof) verification has been implemented per ADR-142. The stub that returned `P3NotImplemented` has been replaced with:
- Hash tier: SHA-256 preimage verification
- Witness tier: Chain linkage + Merkle path verification
- ZK tier: Returns `Unsupported` pending TEE attestation quote support
- SecurityGate now calls `verify_p3()` directly (caller-supplied boolean no longer trusted)
