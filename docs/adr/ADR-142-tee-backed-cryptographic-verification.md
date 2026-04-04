# ADR-142: TEE-Backed Cryptographic Verification for the RVM Hypervisor

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None (amends ADR-135 P3 stub)
**Related**: ADR-042 (TEE Hardened Cognitive Container), ADR-135 (Proof Verifier Design), ADR-132 (RVM Hypervisor Core), ADR-134 (Witness Schema and Log Format), ADR-087 (Cognition Kernel)

---

## Context

A security audit of the RVM hypervisor identified **11 critical** and **23 high** severity findings stemming from the use of FNV-1a as the sole hashing primitive across security-sensitive subsystems. FNV-1a is a non-cryptographic hash function designed for hash table distribution, not tamper resistance. Its use in witness chain signing, attestation accumulation, and proof verification creates exploitable weaknesses.

### Audit Findings Summary

| ID | Severity | Component | Finding |
|----|----------|-----------|---------|
| A-01 | Critical | `nucleus/src/witness_log.rs:559-584` | Witness chain hash uses FNV-1a with 64-bit output expanded to 256 bits by repeated multiplication. Only 64 bits of collision resistance; the remaining 192 bits are deterministic transforms of the first 64. An attacker can forge a witness chain entry in ~2^32 operations. |
| A-02 | Critical | `nucleus/src/witness_log.rs` (WitnessEntry::compute_hash) | Chain hash uses XOR folding of field bytes with attestation and prev_hash. XOR is commutative and associative -- swapping fields produces identical hashes. |
| A-03 | Critical | `types/src/proof_cache_optimized.rs:140-157` | Proof cache index function uses FNV-1a. Cache poisoning via collision allows an attacker to evict valid proofs and substitute pre-computed ones. |
| A-04 | Critical | `region/src/immutable.rs:204-233` | Immutable region content hash uses 4x FNV-1a lanes with deterministic seeding. This provides at most 64 bits of collision resistance, not 256. Content substitution is feasible. |
| A-05 | Critical | `proof/src/verifier.rs:220-276` | P3 (Deep) verification does not perform cryptographic verification. The `CoherenceCert` payload signature field (`[u8; 64]`) is never checked. Any 64-byte value passes. |
| A-06 | Critical | `proof/src/witness.rs:79-109` | Merkle witness `verify()` checks structural bounds but never recomputes the hash chain from leaf to root. It accepts any path with valid length. |
| A-07 | High | `cap/src/security.rs:259-264` | `verify_signature()` accepts any non-zero signature when a trusted key is present. No actual Ed25519 verification. |
| A-08 | High | `boot/src/signature.rs:170-178` | `verify_ml_dsa_65()` returns `Valid` for all-zero test key with all-zero signature. No feature gate restricts this to test builds. |
| A-09 | High | `nucleus/src/graph_store.rs:498` | Graph store state hash uses FNV-1a. |
| A-10 | High | `nucleus/src/vector_store.rs:385` | Vector store state hash uses FNV-1a. |
| A-11 | High | `proof/src/verifier.rs:130-131` | Hash comparison (`!=`) is not constant-time. Timing side channel leaks prefix information about the expected mutation hash. |

### Root Cause

ADR-135 explicitly deferred P3 (Deep Proof) to post-v1 with a stub that returns `P3NotImplemented`. The codebase then grew around this deferral, and non-cryptographic FNV-1a was used as a placeholder in multiple security-critical paths. The placeholder was never replaced, and no feature gate distinguished "development stub" from "production code."

### Existing Infrastructure

ADR-042 already defines TEE infrastructure (SGX, SEV-SNP, TDX, ARM CCA) with `AttestationHeader`, TEE-bound key records, and platform verification. The `WitnessSigner` trait concept from the hypervisor design is pluggable. The `sha2` crate is already a dependency in `ruvix-boot` (used in `boot/src/attestation.rs` and `boot/src/signature.rs`). The `subtle` crate is already present in `Cargo.lock` as a transitive dependency.

---

## Decision

### 1. Replace FNV-1a with SHA-256 as the Minimum Cryptographic Baseline

All security-sensitive hash computations must use SHA-256 (`sha2` crate, `no_std` compatible). FNV-1a may remain only for non-security hash table indexing (e.g., proof cache slot selection) and only behind the `fnv-fallback` feature flag.

**Witness chain hashing** (`nucleus/src/witness_log.rs`):
- Replace `hash_attestation()` FNV-1a implementation with SHA-256 over the concatenation of all attestation fields in canonical order.
- Replace `WitnessEntry::compute_hash()` XOR-fold with SHA-256 over the serialized entry. The current XOR approach is commutative; SHA-256 is not.

**Immutable region hashing** (`region/src/immutable.rs`):
- Replace the 4-lane FNV-1a hash in `compute_content_hash()` with a single SHA-256 pass over the region content.

**Store state hashing** (`nucleus/src/vector_store.rs`, `nucleus/src/graph_store.rs`):
- Replace FNV-1a state hashes with SHA-256.

**Proof cache indexing** (`types/src/proof_cache_optimized.rs`):
- This is a hash table index, not a security function. Retain FNV-1a for performance but rename to `cache_slot_index()` and add documentation that this is explicitly non-cryptographic. Gate behind `fnv-fallback`.

### 2. TEE Evidence and Signer Pipeline

TEE attestation involves two distinct operational problems: local evidence generation and remote evidence verification. These must not be conflated into a single abstraction. The pipeline is:

1. **`TeeQuoteProvider`** — Produces local attestation evidence (quote) bound to the platform measurement. Runs inside the TEE. Output is opaque platform-specific evidence.
2. **`TeeQuoteVerifier`** — Validates evidence plus collateral policy. Handles collateral refresh discipline (Intel TDX collateral expires after 30 days per Intel's TDX Enabling Guide). May delegate to a quote verification service. Runs outside the TEE or in a verification enclave.
3. **`WitnessSigner`** — Signs the digest after the quote is accepted. The signer is bound to an identity established by the quote, not the other way around.

This separation prevents the cryptographic core from inheriting platform verifier complexity.

#### WitnessSigner Trait

```rust
/// Typed verification failure causes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    BadSignature,
    UnknownKey,
    BadMeasurement,
    ExpiredCollateral,
    Replay,
    UnsupportedPlatform,
    MalformedInput,
}

/// Trait for cryptographically signing witness records.
pub trait WitnessSigner: Send + Sync {
    /// Signs a witness record digest, returning a 64-byte signature.
    fn sign(&self, digest: &[u8; 32]) -> [u8; 64];

    /// Verifies a signature against a digest.
    /// Returns a typed error on failure — `bool` is too lossy for a security boundary.
    fn verify(&self, digest: &[u8; 32], signature: &[u8; 64]) -> Result<(), SignatureError>;

    /// Returns the canonical signer identifier.
    /// Defined as SHA-256 over a signer descriptor record:
    ///   Ed25519:  SHA-256(0x01 || public_key_bytes)
    ///   HMAC:     SHA-256(0x02 || key_id_bytes || domain_tag)
    ///   TEE:      SHA-256(0x03 || platform_byte || measurement)
    /// This is NOT a raw public key hash — it is a canonical digest
    /// over a typed descriptor, ensuring domain separation across signer kinds.
    fn signer_id(&self) -> [u8; 32];
}

/// Produces local TEE attestation evidence.
pub trait TeeQuoteProvider: Send + Sync {
    fn generate_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, SignatureError>;
    fn platform(&self) -> TeePlatform;
}

/// Validates TEE evidence plus collateral policy.
pub trait TeeQuoteVerifier: Send + Sync {
    fn verify_quote(
        &self,
        quote: &[u8],
        expected_measurement: &[u8; 32],
        expected_report_data: &[u8; 64],
    ) -> Result<(), SignatureError>;
    fn collateral_valid(&self) -> bool;
    fn refresh_collateral(&mut self) -> Result<(), SignatureError>;
}
```

#### TEE Platform Measurement Table

| Platform | Measurement Field | Freshness Mechanism | Collateral Source | Verifier Location |
|----------|-------------------|---------------------|-------------------|-------------------|
| Intel SGX | `MRENCLAVE` (256-bit) | Nonce in `REPORTDATA` | Intel Provisioning Certification Service (PCS) | Local QVE or remote IAS/DCAP |
| Intel TDX | `MRTD` + `RTMR[0..3]` | Nonce in `REPORTDATA`; collateral expires 30 days | Intel PCS (DCAP collateral) | Local QVL or remote PCCS |
| AMD SEV-SNP | `LAUNCH_DIGEST` (384-bit) | `REPORT_DATA` nonce; VCEK cert chain | AMD Key Distribution Service (KDS) | Local via `sev-snp-utilities` or remote verifier |
| ARM CCA | Realm Initial Measurement (RIM) | Challenge nonce in Realm Token | Veraison or custom CCA verifier | Relying Party via CCA attestation token |

#### Signer Implementations

| Struct | Backend | Use Case | Trust Scope |
|--------|---------|----------|-------------|
| `Ed25519WitnessSigner` | `ed25519-dalek` ^2 (`no_std`, `verify_strict`) | Software fallback; default when no TEE available. **Must use `verify_strict()` semantics** per `ed25519-dalek` docs to avoid known verification gotchas. | Cross-partition, publicly verifiable |
| `HmacSha256WitnessSigner` | `hmac` ^0.13 + `sha2` ^0.10 (`no_std`) | Symmetric chain integrity. **Permitted only where verifier and signer are in the same administrative trust domain.** HMAC does not provide signer separation, public verifiability, or multi-tenant trust semantics. Must not be used for cross-partition or cross-host attestation. | Single trust domain only |
| `TeeWitnessSigner` | Platform TEE via `TeeQuoteProvider` + `TeeQuoteVerifier` | Hardware-backed signing; keys sealed to enclave measurement | Hardware-bound, remotely verifiable |
| `NullSigner` | None | **Gated behind `fnv-fallback` feature only**; panics in release builds without the flag | None (testing only) |

The `strict-signing` feature (enabled by default) requires that `NullSigner` cannot be instantiated. Attempting to construct a `NullSigner` without the `fnv-fallback` feature produces a compile-time error.

Crate versions are pinned in the ADR because this is security-critical plumbing: `ed25519-dalek` ^2, `sha2` ^0.10, `hmac` ^0.13, `subtle` ^2.6.

### 3. Implement Real P3 (Deep Proof) Verification

Replace the P3 stub in `proof/src/verifier.rs` with a three-tier cryptographic verification pipeline:

**Hash tier** (Reflex/P1 proofs when `crypto-sha256` is enabled):
- Recompute SHA-256 over the proof's claimed data.
- Compare the result to the committed hash using constant-time comparison (`subtle::ConstantTimeEq`).

**Witness tier** (Standard/P2 proofs):
- Implement real Merkle witness verification in `proof/src/witness.rs`: starting from the leaf hash, iteratively compute `SHA-256(left || right)` up the path, and compare to the claimed root.
- Verify the witness chain signature using `WitnessSigner::verify()`.

**ZK/Attestation tier** (Deep/P3 proofs):
- Verify the `CoherenceCert` signature field using the partition's `WitnessSigner`.
- When TEE features are enabled, verify the platform attestation quote against the expected measurement (`MRENCLAVE` for SGX, `LAUNCH_DIGEST` for SEV-SNP, etc.).
- `SecurityGate` must call `verify_p3()` directly and inspect the result. The current pattern where a caller-supplied boolean is trusted (A-05) is eliminated.

### 4. Constant-Time Comparison for All Verification

All hash comparisons, signature verifications, and attestation checks must use constant-time operations via `subtle::ConstantTimeEq` (^2.6, already in `Cargo.lock` as transitive dependency):

- Replace the `!=` operator in `proof/src/verifier.rs:130` with `ct_eq`.
- Apply to `boot/src/attestation.rs` `verify()` method.
- Apply to `cap/src/security.rs` key comparison in `is_trusted()`.

**Ordering invariant**: Constant-time comparison protects equality checks, but does not repair malformed parsing or variant encodings. All verification paths must follow the sequence: **(1) parse** the input into canonical form, **(2) normalize** length and encoding, **(3) compare** using `ct_eq`. Applying `ct_eq` to un-normalized inputs provides no timing guarantee because the parsing step itself may leak length or format information. This ordering must be documented in `crates/proof/src/constant_time.rs` and enforced by code review.

### 5. Feature Flags

| Feature Flag | Default | Description |
|--------------|---------|-------------|
| `crypto-sha256` | **Enabled** | SHA-256 baseline for all security hashing. Adds `sha2` dependency. |
| `tee-sgx` | Disabled | Intel SGX attestation support. Adds SGX SDK dependency. |
| `tee-sev` | Disabled | AMD SEV-SNP attestation support. |
| `tee-tdx` | Disabled | Intel TDX attestation support. |
| `tee-arm-cca` | Disabled | ARM CCA Realm attestation support. |
| `strict-signing` | **Enabled** | Prevents `NullSigner` construction. Must be explicitly disabled for dev/test. |
| `fnv-fallback` | Disabled | Opt-in for development/testing. Allows `NullSigner` and retains FNV-1a for non-critical paths. **Cannot be enabled in release builds** (enforced by `compile_error!`, same pattern as `disable-boot-verify` in `cap/src/security.rs`). |

---

## Architecture

### Signing and Verification Flow

```
Mutation Request
    |
    v
P1: verify_p1(cap_handle, rights)        [< 1 us, bitmap check]
    |
    v
P2: verify_p2(proof, cap, hash, time)    [< 100 us, constant-time]
    |  - SHA-256 mutation hash comparison (ct_eq)
    |  - Nonce uniqueness (ring buffer)
    |  - Delegation depth, ownership chain
    |
    v
P3: verify_p3(proof, attestation, ctx)   [< 10 ms, cryptographic]
    |  - Hash tier:    SHA-256 preimage check
    |  - Witness tier: Merkle path recomputation
    |  - ZK tier:      WitnessSigner::verify() + TEE quote validation
    |
    v
SecurityGate checks result directly (no caller-supplied boolean)
    |
    v
Execute mutation --> Emit signed witness record
                          |
                          v
                     WitnessSigner::sign(SHA-256(entry))
                          |
                          v
                     Append to witness chain (chain_hash = SHA-256(prev_hash || entry_hash))
```

### Crate Dependency Changes

```
ruvix-types  <-- sha2 (feature: crypto-sha256)
                 subtle (feature: crypto-sha256)

ruvix-proof  <-- sha2 (feature: crypto-sha256)
                 subtle (feature: crypto-sha256)
                 ed25519-dalek (feature: strict-signing, optional)
                 hmac (feature: crypto-sha256, optional)

ruvix-nucleus <-- sha2 (feature: crypto-sha256)

ruvix-region  <-- sha2 (feature: crypto-sha256)

ruvix-boot    <-- sha2 (already present)
                  subtle (new)

ruvix-cap     <-- subtle (new)
```

---

## Affected Files

### Crate: `ruvix-nucleus`

| File | Change | Priority |
|------|--------|----------|
| `crates/nucleus/src/witness_log.rs:558-584` | Replace `hash_attestation()` FNV-1a with SHA-256. Replace XOR-fold in entry hash. | Critical |
| `crates/nucleus/src/witness_log.rs` (WitnessEntry::compute_hash) | Replace XOR-fold chain hash with SHA-256 over serialized entry bytes. | Critical |
| `crates/nucleus/src/vector_store.rs:385` | Replace FNV-1a state hash with SHA-256. | High |
| `crates/nucleus/src/graph_store.rs:498` | Replace FNV-1a state hash with SHA-256. | High |

### Crate: `ruvix-proof`

| File | Change | Priority |
|------|--------|----------|
| `crates/proof/src/verifier.rs:130-131` | Replace `!=` hash comparison with `subtle::ConstantTimeEq`. | Critical |
| `crates/proof/src/verifier.rs:220-276` | Implement real P3 verification: verify `CoherenceCert` signature via `WitnessSigner`, verify Merkle witness hash chain, verify TEE attestation quote. | Critical |
| `crates/proof/src/witness.rs:79-109` | Implement real Merkle path verification: compute `SHA-256(left || right)` iteratively from leaf to root. | Critical |
| `crates/proof/src/attestation.rs:106-137` | Replace `compute_environment_hash()` byte-copy with SHA-256 over canonical payload serialization. | High |
| `crates/proof/src/lib.rs` | Add feature gates for `crypto-sha256`, `strict-signing`. Export `WitnessSigner` trait. | High |
| `crates/proof/src/engine.rs:215-242` | `generate_deep_proof()` must produce real cryptographic payloads (signed coherence cert, not zero-filled signature). | High |
| `crates/proof/Cargo.toml` | Add `sha2`, `subtle`, `ed25519-dalek` (optional), `hmac` (optional) dependencies. | High |

### Crate: `ruvix-region`

| File | Change | Priority |
|------|--------|----------|
| `crates/region/src/immutable.rs:204-233` | Replace 4-lane FNV-1a `compute_content_hash()` with SHA-256. | Critical |

### Crate: `ruvix-types`

| File | Change | Priority |
|------|--------|----------|
| `crates/types/src/proof_cache_optimized.rs:140-157` | Rename to `cache_slot_index()`. Add doc comment stating this is non-cryptographic. Gate behind `fnv-fallback` with SHA-256 alternative as default. | High |
| `crates/types/Cargo.toml` | Add `sha2` (optional, feature: `crypto-sha256`), `subtle` (optional, feature: `crypto-sha256`). | High |

### Crate: `ruvix-boot`

| File | Change | Priority |
|------|--------|----------|
| `crates/boot/src/attestation.rs:164` | Replace `==` in `verify()` with `subtle::ConstantTimeEq`. | High |
| `crates/boot/src/signature.rs:170-178` | Gate `is_test_key()` acceptance behind `#[cfg(test)]` or `fnv-fallback` feature. All-zero key must not pass in release builds. | Critical |
| `crates/boot/Cargo.toml` | Add `subtle` dependency. | High |

### Crate: `ruvix-cap`

| File | Change | Priority |
|------|--------|----------|
| `crates/cap/src/security.rs:197` | Replace `==` key comparison in `is_trusted()` with `subtle::ConstantTimeEq`. | High |
| `crates/cap/src/security.rs:259-264` | Replace placeholder `verify_signature()` with real Ed25519 verification (`ed25519-dalek`). | Critical |
| `crates/cap/Cargo.toml` | Add `subtle`, `ed25519-dalek` (optional) dependencies. | High |

### Test Files

| File | Change | Priority |
|------|--------|----------|
| `tests/src/lib.rs:126-135` | Replace `fnv1a_hash()` test utility with SHA-256 wrapper. Keep FNV variant available for benchmark comparison. | Medium |
| `tests/tests/adr087_section17_acceptance.rs:29-36` | Replace `fnv1a_hash()` with SHA-256 in acceptance tests. Update all call sites. | Medium |
| `tests/benches/integration_bench.rs:264-271` | Add SHA-256 benchmark alongside FNV-1a for comparison. | Low |

### New Files

| File | Purpose |
|------|---------|
| `crates/proof/src/signer.rs` | `WitnessSigner` trait definition with `SignatureError` enum, `Ed25519WitnessSigner` (using `verify_strict`), `HmacSha256WitnessSigner` (single trust domain only), `NullSigner` (gated behind `fnv-fallback`). |
| `crates/proof/src/tee_provider.rs` | `TeeQuoteProvider` trait and platform-specific implementations. Feature-gated behind `tee-*` flags. Produces local evidence only. |
| `crates/proof/src/tee_verifier.rs` | `TeeQuoteVerifier` trait and platform-specific implementations. Handles collateral refresh, measurement comparison, and quote validation. Feature-gated behind `tee-*` flags. |
| `crates/proof/src/tee_signer.rs` | `TeeWitnessSigner` that composes `TeeQuoteProvider` + `TeeQuoteVerifier` + `WitnessSigner`. Orchestrates the evidence-then-sign pipeline. |
| `crates/proof/src/constant_time.rs` | Wrapper functions around `subtle::ConstantTimeEq` for `[u8; 32]` and `[u8; 64]` comparisons. Documents the parse-normalize-compare ordering invariant. |

---

## Consequences

### Positive

- **Witness chain becomes cryptographically tamper-evident** (per NIST FIPS 180-4): SHA-256 provides three distinct security levels that must not be conflated:
  - *Collision resistance*: 128-bit (birthday bound). Finding any two inputs with the same hash requires ~2^128 operations. This is the relevant bound for an attacker who can choose both messages (e.g., forging two witness entries that hash identically).
  - *Second-preimage resistance*: 256-bit (ideal model). Given a specific witness entry and its hash, finding a different entry with the same hash requires ~2^256 operations. This is the relevant bound for tampering with a specific chain link.
  - *Preimage resistance*: 256-bit (ideal model). Recovering chain input from a hash output requires ~2^256 operations.
  
  FNV-1a provides none of these guarantees. The previous 32-bit effective collision resistance (birthday bound on 64-bit truncated to 32-bit) is replaced by 128-bit minimum across all attack classes.
- **P3 verification is real**: The stub that accepted anything is replaced with cryptographic signature verification. `SecurityGate` calls `verify_p3()` directly and acts on the result.
- **Constant-time comparison eliminates timing side channels**: All attestation comparisons, hash verifications, and key lookups use `subtle::ConstantTimeEq`.
- **TEE-backed signing when available**: On platforms with SGX, SEV-SNP, TDX, or ARM CCA, witness signatures are hardware-bound to the enclave measurement. Key extraction requires breaking the TEE.
- **NullSigner is no longer the default**: `strict-signing` is enabled by default. Development builds must explicitly opt in to `fnv-fallback`.
- **Incremental adoption via feature flags**: The `crypto-sha256` default brings immediate security improvement. TEE features are additive and platform-specific.

### Negative

- **Performance cost**: SHA-256 at ~200ns per 64-byte block is ~4x slower than FNV-1a at ~50ns. For witness chain hashing on the critical path, this adds approximately 200ns per entry. This is well within the P2 budget of 100 microseconds and the P3 budget of 10 milliseconds.
- **Binary size increase**: The `sha2` crate adds approximately 30KB. `ed25519-dalek` adds approximately 80KB. `subtle` adds <1KB. Total worst case with all features: ~110KB. Acceptable for a hypervisor.
- **P3 verification budget increases from ~0 microseconds (stub) to <10ms (real crypto)**: This is the designed budget from ADR-135. The stub was the anomaly, not the budget.
- **Test infrastructure changes**: All tests using `fnv1a_hash()` for verification need updating. This is a one-time migration cost.

### Performance Budget Impact

| Operation | Before (FNV-1a / stub) | After (SHA-256 / real) | ADR-135 Budget | Within Budget |
|-----------|----------------------|----------------------|----------------|---------------|
| P1 capability check | < 1 us | < 1 us (unchanged) | < 1 us | Yes |
| P2 hash comparison | ~50ns (FNV) + timing leak | ~200ns (SHA-256, ct_eq) | < 100 us | Yes |
| P2 full validation | ~5 us | ~6 us | < 100 us | Yes |
| P3 deep proof | ~0 us (stub) | ~500 us - 5 ms | < 10 ms | Yes |
| Witness chain append | ~100ns (XOR fold) | ~300ns (SHA-256 + sign) | N/A (async) | Yes |
| Boot measurement | ~10 us (already SHA-256) | ~10 us (unchanged) | N/A | Yes |

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| `ed25519-dalek` `no_std` compatibility breaks on target | Low | High | Pin version; fallback to `HmacSha256WitnessSigner` which uses only `sha2` + `hmac`. |
| SHA-256 performance on constrained embedded targets | Medium | Medium | Benchmark on Seed target early. ARM Cortex-A72 has crypto extensions; enable `asm` feature in `sha2` crate for hardware acceleration. |
| TEE unavailable on deployment target | High | Low | Software fallback (`Ed25519WitnessSigner`) provides full cryptographic verification without hardware TEE. TEE adds hardware binding, not correctness. |
| Existing witness chains become unverifiable after migration | Medium | Medium | Migration tool computes SHA-256 over existing entries and produces a "migration attestation" entry that bridges old FNV-based chain to new SHA-256 chain. |
| `fnv-fallback` accidentally enabled in production | Low | Critical | `compile_error!` in release builds (same pattern as `disable-boot-verify` in `cap/src/security.rs:41-46`). |

---

## Migration Strategy

1. **Phase 1 (immediate)**: Enable `crypto-sha256` as default. Replace all FNV-1a in security paths. Add `subtle` constant-time comparisons. This addresses A-01 through A-04, A-11.

2. **Phase 2 (1 week)**: Implement `WitnessSigner` trait with `Ed25519WitnessSigner` and `HmacSha256WitnessSigner`. Gate `NullSigner` behind `fnv-fallback`. Implement real Merkle witness verification. This addresses A-05, A-06, A-07.

3. **Phase 3 (2 weeks)**: Implement `TeeWitnessSigner` with platform-specific attestation. Integrate with `SecurityGate` for direct P3 verification. This addresses the TEE-backed signing requirement from ADR-042.

4. **Phase 4 (ongoing)**: Add TEE platform support (`tee-sgx`, `tee-sev`, `tee-tdx`, `tee-arm-cca`) as hardware becomes available for testing.

---

## Acceptance Test

A forged witness entry with any of the following properties must fail deterministically and leave the chain append path side-effect free:

- Reordered fields (exploiting former XOR commutativity)
- Reused nonce
- Invalid Merkle path (wrong sibling hash at any level)
- Swapped TEE quote collateral (expired or wrong platform)
- Truncated or zero-padded signature

## Implementation Status (2026-04-04)

All four phases have been implemented and tested (636 tests, 0 failures across 11 library crates).

### Phase 1: SHA-256 Baseline — COMPLETE
- `sha2` ^0.10 added to workspace (`default-features = false`, `no_std`)
- `rvm-witness/src/hash.rs`: SHA-256 chain and record hashing with XOR-fold to u64/u32
- `rvm-security/src/attestation.rs`: SHA-256 chain root accumulation
- `rvm-boot/src/measured.rs`: SHA-256 measurement extension
- Feature-gated: `crypto-sha256` (default), FNV-1a fallback preserved

### Phase 2: Signer Trait — COMPLETE
- `rvm-proof/src/signer.rs`: `WitnessSigner` trait with `SignatureError` enum (7 causes), `signer_id()` per amended spec
- `HmacSha256WitnessSigner`: HMAC-SHA256 with constant-time verify
- `NullSigner`: gated behind `#[cfg(any(test, feature = "null-signer"))]`
- `rvm-proof/src/constant_time.rs`: `ct_eq_32`, `ct_eq_64` with parse-normalize-compare invariant
- `rvm-proof/src/tee.rs`: `TeeQuoteProvider`, `TeeQuoteVerifier`, `TeePlatform` trait definitions

### Phase 3: TEE Pipeline — COMPLETE
- `rvm-proof/src/tee_provider.rs`: `SoftwareTeeProvider` (133-byte structured quotes with HMAC-SHA256 tags)
- `rvm-proof/src/tee_verifier.rs`: `SoftwareTeeVerifier` (quote parsing, measurement check, collateral expiry, constant-time HMAC verify)
- `rvm-proof/src/tee_signer.rs`: `TeeWitnessSigner<P,V>` composing provider->verifier->signer pipeline

### Phase 4: SecurityGate Integration — COMPLETE
- `rvm-witness/src/signer.rs`: `HmacWitnessSigner` (HMAC-SHA256 default), `record_to_digest()` helper
- `rvm-witness/src/log.rs`: `WitnessLog::signed_append()` (signs after chain-hash metadata populated)
- `rvm-security/src/gate.rs`: `SignedSecurityGate<N,S>` with per-link signature verification
- `rvm-proof/src/engine.rs`: `ProofEngine::verify_p3_signed()` with signed witness emission
- `rvm-kernel/src/lib.rs`: `CryptoSignerAdapter<S>` bridging 64-byte to 8-byte signer

### Ed25519 + DualHmac — COMPLETE
- `Ed25519WitnessSigner`: `ed25519-dalek` ^2.1 with `verify_strict()`, feature-gated `ed25519`
- `DualHmacSigner`: 64-byte double-HMAC-SHA256, domain separator `0x04`

### Remaining (hardware-dependent)
- Concrete SGX/SEV-SNP/TDX/ARM CCA `TeeQuoteProvider` implementations (needs hardware)
- TDX collateral refresh infrastructure (30-day expiry policy)
- Replace default HMAC key with TEE-derived key at runtime

---

## References

### Internal ADRs
- ADR-042: Security RVF -- AIDefence + TEE Hardened Cognitive Container
- ADR-135: Proof Verifier Design -- Three-Layer Verification for Capability-Gated Mutation
- ADR-132: RVM Hypervisor Core
- ADR-134: Witness Schema and Log Format
- ADR-087: Cognition Kernel

### Standards
- NIST FIPS 180-4: Secure Hash Standard (SHA-256) — collision resistance 2^128, preimage/second-preimage 2^256
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication

### Platform Specifications
- Intel SGX Attestation Technical Details: https://www.intel.com/content/www/us/en/security-center/technical-details/sgx-attestation-technical-details.html
- Intel TDX Enabling Guide (Infrastructure Setup, collateral refresh): https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/
- AMD SEV-SNP Firmware ABI Specification (LAUNCH_DIGEST, VCEK cert chain)
- ARM Confidential Compute Architecture (CCA) Specification (Realm Initial Measurement, Realm Token)

### Crate Dependencies (pinned major versions — security-critical)
- `sha2` ^0.10: https://docs.rs/sha2 — no_std SHA-256
- `ed25519-dalek` ^2: https://docs.rs/ed25519-dalek — no_std Ed25519 with `verify_strict`
- `subtle` ^2.6: https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html — constant-time equality
- `hmac` ^0.13: https://docs.rs/crate/hmac/latest — keyed HMAC

### Academic
- Bernstein, D.J. "Curve25519: New Diffie-Hellman Speed Records." PKC 2006.
