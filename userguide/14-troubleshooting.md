# Troubleshooting: Common Issues and Solutions

This chapter covers the most frequently encountered problems when building,
testing, and running RVM, along with their solutions. Each section identifies
the symptom, explains the cause, and provides a concrete fix.

For build and deployment details, see [Bare-Metal
Deployment](12-bare-metal.md). For performance-related issues, see
[Performance](11-performance.md).

---

## 1. Build Fails: Missing Target

**Symptom:**

```text
error[E0463]: can't find crate for `core`
  |
  = note: the `aarch64-unknown-none` target may not be installed
```

**Cause:** The bare-metal AArch64 target is not installed.

**Fix:**

```bash
rustup target add aarch64-unknown-none
```

This downloads the precompiled `core` library for the bare-metal target. You
only need to do this once per Rust toolchain version.

---

## 2. Build Fails: Wrong Rust Version

**Symptom:**

```text
error: package `rvm-types v0.1.0` cannot be built because it requires
       rustc 1.77 or newer
```

**Cause:** Your Rust compiler is older than the minimum supported version.

**Fix:**

```bash
rustup update stable
rustc --version  # verify 1.77.0 or later
```

All workspace crates declare `rust-version = "1.77"` in `Cargo.toml`. This
is the minimum version that supports the const generics and language features
RVM depends on.

---

## 3. Build Fails: Feature Flag Conflicts

**Symptom:**

```text
error[E0432]: unresolved import `sha2`
  --> crates/rvm-proof/src/signer.rs:5:5
```

**Cause:** The `crypto-sha256` feature is enabled but the `sha2` dependency
is not available, or you are building with conflicting feature combinations.

**Fix:** Check which features are active:

```bash
cargo tree -p rvm-proof -f "{p} [{f}]"
```

If you are building for Seed (minimal) profile, disable cryptographic
features:

```bash
cargo build -p rvm-proof --no-default-features
```

If you *want* SHA-256 support, ensure the feature is explicitly enabled:

```bash
cargo build -p rvm-proof --features crypto-sha256
```

---

## 4. Tests Fail

**Symptom:** One or more tests fail when running `cargo test`.

**Fix:** Run the full workspace test suite with the correct flags:

```bash
cargo test --workspace --lib
```

Common causes of test failures:

- **Running a single crate without workspace features.** Some crates depend
  on features that are enabled by the workspace `Cargo.toml`. Running
  `cargo test -p rvm-proof` alone may miss features. Always use `--workspace`
  for the full test suite.

- **Stale build artifacts.** After switching branches or updating Rust:

  ```bash
  cargo clean && cargo test --workspace
  ```

- **Platform-specific failures.** The AArch64 HAL tests only compile when
  targeting `aarch64-unknown-none`. Host-side tests skip platform-specific
  code automatically.

---

## 5. QEMU Does Not Boot

**Symptom:** `make run` hangs with no output, or QEMU prints an error and
exits.

### QEMU not installed

```text
make: qemu-system-aarch64: No such file or directory
```

**Fix:** Install QEMU:

```bash
# macOS
brew install qemu

# Ubuntu / Debian
sudo apt install qemu-system-aarch64
```

### Wrong machine type

```text
qemu-system-aarch64: -M invalid: unsupported machine type
```

**Fix:** RVM targets the `virt` machine type. Verify your QEMU supports it:

```bash
qemu-system-aarch64 -M help | grep virt
```

### Linker script not found

```text
rust-lld: error: cannot find linker script rvm.ld
```

**Fix:** The linker script must be in the workspace root. Verify:

```bash
ls -la rvm.ld
```

If you are building from a subdirectory, `cd` to the workspace root first.
The `.cargo/config.toml` sets `rustflags = ["-C", "link-arg=-Trvm.ld"]`,
which is relative to the workspace root.

### Kernel hangs at boot

If QEMU starts but produces no UART output, the issue is likely in the
assembly boot stub or the HAL initialization. Check:

1. The ELF entry point is at `0x4000_0000`:
   ```bash
   make objdump | head -20
   ```
2. The BSS section is properly zeroed (check `__bss_start` and `__bss_end`
   symbols).
3. The stack pointer is correctly set to `__stack_top`.

Press **Ctrl-A X** to exit QEMU.

---

## 6. Capability Errors

### InsufficientCapability

**Symptom:** `Err(InsufficientCapability)` from a capability check.

**Cause:** The `CapToken` does not have the required `CapRights` for the
operation.

**Fix:** Verify the token's rights include what the operation needs:

```rust
// Check what rights the token has
let rights = token.rights();

// Common required rights:
// - READ for memory access
// - WRITE for memory mutation
// - EXECUTE for code execution
// - GRANT for capability delegation
// - REVOKE for capability revocation
// - PROVE for proof submission
```

### CapabilityTypeMismatch

**Symptom:** `Err(CapabilityTypeMismatch)` when presenting a capability.

**Cause:** The capability's `CapType` does not match the resource type. For
example, presenting a `CapType::Partition` token when a
`CapType::Region` token is required.

**Fix:** Create or derive a capability with the correct type. Capability
types cannot be changed after creation -- you need a new capability.

### Epoch mismatch (StaleCapability)

**Symptom:** `Err(StaleCapability)` or `Err(InsufficientCapability)` when
the token was previously valid.

**Cause:** The system epoch has advanced since the capability was created.
Epoch-based revocation invalidates all capabilities from prior epochs.

**Fix:** Obtain a fresh capability from the current epoch. The epoch is
rotated during bulk revocation events. See [Capabilities and
Proofs](05-capabilities-proofs.md) for epoch semantics.

---

## 7. Proof Verification Fails

### ProofInvalid

**Symptom:** `Err(ProofInvalid)` from `rvm_proof::verify()`.

**Common causes:**

1. **Empty proof data.** A proof with zero-length data always fails:

   ```rust
   // This will fail:
   let proof = Proof::hash_proof(commitment, &[]);
   ```

2. **Wrong commitment.** The proof's commitment must match the expected
   commitment exactly. The commitment is computed from the proof data:

   ```rust
   let data = b"my proof data";
   let commitment = rvm_proof::compute_data_hash(data);
   let proof = Proof::hash_proof(commitment, data);
   // verify(proof, &commitment) -- this matches
   ```

3. **Witness chain proof with broken links.** For P2 (Witness tier) proofs,
   each 16-byte link must chain correctly:
   `link[i].record_hash == link[i+1].prev_hash`.

### ProofTierInsufficient

**Symptom:** `Err(ProofTierInsufficient)` from the proof engine.

**Cause:** The operation requires a higher proof tier than what was submitted.
For example, a cross-partition operation may require P2 (Witness) but only
P1 (Hash) was provided.

**Fix:** Submit a proof at the required tier. See the tier table in
[Capabilities and Proofs](05-capabilities-proofs.md).

---

## 8. Memory Alignment Errors

### AlignmentError

**Symptom:** `Err(AlignmentError)` from memory operations.

**Cause:** A guest or host physical address is not page-aligned. RVM requires
all memory regions to start on 4 KB page boundaries.

**Fix:** Ensure addresses are multiples of `PAGE_SIZE` (4096):

```rust
use rvm_memory::PAGE_SIZE;

let addr = PhysAddr::new(0x1000_0000);  // OK: aligned
let bad  = PhysAddr::new(0x1000_0001);  // Error: not aligned

// Check alignment:
assert!(addr.is_page_aligned());
```

---

## 9. Partition Limits

### ResourceLimitExceeded / PartitionLimitExceeded

**Symptom:** `Err(ResourceLimitExceeded)` or `Err(PartitionLimitExceeded)`
when creating a partition.

**Cause:** RVM supports a maximum of 256 partitions per instance. This limit
comes from the ARM VMID width (8 bits). The constant
`MAX_PARTITIONS` in `rvm-types` enforces it.

**Fix:** Either:
- Destroy unused partitions before creating new ones.
- Merge tightly coupled partitions to free VMID slots. See [Advanced and
  Exotic](13-advanced-exotic.md) for merge preconditions.

### DelegationDepthExceeded

**Symptom:** `Err(DelegationDepthExceeded)` when granting a capability.

**Cause:** The capability derivation tree has reached its maximum depth of 8
levels. A capability that was delegated 8 times cannot be delegated further.

**Fix:** Grant from a capability closer to the root of the derivation tree,
or use `GRANT_ONCE` for non-transitive delegation.

---

## 10. Witness Chain Broken

### ChainIntegrityError

**Symptom:** `verify_chain()` returns `Err(ChainIntegrityError { .. })`.

**Cause:** The `prev_hash` of record N does not match the `record_hash` of
record N-1. This indicates either:

1. **Tampering.** Someone or something modified a witness record after
   emission.
2. **Ring buffer wrap.** If the ring buffer wrapped and you are reading
   across the wrap boundary, the chain naturally breaks at the oldest
   retained record.
3. **NullSigner in production.** The `NullSigner` does not compute real
   hashes. It is only for testing.

**Fix:**

- If the break is at the ring buffer wrap point, this is expected behavior.
  The chain is valid within each contiguous segment.
- If the break is mid-segment, investigate the surrounding records for
  anomalies (wrong sequence numbers, impossible timestamps).
- **Never use `NullSigner` in production.** Use `StrictSigner` or
  `HmacSha256WitnessSigner` for real deployments. The `NullSigner` is gated
  behind the `null-signer` feature flag and is deprecated. See [Witness and
  Audit](06-witness-audit.md) and [Security](10-security.md).

---

## 11. Performance Issues

**Symptom:** Operations are slower than expected benchmarks.

### Check the build profile

The most common cause of poor performance is benchmarking in dev profile:

```bash
# WRONG: dev profile, no optimization
cargo test  # tests run in dev profile

# RIGHT: release profile
cargo bench  # benchmarks run in bench profile (inherits release)
```

If you need to time something outside of Criterion, build with `--release`:

```bash
cargo build --release
```

### Check feature flags

Unused subsystems add code and may affect instruction cache behavior. For
peak performance on resource-constrained hardware, disable features you do
not use:

```bash
cargo build --release --no-default-features --features "crypto-sha256"
```

### Check ring buffer size

An oversized witness ring buffer wastes memory and can cause cache pressure.
For the Seed profile, use the smallest ring that avoids `WitnessLogFull`
errors:

```rust
let log = WitnessLog::<64>::new();  // 64 records = 4 KB
```

For Appliance deployments with heavy witness traffic, increase the ring:

```rust
let log = WitnessLog::<262144>::new();  // 262,144 records = 16 MB
```

### Check the adaptive engine

If coherence computations are being dropped, the
`AdaptiveCoherenceEngine::budget_exceeded_count` field will be non-zero. This
means the CPU is too loaded for the configured MinCut budget. Reduce the
MinCut budget or accept a less accurate cut computation. See
[Performance](11-performance.md) for tuning details.

---

## 12. Getting Help

### ADR documents

The `docs/adr/` directory contains the Architecture Decision Records that
define every aspect of RVM's design. Key ADRs:

| ADR | Topic |
|---|---|
| ADR-132 | First-class kernel objects and design constraints |
| ADR-133 | Hardware abstraction layer |
| ADR-134 | Witness trail specification |
| ADR-135 | Capability and proof system |
| ADR-136 | Four-tier memory model |
| ADR-137 | Seven-phase boot sequence |
| ADR-138 | Memory management details |
| ADR-139 | Coherence engine |
| ADR-140 | Partition lifecycle |
| ADR-142 | TEE and cryptographic integration |

### GitHub issues

File issues at the RVM repository. Include:

1. The exact error message or unexpected behavior.
2. The command you ran (e.g., `cargo test --workspace`).
3. Your Rust version (`rustc --version`) and OS.
4. Any feature flags you enabled or disabled.

### This user guide

| I need to... | Read |
|---|---|
| Build and boot RVM | [Quick Start](01-quickstart.md) |
| Understand the architecture | [Architecture](03-architecture.md) |
| Find a specific API | [Crate Reference](04-crate-reference.md) |
| Debug capability issues | [Capabilities and Proofs](05-capabilities-proofs.md) |
| Debug witness issues | [Witness and Audit](06-witness-audit.md) |
| Debug memory issues | [Memory Model](08-memory-model.md) |
| Optimize performance | [Performance](11-performance.md) |
| Find a term definition | [Glossary](15-glossary.md) |
| Find cross-references | [Cross-Reference Index](cross-reference.md) |

---

## Further Reading

- [Quick Start](01-quickstart.md) -- build, test, and boot in five minutes
- [Bare-Metal Deployment](12-bare-metal.md) -- QEMU parameters and linker script
- [Performance](11-performance.md) -- build profiles and tuning
- [Security](10-security.md) -- signer configuration and NullSigner deprecation
- [Cross-Reference Index](cross-reference.md) -- find every mention of a concept
