# ADR-149: RVF Integration for RVM

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core, memory tiers), ADR-134 (Witness Schema), ADR-142 (TEE Crypto), ADR-148 (Error Model)

---

## Context

The RuVector ecosystem includes 22 RVF (RuVector Format) crates that provide a
standardized package format for boot images, vector indexes, cryptographic
manifests, and runtime containers. RVM currently has no specification for how it
consumes RVF packages. The deep review identified this as specification gap B5:
how RVM uses RVF for boot images, dormant memory checkpoints, witness archives,
and GPU kernel distribution is undocumented.

The key RVF crates for RVM integration are: `rvf-types` (core types), `rvf-crypto` (signing/verification), `rvf-manifest` (package manifests), `rvf-index` (HNSW indexing), `rvf-runtime` (execution environment), `rvf-kernel` (kernel integration), and `rvf-quant` (quantized compression). A total of 22 crates are available in `ruvector/crates/rvf/`.

### Problem Statement

1. **Boot image format is unspecified**: `rvm-boot` loads partition images but the packaging format is ad hoc.
2. **Dormant memory has no container format**: the `Dormant` tier (tier 2) in `rvm-memory` stores compressed state, but the container format and metadata are not standardized.
3. **Witness archives are not portable**: witness logs are append-only in memory but have no export/archive format.
4. **GPU kernel distribution is undefined**: ADR-144 introduces GPU compute but does not specify how GPU kernels are packaged and distributed to partitions.
5. **No cryptographic binding between RVF signing and RVM verification**: `rvf-crypto` and `rvm-proof`'s `WitnessSigner` both provide signing, but their relationship is not specified.

---

## Decision

### 1. RVF as the Universal Container Format

All persistent artifacts in RVM are stored as RVF containers. An RVF container
consists of:

- **Manifest** (`rvf-manifest`): JSON or CBOR metadata describing contents,
  version, dependencies, and cryptographic hashes.
- **Payload**: the raw artifact data (binary image, compressed state, log entries).
- **Signature** (`rvf-crypto`): Ed25519 or HMAC-SHA256 signature over the
  manifest + payload hash.

RVF containers are identified by a content-addressed hash of the manifest,
enabling deduplication and integrity verification without parsing the payload.

### 2. Boot Image Packaging

`rvm-boot` loads partition images from RVF containers. The manifest declares `type: "rvm-boot-image"`, `target_arch`, `entry_point`, `stack_size`, `vmid`, and `payload_hash`. The payload is an ELF or flat binary; the signature uses Ed25519.

Boot sequence: (1) verify signature via `rvf-crypto`, (2) verify payload hash against manifest, (3) extract entry point/stack/VMID and pass to `SwitchContext::init()` (ADR-146), (4) load binary into stage-2 address space via `MmuOps::map_page()` (ADR-147), (5) emit witness record with boot image hash, VMID, and epoch.

### 3. Dormant Memory Checkpoints

The `Dormant` tier (tier 2) in `rvm-memory/src/tier.rs` stores compressed partition state. When coherence drops below `TierThresholds::warm_to_dormant`, memory is compressed and stored as an RVF checkpoint container. The manifest declares `type: "rvm-checkpoint"`, `partition_id`, `epoch`, `witness_sequence`, `timestamp_ns`, `compression: "lz4"`, and `payload_hash`. These fields map directly to `RecoveryCheckpoint` (ADR-148).

Reconstruction (Dormant -> Warm) uses `ReconstructionReceipt` with `was_hibernated = true`. The `ReconstructionPipeline` in `rvm-memory/src/reconstruction.rs` decompresses the payload and remaps pages via `MmuOps::map_page()`.

### 4. Witness Archive

Witness logs (ADR-134) are archived to RVF containers for long-term storage. The manifest declares `type: "rvm-witness-archive"`, `sequence_range`, `epoch_range`, `record_count`, `chain_hash` (final hash in the witness chain), and `payload_hash`. The `chain_hash` enables verification that the archive is a contiguous, untampered segment. Archives are stored in Cold tier (tier 3, ADR-132) and accessed only during recovery or audit.

### 5. GPU Kernel Distribution

GPU kernels (ADR-144) are distributed as RVF containers with `type: "rvm-gpu-kernel"`, `backend` (webgpu/cuda/opencl), `workgroup_size`, and `required_capabilities`. The payload is SPIR-V or WGSL bytecode. The GPU manager verifies the container signature before loading, maps the kernel into the partition's GPU address space, and updates `SwitchContext::gpu_queue_head`.

### 6. Cryptographic Alignment: rvf-crypto and WitnessSigner

`rvf-crypto` provides Ed25519 and HMAC-SHA256 signing. `rvm-proof`'s
`WitnessSigner` trait (ADR-134, ADR-142) provides the same algorithms for
witness chain signing. The alignment:

| Operation | rvf-crypto | rvm-proof WitnessSigner |
|-----------|-----------|----------------------|
| Ed25519 sign | `rvf_crypto::sign_ed25519()` | `Ed25519Signer::sign()` |
| Ed25519 verify | `rvf_crypto::verify_ed25519()` | `Ed25519Signer::verify()` |
| HMAC-SHA256 | `rvf_crypto::hmac_sha256()` | `HmacSha256Signer::sign()` |

Both use the same key format (32-byte Ed25519 seed, 32-byte HMAC key). RVM
uses `WitnessSigner` for runtime witness operations and `rvf-crypto` for
container-level signing. A single key pair can be used for both, enabling
end-to-end verification from witness record to archived container.

For TEE deployments (ADR-142), the signing key is held in the secure enclave
and both `WitnessSigner` and `rvf-crypto` delegate to the TEE signing API.

### 7. Integration Path

The RVF integration touches three RVM crates:

| RVM Crate | RVF Dependency | Integration Point |
|-----------|---------------|-------------------|
| `rvm-boot` | `rvf-types`, `rvf-manifest`, `rvf-crypto` | Boot image loading and verification |
| `rvm-memory` | `rvf-types`, `rvf-manifest`, `rvf-crypto`, `rvf-quant` | Dormant checkpoint storage and reconstruction |
| `rvm-witness` | `rvf-types`, `rvf-manifest`, `rvf-crypto` | Witness log archival to Cold tier |
| `rvm-gpu` | `rvf-types`, `rvf-manifest`, `rvf-crypto` | GPU kernel packaging and distribution |

All RVF dependencies are optional, gated behind the `rvf` feature flag. Without
the feature, RVM operates with raw binary formats (backwards compatible).

---

## Consequences

### Positive

- Unified container format across all persistent artifacts.
- Cryptographic signing provides tamper-evident packaging for all artifacts.
- Content-addressed manifests enable deduplication and integrity checking.
- `rvf-quant` provides quantized compression for Dormant tier, reducing memory.
- Feature-gated integration preserves minimal builds for Seed tier (64KB MCU).

### Negative

- RVF adds 3-4 new crate dependencies to each integrating RVM crate.
- Manifest parsing requires either JSON or CBOR support, adding code size.
- Container overhead (manifest + signature) adds latency to boot and checkpoint paths.

### Risks

- If `rvf-crypto` and `rvm-proof` key formats diverge, key management becomes fragmented.
- RVF container format changes in upstream ruvector could break RVM compatibility.
- Cold-tier witness archives may grow unbounded without a retention policy.

---

## References

- `ruvector/crates/rvf/` -- 22 RVF crates
- `rvm-memory/src/tier.rs` -- `Tier::Dormant`, `TierThresholds`
- `rvm-memory/src/reconstruction.rs` -- `ReconstructionPipeline`
- `rvm-types/src/recovery.rs` -- `RecoveryCheckpoint`, `ReconstructionReceipt`
- `rvm-proof` -- `WitnessSigner` trait (Ed25519, HMAC-SHA256, DualHmac)
- ADR-132 -- Memory tier model (Hot, Warm, Dormant, Cold)
- ADR-134 -- Witness schema and log format
- ADR-142 -- TEE-backed cryptographic verification
- ADR-144 -- GPU compute support
- ADR-148 -- Error model and recovery (checkpoint/reconstruction types)
- `docs/RUVECTOR-INTEGRATION.md` -- RVF crate inventory
