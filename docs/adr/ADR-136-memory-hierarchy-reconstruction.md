# ADR-136: Memory Hierarchy and Reconstruction

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

---

## Context

ADR-132 introduces a four-tier memory model where page residency is driven by coherence graph signals rather than simple access frequency. Traditional hypervisors use demand paging with a binary resident/swapped model. RVM needs a richer model because:

1. **Coherence-driven placement**: Pages should remain resident not just because they are accessed, but because the graph structure (cut pressure, locality) justifies the cost of keeping them hot.
2. **Reconstruction from witnesses**: Dormant state can be restored without storing full memory snapshots, by replaying witness-recorded deltas against a compressed checkpoint.
3. **No-std constraint**: The memory manager must operate with zero heap allocation, using only caller-provided fixed-size buffers.

## Decision

### Four-Tier Memory Model

| Tier | Name | Location | Residency Rule |
|------|------|----------|----------------|
| 0 | Hot | Per-core SRAM / L1-adjacent | Always resident during partition execution |
| 1 | Warm | Shared cluster DRAM | Resident if `cut_value + recency_score > eviction_threshold` |
| 2 | Dormant | Compressed in main memory | Checkpoint + witness delta; reconstructed on demand |
| 3 | Cold | RVF-backed persistent archival | Accessed only during recovery; never auto-promoted |

All tier transitions are **explicit**, not demand-paged. The kernel (or coherence engine, when available) decides when to promote or demote a region. Every transition emits a `RegionPromote` or `RegionDemote` witness record.

### DC-1 Degraded Mode

When the coherence engine is absent (DC-1), `cut_value` defaults to 0. Tier placement falls back to static thresholds based on `recency_score` alone:

| Transition | Threshold (basis points) |
|------------|------------------------|
| Hot -> Warm | 7000 |
| Warm -> Dormant | 4000 |
| Dormant -> Cold | 1000 |
| Warm -> Hot | 8000 |
| Dormant -> Warm | 5000 |

These conservative defaults prevent aggressive demotion without coherence data.

### BuddyAllocator

Physical page allocation uses a power-of-two buddy allocator operating on 4 KiB pages (`PAGE_SIZE = 4096`). The allocator is `no_std` compatible with zero heap allocation, using a fixed-size bitmap for free-list tracking.

### RegionManager

The `RegionManager` tracks `OwnedRegion` instances, each containing:

- Guest physical base address (page-aligned).
- Host physical base address (page-aligned).
- Page count and access permissions (read/write/execute).
- Owning `PartitionId`.
- Current tier state via `RegionTierState`.

Region overlap checks enforce isolation: guest-physical overlap is valid only within the same partition (separate stage-2 page tables), but host-physical overlap across partitions is a critical isolation violation.

### ReconstructionPipeline

Dormant memory is stored as a `CompressedCheckpoint` plus a sequence of `WitnessDelta` entries. Reconstruction proceeds in three steps:

1. **Load checkpoint**: Decompress the LZ4-compressed snapshot into a caller-provided buffer.
2. **Apply deltas**: Replay each `WitnessDelta` in sequence order, writing the recorded data at the specified offset.
3. **Verify hash**: Validate the final state hash (FNV-1a) against the expected value stored in the checkpoint.

If verification fails, the reconstruction is aborted and the region remains dormant. A `RecoveryEnter` witness is emitted on failure.

Each `WitnessDelta` records:
- Witness sequence number (for ordering).
- Byte offset within the region.
- Data length.
- FNV-1a hash of the written data (integrity check per delta).

### Address Space Validation

The `validate_region()` function enforces:
- Page alignment of both guest and host base addresses.
- Non-zero page count.
- At least one permission bit set (read, write, or execute).

The `regions_overlap()` and `regions_overlap_host()` functions detect guest-physical and host-physical overlaps respectively, enabling the kernel to reject mappings that would break isolation.

## Consequences

### Positive

- **Coherence-driven residency** reduces remote memory traffic by keeping pages hot only when graph structure justifies it (target: 20% reduction vs. naive placement).
- **Checkpoint + delta reconstruction** avoids storing full dormant snapshots, reducing cold storage requirements.
- **Zero-allocation design** enables deployment on Seed-class hardware (64 KB - 1 MB RAM).
- **Explicit tier transitions** eliminate demand-paging complexity and make memory behavior deterministic and auditable.

### Negative

- **No demand paging** means a page fault on a demoted region is a hard fault, not a transparent recovery. The kernel must proactively manage promotions.
- **Reconstruction latency** depends on the number of deltas since the last checkpoint. Long-running partitions with infrequent checkpoints may have slow reconstruction.
- **Static DC-1 thresholds** are conservative and may over-demote on hardware where DRAM is abundant.

### Neutral

- The compression stub currently uses a simple byte-level algorithm. Production deployments will use `lz4_flex` or hardware compression; the interface is abstracted behind the `CompressedCheckpoint` type.

## References

- ADR-132: RVM Hypervisor Core (DC-1, DC-6, memory model section)
- ADR-138: Seed Hardware Profile (no_alloc constraints)
- `crates/rvm-memory/src/lib.rs` -- Module root and region validation
- `crates/rvm-memory/src/tier.rs` -- Four-tier model and thresholds
- `crates/rvm-memory/src/allocator.rs` -- BuddyAllocator
- `crates/rvm-memory/src/region.rs` -- OwnedRegion and RegionManager
- `crates/rvm-memory/src/reconstruction.rs` -- ReconstructionPipeline
