# ADR-136: Memory Hierarchy and Reconstruction — Four-Tier Coherence-Driven Memory Model

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-135 (Proof Verifier Design), ADR-133 (Partition Object Model)

---

## Context

ADR-132 establishes a four-tier memory model (hot/warm/dormant/cold) as a key differentiator of the RVM hypervisor. Unlike traditional virtual memory systems that treat pages as either resident or swapped, RVM assigns pages to tiers based on cut-value and recency scoring derived from the coherence graph. The memory model is also designed to work without the coherence engine (design constraint DC-1), falling back to static thresholds for tier transitions.

### Problem Statement

1. **Traditional VM memory management wastes coherence locality**: Demand paging treats all pages equally. A page that anchors a heavily-used cross-partition communication channel is evicted with the same LRU logic as a page containing stale temporary data. RVM needs memory placement decisions that understand the coupling structure of the workload.
2. **Memory is the scarcest resource on edge/appliance targets**: The Seed profile runs on hardware-constrained devices where RAM is measured in megabytes, not gigabytes. Keeping dormant state as compressed checkpoints rather than raw bytes dramatically extends effective capacity.
3. **Reconstruction from compressed state is a novel capability**: No existing hypervisor stores dormant memory as "witness checkpoint + delta compression" and reconstructs the original state on demand. This enables a form of "memory time travel" where any historical state can be rebuilt from its checkpoint plus the witness replay log.
4. **Tier transition logic is a large bug surface**: Four tiers with compression, decompression, reconstruction, and witness replay create a combinatorial interaction surface. Without disciplined module boundaries, this becomes the system's primary reliability risk.
5. **The memory model must work without the coherence engine**: DC-1 requires that tier transitions function with static thresholds when the coherence engine is absent, degraded, or over budget.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| Firecracker memory balloon | Page-level memory management for microVMs | Baseline comparison; RVM goes beyond single-tier resident/not-resident |
| zswap (Linux) | Compressed swap cache | Validates compressed-in-memory tier approach; RVM formalizes this as the dormant tier |
| Theseus OS | Rust ownership for OS memory management | Informs OwnedRegion with transfer-by-move semantics |
| RedLeaf | Cross-domain memory isolation in Rust | Informs capability-gated shared region design |
| ZRAM (Linux) | Block device backed by compressed RAM | Compression approach for dormant tier; RVM adds reconstruction semantics |
| ARM two-stage translation | VA -> IPA -> PA for hypervisors | Direct model for RVM partition stage-1 + hypervisor stage-2 |
| Buddy allocator (Knuth) | Power-of-two block allocation | Foundation for per-tier free list management |

---

## Decision

Implement a four-tier memory hierarchy where tier placement is driven by coherence cut-value and recency scoring, dormant state is stored as reconstructable compressed checkpoints, and all memory ownership is enforced through Rust's type system.

### The Four Tiers

| Tier | Name | Location | Contents | Residency Rule |
|------|------|----------|----------|----------------|
| **0 (Hot)** | Tile/core-local | Per-core SRAM or L1-adjacent | Active execution state: registers, stack, heap of running partition | Always resident during partition execution. Evicted to warm on context switch if pressure exceeds threshold. |
| **1 (Warm)** | Shared fast memory | Cluster-shared DRAM | Recently-used shared state, IPC buffers, capability tables | Resident if `cut_value + recency_score > eviction_threshold`. Evaluated by coherence engine (or static threshold per DC-1). |
| **2 (Dormant)** | Compressed storage | Main memory, compressed | NOT raw bytes. Stored as witness checkpoint + delta compression. Contains suspended partition state, proof objects, embeddings. | Compressed; reconstructed on demand or at recovery. Promotes to warm when accessed. |
| **3 (Cold)** | RVF-backed archival | Persistent storage (flash/NVMe) | Restore points, historical state snapshots, full RVF checkpoints | Accessed only during recovery or explicit restore. Never promoted automatically. |

### Design Principles

- **Explicit promotion/demotion, NOT demand paging**: This is philosophically different from traditional virtual memory. Pages do not fault into residence. The tier transition engine explicitly moves regions between tiers based on scoring. There is no page fault handler that transparently loads from swap.
- **Residency rule**: `cut_value + recency_score > eviction_threshold`. This is continuously recomputed by the coherence engine as the graph evolves. When the coherence engine is absent (DC-1), `cut_value` defaults to 0 and only `recency_score` drives tier placement against a static threshold.
- **Dormant memory is reconstructable**: The dormant tier does not store raw page contents. It stores a witness checkpoint (the last known-good state hash) plus delta compression (the mutations applied since that checkpoint). Reconstruction replays the deltas against the checkpoint to produce the original state. This is the quiet killer feature.
- **Memory ownership via Rust's type system**: `OwnedRegion<P>` is non-copyable (`!Copy`, `!Clone`) with transfer-by-move semantics. A region belongs to exactly one partition at a time. Transfer between partitions requires a proof-gated `region_transfer` syscall that moves ownership atomically.
- **Zero-copy sharing via capability-gated read-only mapping**: Immutable regions can be mapped into multiple partitions' stage-2 tables as read-only or append-only. No writable page is ever shared between partitions (SEC-005 from the security model).
- **Tier transition logic lives in ONE module**: All promotion, demotion, compression, decompression, and reconstruction logic is in `tier_engine.rs`. No other module performs tier transitions. This is the primary defense against the combinatorial bug surface.

---

## Architecture

### Crate Structure

```
crates/ruvix/crates/memory/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Module root, feature-gated exports
│   ├── tier.rs                 # Tier enum, TierConfig, static threshold defaults
│   ├── tier_engine.rs          # THE tier transition engine (promotion/demotion/compress/reconstruct)
│   ├── owned_region.rs         # OwnedRegion<P>, non-copyable, transfer-by-move
│   ├── shared_region.rs        # Capability-gated read-only/append-only shared mappings
│   ├── buddy_allocator.rs      # Buddy allocator with per-tier free lists
│   ├── address_translation.rs  # Two-stage: VA -> IPA (partition) -> PA (hypervisor)
│   ├── compression.rs          # zstd/lz4 compression for dormant tier (configurable)
│   ├── reconstruction.rs       # Checkpoint + delta replay -> original state
│   ├── scoring.rs              # cut_value + recency_score computation, static fallback
│   ├── eviction.rs             # Eviction candidate selection, threshold enforcement
│   ├── types.rs                # PhysFrame, VirtAddr, IPA, RegionDescriptor, TierMetrics
│   └── error.rs                # MemoryError variants
└── tests/
    ├── tier_engine_tests.rs    # Exhaustive tier transition tests
    ├── reconstruction_tests.rs # Checkpoint + delta -> correct state
    ├── allocator_tests.rs      # Buddy allocator correctness
    ├── ownership_tests.rs      # Move semantics, no double-free, no use-after-transfer
    └── integration.rs          # Full lifecycle: allocate -> use -> dormant -> reconstruct
```

### Two-Stage Address Translation

```
┌─────────────────────────────────────────────────────────────────┐
│  Partition (EL0/EL1)                    Hypervisor (EL2)        │
│                                                                  │
│  Virtual Address (VA)                                            │
│       │                                                          │
│       ▼                                                          │
│  Stage-1 MMU (TTBR0_EL1)                                        │
│  Partition-controlled page table                                 │
│  VA → Intermediate Physical Address (IPA)                        │
│       │                                                          │
│       ▼                                                          │
│  Stage-2 MMU (VTTBR_EL2)                                        │
│  Hypervisor-controlled page table                                │
│  IPA → Physical Address (PA)                                     │
│       │                                                          │
│       ▼                                                          │
│  Physical Memory (tier 0/1) or                                   │
│  Compressed Storage (tier 2) or                                  │
│  Persistent Storage (tier 3)                                     │
└─────────────────────────────────────────────────────────────────┘
```

Stage-1 is per-partition: each partition manages its own virtual address space. Stage-2 is per-hypervisor: RVM controls which physical pages each partition can actually access. This separation means a compromised partition cannot map arbitrary physical memory even if it corrupts its own page tables.

### OwnedRegion Type

```rust
/// A memory region owned by exactly one partition.
/// Non-copyable, non-cloneable. Transfer is by move only.
/// The type parameter P identifies the owning partition (phantom).
#[repr(C)]
pub struct OwnedRegion<P: Partition> {
    /// Physical frames backing this region.
    frames: PhysFrameRange,
    /// Current tier (hot, warm, dormant, cold).
    tier: Tier,
    /// Region policy (immutable, append-only, slab, device MMIO).
    policy: RegionPolicy,
    /// Capability required to access this region.
    cap_handle: CapHandle,
    /// Compression state (for dormant tier).
    compression: Option<CompressionState>,
    /// Reconstruction metadata (checkpoint sequence + delta count).
    reconstruction: Option<ReconstructionMeta>,
    /// Phantom type for partition ownership.
    _partition: core::marker::PhantomData<P>,
}

// Ownership enforcement: no copy, no clone.
// Transfer between partitions requires proof-gated syscall.
impl<P: Partition> !Copy for OwnedRegion<P> {}
impl<P: Partition> !Clone for OwnedRegion<P> {}

impl<P: Partition> Drop for OwnedRegion<P> {
    fn drop(&mut self) {
        // Return physical frames to the buddy allocator's per-tier free list.
        // Unmap from stage-2 tables. Zero frames before return (security).
    }
}
```

### Tier Transition Engine

All tier transitions flow through one module. This is the primary defense against the combinatorial bug surface.

```rust
/// The tier transition engine. ALL tier changes go through this module.
/// No other module calls compress(), decompress(), promote(), or demote().
pub struct TierEngine {
    allocator: BuddyAllocator,
    compressor: Compressor,       // zstd or lz4, configurable
    scorer: ResidencyScorer,      // cut_value + recency, with static fallback
    witness_log: WitnessLogRef,   // For reconstruction deltas
}

impl TierEngine {
    /// Promote a region to a higher (hotter) tier.
    /// Hot <- Warm <- Dormant <- Cold
    pub fn promote(
        &mut self,
        region: &mut OwnedRegion<impl Partition>,
        target_tier: Tier,
    ) -> Result<(), MemoryError> {
        match (region.tier, target_tier) {
            (Tier::Warm, Tier::Hot) => self.warm_to_hot(region),
            (Tier::Dormant, Tier::Warm) => self.reconstruct_and_promote(region),
            (Tier::Cold, Tier::Dormant) => self.cold_to_dormant(region),
            _ => Err(MemoryError::InvalidTierTransition),
        }
    }

    /// Demote a region to a lower (colder) tier.
    /// Hot -> Warm -> Dormant -> Cold
    pub fn demote(
        &mut self,
        region: &mut OwnedRegion<impl Partition>,
        target_tier: Tier,
    ) -> Result<(), MemoryError> {
        match (region.tier, target_tier) {
            (Tier::Hot, Tier::Warm) => self.hot_to_warm(region),
            (Tier::Warm, Tier::Dormant) => self.compress_and_demote(region),
            (Tier::Dormant, Tier::Cold) => self.dormant_to_cold(region),
            _ => Err(MemoryError::InvalidTierTransition),
        }
    }

    /// Reconstruct a dormant region: checkpoint + witness replay + deltas.
    fn reconstruct_and_promote(
        &mut self,
        region: &mut OwnedRegion<impl Partition>,
    ) -> Result<(), MemoryError> {
        let meta = region.reconstruction.as_ref()
            .ok_or(MemoryError::NoReconstructionMeta)?;

        // 1. Decompress the checkpoint
        let checkpoint = self.compressor.decompress(&region.frames)?;

        // 2. Replay witness deltas from checkpoint sequence to current
        let deltas = self.witness_log.deltas_since(
            meta.checkpoint_sequence,
            region.cap_handle,
        )?;

        // 3. Apply deltas to checkpoint -> reconstructed state
        let reconstructed = apply_deltas(checkpoint, &deltas)?;

        // 4. Allocate warm-tier frames and copy reconstructed state
        let warm_frames = self.allocator.alloc(Tier::Warm, reconstructed.len())?;
        copy_to_frames(&warm_frames, &reconstructed);

        // 5. Update region metadata
        region.frames = warm_frames;
        region.tier = Tier::Warm;
        region.compression = None;
        region.reconstruction = None;

        Ok(())
    }
}
```

### Residency Scoring

```rust
/// Computes the residency score for a region.
/// When coherence engine is available: cut_value + recency_score.
/// When coherence engine is absent (DC-1): recency_score only,
/// against a static threshold.
pub struct ResidencyScorer {
    /// Static eviction threshold (used when coherence engine absent).
    static_threshold: f32,
    /// Whether the coherence engine is available.
    coherence_available: bool,
}

impl ResidencyScorer {
    /// Compute the residency score for a region.
    pub fn score(&self, region: &RegionDescriptor, graph: Option<&CoherenceGraph>) -> f32 {
        let recency = self.recency_score(region);

        let cut_value = match (self.coherence_available, graph) {
            (true, Some(g)) => g.cut_value(region.coherence_node_id()),
            _ => 0.0, // DC-1 fallback: no cut_value contribution
        };

        cut_value + recency
    }

    /// Should this region be evicted (demoted to a colder tier)?
    pub fn should_evict(&self, score: f32) -> bool {
        let threshold = if self.coherence_available {
            self.dynamic_threshold()
        } else {
            self.static_threshold // DC-1 fallback
        };
        score <= threshold
    }

    /// Recency score: decays exponentially with time since last access.
    fn recency_score(&self, region: &RegionDescriptor) -> f32 {
        let age_ns = current_time_ns() - region.last_accessed_ns;
        let age_ms = age_ns as f32 / 1_000_000.0;
        (-age_ms / RECENCY_HALF_LIFE_MS).exp()
    }
}
```

### Buddy Allocator with Per-Tier Free Lists

```rust
/// Buddy allocator managing physical frames across all four tiers.
/// Each tier has its own free list to enable tier-aware allocation.
pub struct BuddyAllocator {
    /// Per-tier free lists, indexed by Tier enum.
    free_lists: [BuddyFreeList; 4],
    /// Total physical memory managed, per tier.
    capacity: [usize; 4],
    /// Current usage, per tier.
    used: [usize; 4],
}

impl BuddyAllocator {
    /// Allocate frames from a specific tier's free list.
    pub fn alloc(&mut self, tier: Tier, size: usize) -> Result<PhysFrameRange, MemoryError> {
        let order = size.next_power_of_two().trailing_zeros() as usize;
        self.free_lists[tier as usize].alloc(order)
            .ok_or(MemoryError::OutOfMemory { tier })
    }

    /// Free frames back to the appropriate tier's free list.
    /// Frames are zeroed before return (security requirement).
    pub fn free(&mut self, tier: Tier, frames: PhysFrameRange) {
        zero_frames(&frames); // Prevent information leakage
        let order = frames.len().trailing_zeros() as usize;
        self.free_lists[tier as usize].free(frames.start(), order);
    }

    /// Report per-tier usage metrics.
    pub fn metrics(&self) -> TierMetrics {
        TierMetrics {
            hot:     (self.used[0], self.capacity[0]),
            warm:    (self.used[1], self.capacity[1]),
            dormant: (self.used[2], self.capacity[2]),
            cold:    (self.used[3], self.capacity[3]),
        }
    }
}
```

### Compression Configuration

```rust
/// Compression algorithm for the dormant tier. Configurable per-partition.
pub enum CompressionAlgo {
    /// zstd: higher compression ratio, higher CPU cost.
    /// Default for Appliance profile (more CPU, less memory).
    Zstd { level: i32 },
    /// lz4: lower compression ratio, lower CPU cost.
    /// Default for Seed profile (constrained CPU).
    Lz4,
    /// No compression (testing, or when CPU is the bottleneck).
    None,
}

/// Compression state stored with a dormant region.
pub struct CompressionState {
    pub algo: CompressionAlgo,
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f32,
}
```

### Zero-Copy Shared Regions

```rust
/// A shared region mapped into multiple partitions' stage-2 tables.
/// Only immutable or append-only policies are allowed for sharing.
/// SEC-005: no writable page is shared between partitions.
pub struct SharedRegion {
    /// Physical frames (shared, read-only or append-only mapping).
    frames: PhysFrameRange,
    /// Partitions with read access (capability-gated).
    readers: ArrayVec<PartitionId, 16>,
    /// Single writer (for append-only; None for immutable).
    writer: Option<PartitionId>,
    /// Region policy (must be Immutable or AppendOnly).
    policy: RegionPolicy,
}

impl SharedRegion {
    /// Map this region into a partition's stage-2 tables.
    /// Requires a capability with READ right on the region.
    pub fn map_into(
        &mut self,
        partition: PartitionId,
        cap: &Capability,
        stage2: &mut Stage2Tables,
    ) -> Result<VirtAddr, MemoryError> {
        // Verify capability
        if !cap.rights.contains(CapRights::READ) {
            return Err(MemoryError::InsufficientRights);
        }

        // Map as read-only in stage-2
        let pte_flags = match self.policy {
            RegionPolicy::Immutable => PTE_USER | PTE_RO | PTE_CACHEABLE,
            RegionPolicy::AppendOnly { .. } => {
                // Append-only: mapped read-only in EL0; writes go through syscall
                PTE_USER | PTE_RO | PTE_CACHEABLE
            }
            _ => return Err(MemoryError::InvalidSharingPolicy),
        };

        let virt = stage2.map(self.frames, pte_flags)?;
        self.readers.push(partition);
        Ok(virt)
    }
}
```

### Reconstruction: The Quiet Killer Feature

Dormant memory is not dead memory. It is reconstructable state:

```
Reconstruction Pipeline:
                                                              
  ┌─────────────┐     ┌──────────────┐     ┌──────────────┐  
  │  Compressed  │     │   Witness    │     │              │  
  │  Checkpoint  │────>│   Delta      │────>│ Reconstructed│  
  │  (dormant)   │     │   Replay     │     │    State     │  
  └─────────────┘     └──────────────┘     └──────────────┘  
        │                     │                     │         
        │  decompress()       │  apply_deltas()     │         
        │  zstd/lz4           │  witness log scan   │         
        │                     │                     │         
  checkpoint state    +  mutations since     =  original state
```

This means:
- A partition that has been dormant for hours can be reconstructed to its exact pre-dormancy state.
- The witness log serves double duty: audit trail AND reconstruction source.
- Cold-tier RVF checkpoints provide deep recovery points that can restore state from days or weeks ago.
- Memory consumption during dormancy is proportional to the compressed checkpoint size plus the delta log size, not the original working set size.

---

## DC-1 Compliance: Operation Without Coherence Engine

The memory hierarchy MUST function when the coherence engine is absent:

| Feature | With Coherence Engine | Without Coherence Engine (DC-1) |
|---------|----------------------|-------------------------------|
| Residency scoring | `cut_value + recency_score` | `recency_score` only (cut_value = 0) |
| Eviction threshold | Dynamically adjusted by coherence pressure | Static threshold from boot config |
| Warm tier sharing | Driven by cut-value (high coupling = share) | Driven by explicit `region_share` syscall only |
| Tier transitions | Coherence engine triggers promotion/demotion | Scheduler triggers based on recency only |
| Migration | Cut-pressure-driven partition migration | No automatic migration (manual only) |

The key invariant: the tier engine never calls into the coherence engine directly. It receives scores through the `ResidencyScorer` abstraction, which returns static defaults when the engine is absent.

---

## Bug Surface Warning

Tier transitions + compression + reconstruction + witness replay = large interaction surface. The following discipline is mandatory:

1. **ALL tier transition logic in `tier_engine.rs`**: No other module calls `compress()`, `decompress()`, `promote()`, or `demote()`.
2. **Exhaustive state machine testing**: Every valid tier transition (hot->warm, warm->dormant, dormant->cold, and reverses) has dedicated tests.
3. **Invalid transitions are compile-time errors where possible**: The `promote()` and `demote()` match arms reject invalid transitions (e.g., hot->cold skipping intermediate tiers).
4. **Reconstruction is idempotent**: Applying the same delta set to the same checkpoint always produces the same result. This is verified by property-based testing.
5. **Compression round-trip tests**: For every supported algorithm, `decompress(compress(data)) == data`.
6. **Frame zeroing on free**: Every freed frame is zeroed before return to the free list. This prevents cross-partition information leakage through recycled frames.

---

## Consequences

### Positive

- **Reconstructable state (quiet killer feature)**: No existing hypervisor stores dormant memory as compressed checkpoints with witness-replay reconstruction. This enables memory time travel, dramatically reduces memory pressure on constrained hardware, and makes the dormant tier qualitatively different from traditional swap.
- **Dramatically reduced memory pressure**: On a Seed device with 64 MB RAM, the dormant tier with zstd compression can store 3-5x more partition state than raw pages. This extends the number of partitions the system can support.
- **Coherence-aware placement**: When the coherence engine is active, memory placement decisions understand the coupling structure of the workload. High-cut-value regions stay warm; low-value regions compress to dormant. This is fundamentally better than LRU.
- **DC-1 compliance**: The memory model degrades gracefully to recency-only scoring when the coherence engine is absent. No kernel boot dependency on Layer 2.
- **Rust ownership prevents double-mapping**: `OwnedRegion<P>` with move semantics makes it impossible at the type level to have the same region owned by two partitions simultaneously.

### Negative

- **Compression and reconstruction add latency**: Promoting a dormant region to warm requires decompression + witness replay. Worst case for a large region with many deltas could approach the P3 proof budget (10 ms). This latency must be accounted for in scheduling.
- **Reconstruction correctness depends on witness log integrity**: If the witness log is corrupted or truncated, reconstruction may produce incorrect state. The chained witness hashing (from the security model) mitigates this, but does not eliminate it.
- **Four tiers increase complexity**: Each additional tier adds transition paths, scoring logic, and failure modes. The strict "one module for all transitions" discipline mitigates this but requires vigilant enforcement.
- **Delta log growth**: The witness delta log grows over time. Without periodic re-checkpointing, dormant regions accumulate large delta histories that slow reconstruction. The tier engine must periodically re-checkpoint long-dormant regions.
- **Explicit promotion adds scheduling complexity**: Unlike demand paging where the hardware faults and the OS transparently loads the page, RVM requires the scheduler or coherence engine to explicitly trigger promotion. This shifts complexity from the fault handler to the decision engine.

### Risks

| Risk | Mitigation |
|------|------------|
| Reconstruction produces wrong state due to witness corruption | Chained hash verification before replay; fail-safe: discard corrupted region and restore from cold-tier checkpoint |
| Compression latency spikes on large regions | Bound maximum compressed region size; split large regions before dormant demotion |
| Delta log grows unbounded for long-dormant regions | Re-checkpoint dormant regions when delta count exceeds configurable threshold (default: 1024 deltas) |
| Buddy allocator fragmentation under mixed tier workloads | Per-tier free lists prevent cross-tier fragmentation; compaction pass during recovery mode |
| Coherence engine absence causes all warm regions to evict | Static threshold is calibrated during boot to keep critical system regions warm regardless of scoring |

---

## Testing Strategy

| Category | Tests | Coverage |
|----------|-------|----------|
| Tier transitions | Every valid transition: hot<->warm, warm<->dormant, dormant<->cold; invalid transitions rejected | State machine completeness |
| Reconstruction | Checkpoint + N deltas -> correct state for N in {0, 1, 10, 100, 1000} | Reconstruction correctness |
| Compression round-trip | zstd and lz4: `decompress(compress(data)) == data` for random data, all-zeros, all-ones | Compression correctness |
| Ownership | Move semantics enforced; double-use after transfer is compile error; Drop zeros and frees frames | Rust type system guarantees |
| Scoring | With coherence engine: cut_value + recency drives placement; without: recency only against static threshold | DC-1 compliance |
| Allocator | Buddy alloc/free, coalescing, per-tier isolation, OOM handling, frame zeroing | Allocator correctness |
| Shared regions | Read-only mapping into multiple partitions; write attempt fails; append-only through syscall only | SEC-005 compliance |
| Integration | Full lifecycle: alloc hot -> use -> demote warm -> demote dormant -> promote warm -> verify state identical | End-to-end |
| Property-based | Random tier transitions on random regions; invariant: tier engine never panics, all transitions produce valid state | Robustness |

---

## References

- Agache, A., et al. "Firecracker: Lightweight Virtualization for Serverless Applications." NSDI 2020.
- Boos, K., et al. "Theseus: an Experiment in Operating System Structure and State Management." OSDI 2020.
- Narayanan, V., et al. "RedLeaf: Isolation and Communication in a Safe Operating System." OSDI 2020.
- Knuth, D.E. "The Art of Computer Programming, Vol. 1: Fundamental Algorithms." (Buddy allocation)
- ARM Architecture Reference Manual, AArch64: Stage 1 and Stage 2 Translation.
- Collet, Y. "Zstandard Compression." RFC 8878, 2021.
- RVM security model: `docs/research/ruvm/security-model.md`
- ADR-132: RVM Hypervisor Core
- ADR-135: Proof Verifier Design
