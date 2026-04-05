# Memory Model: Four Tiers and Time Travel

RVM does not use demand paging. Every tier transition is explicit, driven by coherence scores and residency rules. Memory lives in one of four tiers at all times, and any historical state can be perfectly reconstructed from a checkpoint plus the witness delta log.

This chapter covers the four-tier model, the buddy allocator, memory regions, address translation, and the reconstruction pipeline.

---

## 1. The Four-Tier Model

```
                 +-----------------------+
    Tier 0       |        HOT            |   Per-core SRAM / L1-adjacent
    (always      |   Always resident     |   Fastest access, smallest capacity
     resident)   |   during execution    |
                 +-----------+-----------+
                             |
                     explicit promote / demote
                             |
                 +-----------+-----------+
    Tier 1       |        WARM           |   Shared DRAM
    (resident    |   Resident if         |   Resident when residency rule is met:
     if rule     |   residency rule met  |     cut_value + recency_score > threshold
     met)        +-----------+-----------+
                             |
                     explicit promote / demote
                             |
                 +-----------+-----------+
    Tier 2       |       DORMANT         |   Compressed checkpoint + delta
    (compressed) |   Stored as snapshot  |   Reconstructed on demand
                 |   + witness deltas    |   Not raw bytes -- structured data
                 +-----------+-----------+
                             |
                     explicit promote / demote
                             |
                 +-----------+-----------+
    Tier 3       |        COLD           |   Persistent archival (RVF-backed)
    (archival)   |   Accessed only       |   Never auto-promoted
                 |   during recovery     |   Explicit restore only
                 +-----------------------+
```

Key properties:

- **All transitions are explicit.** There is no page fault handler that silently promotes memory. The tier manager decides when to move a region, and the move is a witnessed operation.
- **Coherence drives placement.** High coherence score means the region is actively used by communicating agents -- keep it hot. Low coherence means it can safely go dormant.
- **Dormant is not deleted.** Tier 2 stores a compressed checkpoint plus a sequence of witness deltas. The original state can be perfectly reconstructed at any time.
- **Cold is archival.** Tier 3 is for long-term storage on persistent media. It is accessed only during recovery or explicit restore operations. Cold regions are never automatically promoted.

The `Tier` enum in `rvm-memory/src/tier.rs`:

```rust
pub enum Tier {
    Hot     = 0,   // per-core SRAM / L1-adjacent
    Warm    = 1,   // cluster-shared DRAM
    Dormant = 2,   // compressed checkpoint + delta
    Cold    = 3,   // persistent archival
}
```

## 2. TierManager

The `TierManager` in `rvm-memory/src/tier.rs` governs tier placement. It uses a residency rule:

```
cut_value + recency_score > eviction_threshold
```

When the coherence engine is absent (DC-1 degraded mode), `cut_value` defaults to zero and only `recency_score` drives placement.

**`TierThresholds`** configures the transition points. All values are in basis points (0 to 10,000):

```rust
pub struct TierThresholds {
    pub hot_to_warm: u16,          // below this -> demote Hot to Warm
    pub warm_to_dormant: u16,      // below this -> demote Warm to Dormant
    pub dormant_to_cold: u16,      // below this -> demote Dormant to Cold
    pub warm_to_hot: u16,          // above this -> promote Warm to Hot
    pub dormant_to_warm: u16,      // above this -> promote Dormant to Warm
}
```

The conservative defaults (`TierThresholds::DEFAULT`) for DC-1 mode:

| Transition | Threshold |
|------------|-----------|
| Hot to Warm | 7,000 (70%) |
| Warm to Dormant | 4,000 (40%) |
| Dormant to Cold | 1,000 (10%) |
| Warm to Hot | 8,000 (80%) |
| Dormant to Warm | 5,000 (50%) |

Notice the hysteresis: promoting Warm to Hot requires 80%, but demoting Hot to Warm triggers at 70%. This prevents oscillation at the boundary.

**`RegionTierState`** tracks the current tier for each memory region, indexed by `OwnedRegionId`. The tier manager maintains this mapping and updates it when a region is promoted or demoted.

## 3. The Buddy Allocator

`BuddyAllocator` in `rvm-memory/src/allocator.rs` handles physical page allocation. It is a classic power-of-two buddy allocator with these design constraints:

- **`#![no_std]` compatible** -- no heap allocation. The entire bitmap is stack-allocated.
- **`#![forbid(unsafe_code)]`** -- fully safe Rust.
- **`PAGE_SIZE = 4096`** bytes (4 KiB).
- **Maximum order: 10** -- the largest single allocation is 2^10 = 1,024 pages = 4 MiB.

The allocator is parameterized by two const generics:

```rust
pub struct BuddyAllocator<const TOTAL_PAGES: usize, const BITMAP_WORDS: usize>
```

- `TOTAL_PAGES` -- how many 4 KiB pages the allocator manages (must be a power of two)
- `BITMAP_WORDS` -- the number of `u64` words in the allocation bitmap. Use `BuddyAllocator::REQUIRED_BITMAP_WORDS` to compute this.

**Creating an allocator:**

```rust
// Manage 256 pages (1 MiB) starting at physical address 0x1000_0000.
type Alloc = BuddyAllocator<256, 16>;
let mut alloc = Alloc::new(PhysAddr::new(0x1000_0000))?;
```

The base address must be page-aligned. All blocks start as free at the highest usable order.

**Allocating pages:**

```rust
let addr = alloc.alloc_pages(0)?;  // 1 page (4 KiB)
let addr = alloc.alloc_pages(2)?;  // 4 pages (16 KiB)
let addr = alloc.alloc_pages(8)?;  // 256 pages (1 MiB)
```

If no block of the requested size is free, the allocator splits a larger block. If no larger block exists either, it returns `OutOfMemory`.

**Freeing pages:**

```rust
alloc.free_pages(addr, 0)?;  // free a 1-page block
```

Freed blocks are automatically coalesced with their buddy. If both halves of a pair are free, they merge into a single block at the next order up. This continues recursively until no further merging is possible.

The allocator detects double-frees: attempting to free an already-free block returns `InternalError`.

**Free count:**

```rust
let free = alloc.free_page_count();  // total free pages across all orders
```

Internally, the allocator uses `trailing_zeros` on bitmap words for fast first-free-block scanning -- O(1) per 64-bit word instead of checking bit by bit. Pre-computed cumulative bit offsets give O(1) level indexing.

## 4. Memory Regions

A `MemoryRegion` in `rvm-memory/src/lib.rs` describes a contiguous mapping from guest physical address space to host physical address space:

```rust
pub struct MemoryRegion {
    pub guest_base: GuestPhysAddr,     // guest physical base (page-aligned)
    pub host_base: PhysAddr,           // host physical base (page-aligned)
    pub page_count: usize,             // number of 4 KiB pages
    pub permissions: MemoryPermissions,
    pub owner: PartitionId,
}
```

**Permissions** are defined by `MemoryPermissions`:

| Constant | Read | Write | Execute |
|----------|------|-------|---------|
| `READ_ONLY` | yes | no | no |
| `READ_WRITE` | yes | yes | no |
| `READ_EXECUTE` | yes | no | yes |

**Validation:** `validate_region()` checks three conditions:

1. Both `guest_base` and `host_base` must be page-aligned (`AlignmentError`)
2. `page_count` must be non-zero (`ResourceLimitExceeded`)
3. At least one permission bit must be set (`Unsupported`)

**Overlap detection:** Two functions check for dangerous overlaps:

- **`regions_overlap(a, b)`** -- checks guest-physical overlap within the same partition. Regions in different partitions have separate guest address spaces, so cross-partition guest overlap is not a conflict.

- **`regions_overlap_host(a, b)`** -- checks host-physical overlap across all partitions. This is a **critical security check**: two partitions mapping the same host physical pages would break isolation entirely. One partition could read or write another's memory.

## 5. Region Manager

`RegionManager` in `rvm-memory/src/region.rs` maintains a fixed-capacity table of `OwnedRegion` entries. It extends the basic `MemoryRegion` concept with tier metadata and lifecycle management.

**`OwnedRegion`** adds tier tracking:

```rust
pub struct OwnedRegion {
    pub id: OwnedRegionId,
    pub owner: PartitionId,
    pub guest_base: GuestPhysAddr,
    pub host_base: PhysAddr,
    pub page_count: u32,
    pub tier: Tier,                    // Hot | Warm | Dormant | Cold
    pub permissions: MemoryPermissions,
}
```

**`RegionConfig`** is the creation descriptor:

```rust
pub struct RegionConfig {
    pub id: OwnedRegionId,
    pub owner: PartitionId,
    pub guest_base: GuestPhysAddr,
    pub host_base: PhysAddr,
    pub page_count: u32,
    pub tier: Tier,
    pub permissions: MemoryPermissions,
}
```

**Key operations on `RegionManager<MAX>`:**

| Operation | Description |
|-----------|-------------|
| `create(config)` | Create a region. Validates alignment, non-zero page count, and rejects overlaps (guest-physical within same partition, host-physical across all partitions). |
| `create_auto_id(owner, guest, host, pages, tier, perms)` | Same as `create` but auto-assigns a monotonically increasing `OwnedRegionId`. |
| `destroy(region_id)` | Remove a region and return it. Frees the slot for reuse. |
| `transfer(region_id, new_owner)` | Move ownership to a different partition. The guest mapping stays the same. Rejects if the new owner has an overlapping region. |
| `get(region_id)` / `get_mut(region_id)` | Look up a region by ID. |
| `translate(owner, guest_addr)` | Translate a guest physical address to a host physical address within the given partition. Returns an `AddressMapping` with the host address and permissions. |
| `count_for_partition(owner)` | Count regions owned by a partition. |
| `regions_for_partition(owner, out)` | Write matching region IDs into a caller-provided buffer. |

**`AddressMapping`** is the result of address translation:

```rust
pub struct AddressMapping {
    pub guest: GuestPhysAddr,
    pub host: PhysAddr,
    pub permissions: MemoryPermissions,
}
```

The host-physical overlap check in `create()` is the critical isolation enforcement point. It runs across all partitions regardless of ownership. Without it, a malicious partition could map the same physical memory as another partition and read its secrets.

## 6. Memory Time Travel (Reconstruction)

Dormant memory (Tier 2) is not stored as raw bytes. It is stored as a **compressed checkpoint** plus a sequence of **witness deltas**. To restore a dormant region, the reconstruction pipeline:

1. Loads the checkpoint (compressed snapshot at a known-good state)
2. Applies the witness delta log in sequence order
3. Validates the final state hash against the expected value

This means any historical state can be perfectly rebuilt on demand -- days or weeks after the region went dormant.

**`CompressedCheckpoint`** in `rvm-memory/src/reconstruction.rs`:

```rust
pub struct CompressedCheckpoint {
    pub id: CheckpointId,
    pub region_id: OwnedRegionId,
    pub witness_sequence: u64,    // witness log position at checkpoint time
    pub uncompressed_hash: u64,   // FNV-1a hash for integrity verification
    pub uncompressed_size: u32,
    pub compressed_size: u32,
}
```

**`WitnessDelta`** represents a single write operation recorded in the witness log:

```rust
pub struct WitnessDelta {
    pub sequence: u64,    // position in the witness log
    pub offset: u32,      // byte offset within the region
    pub length: u16,      // bytes written
    pub data_hash: u64,   // FNV-1a hash of the written data
}
```

**`ReconstructionPipeline<MAX_DELTAS>`** orchestrates the reconstruction:

1. Buffer the relevant witness deltas (up to `MAX_DELTAS` at a time)
2. Decompress the checkpoint into a caller-provided buffer
3. Apply each delta in sequence order
4. Compute the hash of the final state and verify it

**`ReconstructionResult`** reports what happened:

```rust
pub struct ReconstructionResult {
    pub region_id: OwnedRegionId,
    pub size_bytes: u32,
    pub deltas_applied: u32,
    pub final_hash: u64,
}
```

The reconstruction pipeline uses no heap allocation. All buffers are caller-provided with fixed sizes. In production, checkpoint compression would use LZ4 or a hardware compression engine; the current implementation uses a byte-level compression stub that is correct but not optimized.

**`create_checkpoint()`** creates a new checkpoint for a region, capturing its current state as a compressed snapshot with integrity hash.

The witness deltas that feed reconstruction come from the same witness trail that records all mutations in the system. For details on how witness records are structured, signed, and chained, see [Witness and Audit](06-witness-audit.md). For advanced reconstruction scenarios including cross-partition state recovery, see [Advanced: Memory Time Travel](13-advanced-exotic.md).

## 7. Address Types

RVM uses strongly-typed address wrappers to prevent accidental mixing of address spaces. All are defined in `rvm-types/src/addr.rs`:

**`GuestPhysAddr`** -- a guest physical address, scoped to a partition. Each partition has its own guest physical address space isolated by stage-2 page tables.

```rust
pub struct GuestPhysAddr(u64);
impl GuestPhysAddr {
    pub const fn new(addr: u64) -> Self;
    pub const fn as_u64(self) -> u64;
    pub const fn is_page_aligned(self) -> bool;   // 4 KiB alignment
}
```

**`PhysAddr`** -- a host physical address. This is the actual hardware address.

```rust
pub struct PhysAddr(u64);
impl PhysAddr {
    pub const fn new(addr: u64) -> Self;
    pub const fn as_u64(self) -> u64;
    pub const fn is_page_aligned(self) -> bool;
    pub const fn page_align_down(self) -> Self;   // round down to 4 KiB boundary
}
```

**`VirtAddr`** -- a host virtual address, used within the hypervisor's own address space.

```rust
pub struct VirtAddr(u64);
impl VirtAddr {
    pub const fn new(addr: u64) -> Self;
    pub const fn as_u64(self) -> u64;
}
```

All three types are `#[repr(transparent)]` wrappers around `u64` with no runtime overhead. The type system prevents you from accidentally passing a guest physical address where a host physical address is expected -- a class of bug that has caused real hypervisor security vulnerabilities.

---

## Cross-References

| Topic | Chapter |
|-------|---------|
| How partitions own memory regions | [Partitions and Scheduling](07-partitions-scheduling.md) |
| Witness records that feed reconstruction deltas | [Witness and Audit](06-witness-audit.md) |
| WASM agent memory quotas | [WASM Agents](09-wasm-agents.md) |
| Stage-2 page tables and VTTBR_EL2 | [Bare Metal](12-bare-metal.md) |
| Coherence-driven tier placement | [Core Concepts](02-core-concepts.md) |
| Advanced reconstruction scenarios | [Advanced and Exotic](13-advanced-exotic.md) |
| Security implications of host-physical overlap | [Security](10-security.md) |
| Benchmark results for buddy allocator | [Performance](11-performance.md) |
| Full API reference for `rvm-memory` | [Crate Reference](04-crate-reference.md) |
