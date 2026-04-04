# ADR-133: Partition Object Model

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-124 (Dynamic Partition Cache), ADR-014 (Coherence Engine)

---

## Context

ADR-132 establishes that RVM replaces the VM abstraction with coherence domains. However, ADR-132 describes the partition as a first-class object only at the architectural level. This ADR specifies the concrete object model: what a partition contains, how it is created and destroyed, how it relates to hardware-enforced isolation, and how its lifecycle operations interact with the proof system and witness log.

### Problem Statement

1. **A partition is not a VM, but the boundaries must be precise**: Without a rigorous object model, implementers will drift toward VM-like abstractions (emulated hardware, guest kernels, BIOS). The partition abstraction must be defined with enough precision that the implementation cannot accidentally become a VMM.
2. **Ownership semantics need type-level enforcement**: Memory regions, capability tables, and communication edges belong to exactly one partition at a time. Transfer must consume the source reference. Rust's move semantics make this enforceable at compile time, but only if the types are designed correctly.
3. **Split and merge are the novel operations**: No existing hypervisor supports live partition splitting along a graph-theoretic cut boundary. The object model must define what happens to every sub-object (tasks, regions, capabilities, edges, leases) during a split or merge.
4. **Partition count must be bounded**: Unbounded partition creation would exhaust page table memory, capability table slots, and witness log bandwidth. The system needs an explicit limit and a clear error path when the limit is reached.
5. **Partition switch latency is a hard target**: ADR-132 specifies < 10 microseconds. The object model must be designed so that a switch involves only TTBR write + TLB invalidation + register restore, not data structure walks or allocation.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| seL4 | CNode-based capability model, formally verified object creation | Capability table structure; RVM adapts CNode to partition scope |
| Xen | Domain as isolation unit, hypercall interface | Historical precedent for domain-based (not process-based) isolation |
| Theseus OS | Rust ownership for OS resource management | Validates move-semantic resource handles in kernel context |
| RedLeaf | Cross-domain isolation via Rust type system | Informs typed region ownership and transfer protocol |
| Firecracker | MicroVM lifecycle (create, pause, resume, snapshot) | Lifecycle state machine comparison; RVM adds split/merge/hibernate |
| RuVector mincut crate | Graph-theoretic minimum cut | Direct dependency for split decisions |

---

## Decision

Define the partition as a first-class kernel object with the following properties.

### 1. Partition is a Coherence Domain Container, Not a VM

A partition has no emulated hardware, no guest BIOS, no virtual device model. It contains:

- **Stage-2 page tables** (ARM VTTBR_EL2 / RISC-V hgatp / x86-64 EPTP): hardware-enforced address translation owned exclusively by the hypervisor
- **Capability table**: scoped set of unforgeable authority tokens granting rights over kernel objects
- **CommEdge set**: communication channels to other partitions (weighted edges in the coherence graph)
- **CoherenceScore**: locality and coupling metric computed by the solver crate
- **CutPressure**: graph-derived isolation signal computed by the mincut crate
- **MemoryRegion set**: typed, tiered memory ranges with move-semantic ownership
- **Task set**: scheduled execution contexts within this domain
- **DeviceLease set**: time-bounded, revocable hardware access grants

A partition is the unit of scheduling, isolation, migration, and fault containment.

### 2. Partition Struct Definition

```rust
// ruvix-partition/src/partition.rs

/// A coherence domain: the fundamental unit of isolation in RVM.
///
/// This is NOT a VM. There is no emulated hardware, no guest kernel,
/// no BIOS. A partition is a container for a set of tasks, memory
/// regions, capabilities, and communication edges that form a
/// self-consistent computational domain.
pub struct Partition {
    id: PartitionId,
    state: PartitionState,

    // Hardware isolation
    stage2: Stage2Tables,

    // Owned sub-objects (move semantics — these do not implement Copy or Clone)
    tasks: BTreeMap<TaskHandle, TaskControlBlock>,
    regions: BTreeMap<RegionHandle, OwnedRegionDescriptor>,
    cap_table: CapabilityTable,
    comm_edges: ArrayVec<CommEdgeHandle, MAX_EDGES_PER_PARTITION>,
    device_leases: ArrayVec<DeviceLease, MAX_DEVICES_PER_PARTITION>,

    // Coherence metrics (read by scheduler, written by coherence engine)
    coherence: CoherenceScore,
    cut_pressure: CutPressure,

    // Witness linkage
    witness_segment: WitnessSegmentHandle,

    // Scheduling metadata
    last_activity_ns: u64,
    cpu_affinity: Option<u32>,
}

/// Maximum partitions system-wide. Bounded by:
/// - Stage-2 page table memory (each partition requires >= 1 root page)
/// - VMID space (ARM: 8-bit = 256, RISC-V: 14-bit = 16384)
/// - Capability table slots in the root CNode
/// - Witness log bandwidth
pub const MAX_PARTITIONS: usize = 256;

/// Maximum communication edges per partition.
pub const MAX_EDGES_PER_PARTITION: usize = 64;

/// Maximum devices per partition.
pub const MAX_DEVICES_PER_PARTITION: usize = 8;
```

### 3. Partition Identity

```rust
/// Partition identity. Unique within a RVM instance.
///
/// The lower 8 bits serve as the VMID for stage-2 TLB tagging on ARM.
/// VMID 0 is reserved for the hypervisor itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PartitionId(u64);

impl PartitionId {
    /// Extract the VMID for hardware use.
    pub fn vmid(&self) -> u16 {
        (self.0 & 0xFF) as u16
    }

    /// The hypervisor's own partition ID (not schedulable).
    pub const HYPERVISOR: Self = Self(0);
}
```

### 4. Partition Lifecycle

```
                     create()
                        |
                        v
    +----------+   resume()   +----------+
    |          |<-------------|          |
    | Running  |              | Suspended|
    |          |------------->|          |
    +----+-----+  suspend()   +-----+----+
         |                          |
         | (cut_pressure            | hibernate()
         |  triggers split)         |
         v                          v
    +----------+             +------------+
    | Splitting|             | Hibernated |
    +----+-----+             +------+-----+
         |                          |
         | yields (A, B)            | reconstruct()
         v                          v
    two new Running          new Running
    partitions               partition


    Running ----- migrate() ----> Migrating ----> Running (on new node)

    any state --- destroy() ----> Terminated (resources freed)
```

**States:**

| State | Description | Memory Tier | Schedulable |
|-------|-------------|-------------|-------------|
| Created | Object allocated, stage-2 tables empty, no tasks | Hot | No |
| Running | Active execution, tasks scheduled | Hot | Yes |
| Suspended | Tasks paused, state in hot memory | Hot | No |
| Migrating | State being transferred to another node | Hot/Warm | No |
| Hibernated | State compressed to dormant/cold storage | Dormant/Cold | No |
| Terminated | Resources freed, ID reclaimable | N/A | No |

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionState {
    Created,
    Running,
    Suspended,
    Migrating,
    Hibernated,
    Terminated,
}
```

The `Splitting` and `Merging` states from the architecture document are transient internal states, not externally observable. A split operation atomically transitions one Running partition into two new Running partitions. A merge atomically transitions two Suspended partitions into one Running partition.

### 5. PartitionOps Trait

```rust
/// Operations on coherence domains.
///
/// Every method requires a ProofToken (P1 or P2 tier) and emits
/// a witness record. No partition mutation is possible without both.
pub trait PartitionOps {
    /// Create a new empty partition.
    ///
    /// Allocates a PartitionId, creates empty stage-2 page tables,
    /// initializes an empty capability table with a root capability
    /// derived from parent_cap.
    ///
    /// Proof tier: P1 (capability check on parent_cap)
    /// Witness: PartitionCreate
    fn create(
        &mut self,
        config: PartitionConfig,
        parent_cap: CapHandle,
        proof: &ProofToken,
    ) -> Result<PartitionId, PartitionError>;

    /// Destroy a partition.
    ///
    /// Partition must be in Suspended or Hibernated state.
    /// Frees all owned regions, revokes all capabilities,
    /// destroys all CommEdges, releases all device leases.
    ///
    /// Proof tier: P2 (policy validation — ownership chain)
    /// Witness: PartitionDestroy
    fn destroy(
        &mut self,
        partition: PartitionId,
        proof: &ProofToken,
    ) -> Result<(), PartitionError>;

    /// Switch execution to a target partition.
    ///
    /// Performs: save current registers -> write TTBR/VTTBR ->
    /// TLBI by VMID -> restore target registers.
    ///
    /// Target: < 10 microseconds.
    ///
    /// Proof tier: P1 (capability check — scheduler holds switch cap)
    /// Witness: none (switch is too hot; witnessed indirectly via
    ///          scheduler epoch records)
    fn switch(
        &mut self,
        from: PartitionId,
        to: PartitionId,
    ) -> Result<(), PartitionError>;

    /// Split a partition along a mincut boundary.
    ///
    /// Takes a Running partition and a CutResult (from the mincut crate).
    /// Creates two new partitions. Tasks, regions, capabilities, and
    /// edges are redistributed according to which side of the cut they
    /// belong to. CommEdges that cross the cut become inter-partition
    /// edges between the two new partitions.
    ///
    /// Proof tier: P2 (policy validation — structural invariants)
    /// Witness: PartitionSplit (records both new IDs and the cut)
    fn split(
        &mut self,
        partition: PartitionId,
        cut: &CutResult,
        proof: &ProofToken,
    ) -> Result<(PartitionId, PartitionId), PartitionError>;

    /// Merge two partitions into one.
    ///
    /// Both partitions must be Suspended. They must share at least
    /// one CommEdge. The merged coherence score must exceed a
    /// configurable threshold (preventing merges that reduce locality).
    ///
    /// Proof tier: P2 (policy validation — merge preconditions)
    /// Witness: PartitionMerge
    fn merge(
        &mut self,
        a: PartitionId,
        b: PartitionId,
        proof: &ProofToken,
    ) -> Result<PartitionId, PartitionError>;

    /// Hibernate a partition.
    ///
    /// Compresses all owned regions to dormant/cold tier.
    /// Releases hot physical memory. Records a reconstruction
    /// receipt in the witness log.
    ///
    /// Proof tier: P2 (policy validation — ownership, no active leases)
    /// Witness: PartitionHibernate
    fn hibernate(
        &mut self,
        partition: PartitionId,
        proof: &ProofToken,
    ) -> Result<ReconstructionReceipt, PartitionError>;

    /// Reconstruct a hibernated partition from its receipt.
    ///
    /// Allocates fresh physical memory, decompresses state,
    /// rebuilds stage-2 tables, re-registers in scheduler.
    ///
    /// Proof tier: P2 (policy validation — receipt authenticity)
    /// Witness: PartitionReconstruct
    fn reconstruct(
        &mut self,
        receipt: &ReconstructionReceipt,
        proof: &ProofToken,
    ) -> Result<PartitionId, PartitionError>;
}
```

### 6. Memory Ownership Model

Partitions own memory regions with move semantics. The `OwnedRegion<P>` type is non-copyable and non-clonable:

```rust
/// A typed, non-copyable memory region handle.
///
/// Move semantics enforce single-owner invariant at compile time.
/// Transfer consumes self, preventing use-after-transfer.
pub struct OwnedRegion<P: RegionPolicy> {
    handle: RegionHandle,
    owner: PartitionId,
    _policy: PhantomData<P>,
}

// OwnedRegion does NOT implement Copy or Clone.
// Transfer is the only way to change ownership:

impl<P: RegionPolicy> OwnedRegion<P> {
    /// Transfer ownership to another partition.
    /// Consumes self. Updates stage-2 tables for both partitions.
    /// Emits RegionTransfer witness.
    pub fn transfer(
        self,  // <-- consumes
        new_owner: PartitionId,
        proof: &ProofToken,
        witness: &mut WitnessLog,
    ) -> Result<OwnedRegion<P>, PartitionError> {
        witness.record(WitnessRecord::region_transfer(
            self.handle, self.owner, new_owner, proof.tier(),
        ));
        Ok(OwnedRegion {
            handle: self.handle,
            owner: new_owner,
            _policy: PhantomData,
        })
    }
}
```

During a split, regions are redistributed based on which side of the cut their owning tasks fall on. Each region moves to exactly one of the two new partitions. No region is duplicated.

### 7. Split and Merge Operations

**Split preconditions (P2 policy validation):**

1. Partition is in Running state
2. CutResult was computed within the current epoch (not stale beyond configurable threshold)
3. Both sides of the cut contain at least one task
4. The partition holds a capability with SPLIT right
5. System partition count < MAX_PARTITIONS - 1 (need two new slots)

**Split procedure:**

1. Suspend all tasks in the partition
2. Allocate two new PartitionIds and stage-2 table roots
3. For each task: assign to side_a or side_b based on the CutResult membership
4. For each region: assign to the side that owns the majority of its accessing tasks (tie-break: side_a)
5. For each capability: duplicate into both new capability tables (capabilities are not exclusive)
6. For each CommEdge: if both endpoints are on the same side, move the edge; if endpoints span the cut, the edge becomes an inter-partition edge between the two new partitions
7. Compute fresh CoherenceScore and CutPressure for both new partitions
8. Emit PartitionSplit witness record
9. Destroy the original partition
10. Transition both new partitions to Running

**Merge preconditions (P2 policy validation):**

1. Both partitions are in Suspended state
2. At least one CommEdge connects them
3. Predicted merged coherence score exceeds `merge_coherence_threshold`
4. Both partitions hold capabilities with MERGE right
5. Combined task count does not exceed per-partition task limit
6. System partition count >= 2 (cannot merge the last partition)

### 8. Partition-to-Graph Mapping

Each partition is a node in the coherence graph. CommEdges are weighted edges:

```
Coherence Graph:

  [Partition A] ----(w=1200)---- [Partition B]
       |                              |
       |  (w=50)                      | (w=800)
       |                              |
  [Partition C] ----(w=300)----- [Partition D]

Edge weight = accumulated message bytes, decayed per epoch.
Mincut identifies the cheapest set of edges to sever.
```

The PressureEngine maintains this graph and runs the mincut crate within the DC-2 time budget (50 microseconds per epoch). The resulting CutPressure on each partition informs both the scheduler (cut_pressure_boost) and the structural change evaluator (split/merge triggers).

### 9. Partition Switch Performance

The switch path is the hottest code in the system. It must complete in < 10 microseconds:

```
switch(from, to):
  1. Save from's general-purpose registers to TCB    (~50 ns)
  2. Save from's system registers (SP_EL1, ELR_EL1)  (~20 ns)
  3. Write VTTBR_EL2 with to's stage-2 root + VMID   (~10 ns)
  4. TLBI VMID (invalidate from's TLB entries)        (~1-5 us, arch-dependent)
  5. Restore to's system registers                    (~20 ns)
  6. Restore to's general-purpose registers            (~50 ns)
  7. ERET to to's execution context                    (~10 ns)
```

No witness is emitted on the switch hot path. Partition switches are witnessed indirectly through scheduler epoch records (WitnessRecordKind::StructuralChange), which log scheduling decisions in bulk.

### 10. PartitionManager

```rust
/// Manages the system-wide set of partitions.
pub struct PartitionManager {
    /// Active partitions, indexed by PartitionId.
    partitions: BTreeMap<PartitionId, Partition>,

    /// Free VMID pool.
    vmid_pool: BitSet<256>,

    /// Next PartitionId sequence number.
    next_id: u64,

    /// Root capability for partition creation authority.
    root_cap: CapHandle,
}

impl PartitionManager {
    /// Current partition count.
    pub fn count(&self) -> usize {
        self.partitions.len()
    }

    /// Whether a new partition can be created.
    pub fn can_create(&self) -> bool {
        self.count() < MAX_PARTITIONS && self.vmid_pool.any_set()
    }
}
```

### 11. Each Partition Has Its Own TTBR

On AArch64, each partition's stage-2 tables are activated by writing VTTBR_EL2:

```rust
/// Activate this partition's stage-2 address space.
///
/// After this call, all EL1/EL0 memory accesses go through
/// this partition's stage-2 translation tables.
pub unsafe fn activate_stage2(partition: &Partition) {
    let vttbr = partition.stage2.root_phys_addr()
        | ((partition.id.vmid() as u64) << 48);
    core::arch::asm!(
        "msr vttbr_el2, {v}",
        "isb",
        v = in(reg) vttbr,
    );
}
```

On RISC-V the equivalent is writing `hgatp`. On x86-64 the equivalent is loading the EPTP into the VMCS.

---

## Consequences

### Positive

- **Fine-grained agent isolation**: Partitions are lighter than VMs (no emulated hardware, no guest kernel). Multiple agents can run in separate partitions with hardware-enforced isolation at sub-10-microsecond switch cost.
- **Split/merge enables dynamic restructuring**: When the coherence graph changes (agents start communicating more or less), the system can restructure its isolation boundaries to match. No existing hypervisor offers this.
- **Move-semantic ownership eliminates use-after-free**: The `OwnedRegion<P>` type makes it impossible to access a transferred region from the old owner. This is a compile-time guarantee, not a runtime check.
- **Bounded partition count prevents resource exhaustion**: The explicit MAX_PARTITIONS limit and VMID pool ensure that page table memory, capability table slots, and witness log bandwidth are always bounded.
- **Clear degradation story**: If the coherence engine is absent (DC-1), partitions still work. They just do not split, merge, or migrate based on graph pressure. The partition object model does not depend on the coherence engine.

### Negative

- **Higher complexity than a simple process model**: Partitions with split/merge, tiered memory, and graph-derived metrics are conceptually more complex than Unix processes or Xen domains. Developer onboarding requires understanding the coherence domain concept.
- **Split redistributes state non-trivially**: Deciding which regions belong to which side of a cut is not always obvious (what if a region is accessed by tasks on both sides?). The tie-breaking rule (majority accessor, then side_a) is simple but may not be optimal in all cases.
- **MAX_PARTITIONS limits scale**: 256 partitions (constrained by ARM VMID width) may be insufficient for very large agent deployments. Mitigation: VMID recycling for hibernated partitions, and future hardware with wider VMID spaces.
- **Switch witness gap**: Not witnessing individual partition switches means the audit trail has epoch-granularity gaps for scheduling decisions. This is an acceptable tradeoff for < 10 microsecond switch latency, but auditors must be aware of the gap.

---

## Rejected Alternatives

| Alternative | Reason for Rejection |
|-------------|---------------------|
| **VM-style partition with emulated devices** | Defeats the purpose of the coherence domain abstraction. Adds emulation overhead. Makes split/merge impossible (cannot split emulated hardware state). |
| **Unbounded partition count** | Exhausts VMID space, page table memory, and witness log bandwidth. A system that can create partitions without bound will eventually OOM in the kernel. |
| **Copy-semantic region handles** | Allows aliased ownership, which defeats the single-owner invariant. Two partitions holding the same region handle can mutate concurrently, violating isolation. |
| **Witness on every switch** | At 64 bytes per witness and potentially thousands of switches per second, this would consume witness log bandwidth and add latency to the hot path. Epoch-level scheduler witnesses are sufficient. |
| **Lazy split (copy-on-write between halves)** | Adds a fault handler to the critical path. Violates the no-demand-paging design principle (Section 4.5 of the architecture document). Explicit region redistribution is simpler and deterministic. |

---

## References

- Barham, P., et al. "Xen and the Art of Virtualization." SOSP 2003.
- Klein, G., et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009.
- Boos, K., et al. "Theseus: an Experiment in Operating System Structure and State Management." OSDI 2020.
- Narayanan, V., et al. "RedLeaf: Isolation and Communication in a Safe Operating System." OSDI 2020.
- Agache, A., et al. "Firecracker: Lightweight Virtualization for Serverless Applications." NSDI 2020.
- ARM Architecture Reference Manual, Chapter D5: Stage 2 Translation.
- ADR-132: RVM Hypervisor Core.
- RuVector mincut crate: `crates/mincut/`
