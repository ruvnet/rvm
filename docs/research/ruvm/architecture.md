# RVM Microhypervisor Architecture

## Status

Draft -- 2026-04-04

## Abstract

RVM is a Rust-first bare-metal microhypervisor that replaces the VM abstraction with **coherence domains** (partitions). It runs standalone without Linux or KVM, targeting QEMU virt as the reference platform with paths to real hardware on AArch64, RISC-V, and x86-64. The hypervisor integrates RuVector's `mincut`, `sparsifier`, and `solver` crates as first-class subsystems driving placement, isolation, and scheduling decisions.

This document covers the full system architecture from reset vector to agent runtime.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Boot Sequence](#2-boot-sequence)
3. [Core Kernel Objects](#3-core-kernel-objects)
4. [Memory Architecture](#4-memory-architecture)
5. [Scheduler Design](#5-scheduler-design)
6. [IPC Design](#6-ipc-design)
7. [Device Model](#7-device-model)
8. [Witness Subsystem](#8-witness-subsystem)
9. [Agent Runtime Layer](#9-agent-runtime-layer)
10. [Hardware Abstraction](#10-hardware-abstraction)
11. [Integration with RuVector](#11-integration-with-ruvector)
12. [What Makes RVM Different](#12-what-makes-ruvix-different)

---

## 1. Design Principles

### 1.1 Not a VM, Not a Container -- a Coherence Domain

Traditional hypervisors (KVM, Xen, Firecracker) virtualize hardware to run guest operating systems. Traditional containers (Docker, gVisor) share a host kernel with namespace isolation. RVM does neither.

A RVM **partition** is a coherence domain: a set of memory regions, capabilities, communication edges, and scheduled tasks that form a self-consistent unit of computation. Partitions are not VMs -- they have no emulated hardware, no guest kernel, no BIOS. They are not containers -- there is no host kernel to share. The hypervisor is the kernel.

The unit of isolation is defined by the graph structure of partition communication, not by hardware virtualization features. A mincut of the communication graph reveals the natural fault isolation boundary. This is a fundamentally different model.

### 1.2 Core Invariants

These invariants hold for every operation in the system:

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| INV-1 | No mutation without proof | `ProofGate<T>` at type level, 3-tier verification |
| INV-2 | No access without capability | Capability table checked on every syscall |
| INV-3 | Every privileged action is witnessed | Append-only witness log, no opt-out |
| INV-4 | No unbounded allocation in syscall path | Pre-allocated structures, slab allocators |
| INV-5 | No priority inversion | Capability-based access prevents blocking on unheld resources |
| INV-6 | Reconstruction from witness + dormant state | Deterministic replay from checkpoint + log |

### 1.3 Crate Dependency DAG

```
ruvix-types          (no_std, #![forbid(unsafe_code)])
    |
    +-- ruvix-cap    (capability manager, derivation trees)
    |       |
    +-------+-- ruvix-proof    (3-tier proof engine)
    |       |
    +-------+-- ruvix-region   (typed memory with ownership)
    |       |
    +-------+-- ruvix-queue    (io_uring-style IPC)
    |       |
    +-------+-- ruvix-sched    (graph-pressure scheduler)
    |       |
    +-------+-- ruvix-vecgraph (kernel-resident vector/graph)
    |
    +-- ruvix-hal              (HAL traits, platform-agnostic)
    |       |
    |       +-- ruvix-aarch64  (ARM boot, MMU, exceptions)
    |       +-- ruvix-riscv    (RISC-V boot, MMU, exceptions)  [Phase C]
    |       +-- ruvix-x86_64   (x86 boot, VMX, exceptions)     [Phase D]
    |
    +-- ruvix-physmem          (buddy allocator)
    +-- ruvix-dtb              (device tree parser)
    +-- ruvix-drivers          (PL011, GIC, timer)
    +-- ruvix-dma              (DMA engine)
    +-- ruvix-net              (virtio-net)
    +-- ruvix-witness          (witness log + replay)       [NEW]
    +-- ruvix-partition        (coherence domain manager)   [NEW]
    +-- ruvix-commedge         (partition communication)    [NEW]
    +-- ruvix-pressure         (mincut integration)         [NEW]
    +-- ruvix-agent            (WASM agent runtime)         [NEW]
    |
    +-- ruvix-nucleus          (integration, syscall dispatch)
```

---

## 2. Boot Sequence

RVM boots directly from the reset vector with no dependency on any existing OS, bootloader, or hypervisor. The sequence is identical in structure across architectures, with platform-specific assembly stubs.

### 2.1 Stage 0: Reset Vector (Assembly)

The CPU begins execution at the platform-defined reset vector. A minimal assembly stub performs the operations that cannot be expressed in Rust.

**AArch64 (EL2 entry for hypervisor mode):**

```asm
// ruvix-aarch64/src/boot.S
.section .text.boot
.global _start

_start:
    // On QEMU virt, firmware drops us at EL2 (hypervisor mode)
    // x0 = DTB address

    // 1. Check we are at EL2
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    cmp     x1, #2
    b.ne    _wrong_el

    // 2. Disable MMU, caches (clean state)
    mrs     x1, sctlr_el2
    bic     x1, x1, #1         // M=0: MMU off
    bic     x1, x1, #(1 << 2)  // C=0: data cache off
    bic     x1, x1, #(1 << 12) // I=0: instruction cache off
    msr     sctlr_el2, x1
    isb

    // 3. Set up exception vector table
    adr     x1, _exception_vectors_el2
    msr     vbar_el2, x1

    // 4. Initialize stack pointer
    adr     x1, _stack_top
    mov     sp, x1

    // 5. Clear BSS
    adr     x1, __bss_start
    adr     x2, __bss_end
.Lbss_clear:
    cmp     x1, x2
    b.ge    .Lbss_done
    str     xzr, [x1], #8
    b       .Lbss_clear
.Lbss_done:

    // 6. x0 still holds DTB address -- pass to Rust
    bl      ruvix_entry

    // Should never return
    b       .

_wrong_el:
    // If at EL1, attempt to elevate via HVC (QEMU-specific)
    // If at EL3, configure EL2 and eret
    // ...
```

**RISC-V (HS-mode entry):**

```asm
// ruvix-riscv/src/boot.S
.section .text.boot
.global _start

_start:
    // a0 = hart ID, a1 = DTB address
    // QEMU starts in M-mode; OpenSBI transitions to S-mode
    // We need HS-mode (hypervisor extension)

    // 1. Check for hypervisor extension
    csrr    t0, misa
    andi    t0, t0, (1 << 7)   // 'H' bit
    beqz    t0, _no_hypervisor

    // 2. Park non-boot harts
    bnez    a0, _park

    // 3. Set up stack
    la      sp, _stack_top

    // 4. Clear BSS
    la      t0, __bss_start
    la      t1, __bss_end
1:  bge     t0, t1, 2f
    sd      zero, (t0)
    addi    t0, t0, 8
    j       1b
2:

    // 5. Enter Rust (a0=hart_id, a1=dtb)
    call    ruvix_entry

_park:
    wfi
    j       _park
```

**x86-64 (VMX root mode):**

```asm
; ruvix-x86_64/src/boot.asm
; Entered from a multiboot2-compliant loader or direct long mode setup
; eax = multiboot2 magic, ebx = info struct pointer

section .text.boot
global _start
bits 64

_start:
    ; 1. Already in long mode (64-bit) from bootloader
    ; 2. Enable VMX if supported
    mov     ecx, 0x3A          ; IA32_FEATURE_CONTROL MSR
    rdmsr
    test    eax, (1 << 2)      ; VMXON outside SMX
    jz      _no_vmx

    ; 3. Set up stack
    lea     rsp, [_stack_top]

    ; 4. Clear BSS
    lea     rdi, [__bss_start]
    lea     rcx, [__bss_end]
    sub     rcx, rdi
    shr     rcx, 3
    xor     eax, eax
    rep     stosq

    ; 5. rdi = multiboot info pointer
    mov     rdi, rbx
    call    ruvix_entry

    hlt
    jmp     $
```

### 2.2 Stage 1: Rust Entry and Hardware Detection

The assembly stub hands off to a single Rust entry point. This function is `#[no_mangle]` and `extern "C"`, receiving the DTB/multiboot pointer.

```rust
// ruvix-nucleus/src/entry.rs

/// Unified Rust entry point. Platform stubs call this after basic setup.
/// `platform_info` is a DTB address (AArch64/RISC-V) or multiboot2 info
/// pointer (x86-64).
#[no_mangle]
pub extern "C" fn ruvix_entry(platform_info: usize) -> ! {
    // Phase 1: Hardware detection
    let hw = HardwareInfo::detect(platform_info);

    // Phase 2: Early serial for diagnostics
    let mut console = hw.early_console();
    console.write_str("RVM v0.1.0 booting\n");
    console.write_fmt(format_args!(
        "  arch={}, cores={}, ram={}MB\n",
        hw.arch_name(), hw.core_count(), hw.ram_bytes() >> 20
    ));

    // Phase 3: Physical memory allocator
    let mut phys = PhysicalAllocator::new(&hw.memory_regions);

    // Phase 4: MMU / page table setup
    let mut mmu = hw.init_mmu(&mut phys);

    // Phase 5: Hypervisor mode configuration
    hw.init_hypervisor_mode(&mut mmu);

    // Phase 6: Interrupt controller
    let mut irq = hw.init_interrupt_controller();

    // Phase 7: Timer
    let timer = hw.init_timer(&mut irq);

    // Phase 8: Kernel subsystem initialization
    let kernel = Kernel::init(KernelInit {
        phys: &mut phys,
        mmu: &mut mmu,
        irq: &mut irq,
        timer: &timer,
        console: &mut console,
    });

    // Phase 9: Load boot RVF and start first partition
    kernel.load_boot_rvf_and_start();

    // Phase 10: Enter scheduler (never returns)
    kernel.scheduler_loop()
}
```

### 2.3 Stage 2: MMU and Hypervisor Mode

The critical distinction from a traditional kernel: RVM runs in hypervisor privilege level, not kernel level.

| Architecture | RVM Level | Guest (Partition) Level | What This Means |
|-------------|-------------|------------------------|-----------------|
| AArch64 | EL2 | EL1/EL0 | RVM controls stage-2 page tables; partitions get full EL1 page tables if needed |
| RISC-V | HS-mode | VS-mode/VU-mode | Hypervisor extension controls guest physical address translation |
| x86-64 | VMX root | VMX non-root | EPT (Extended Page Tables) provide second-level address translation |

Running at the hypervisor level provides two key advantages over running at kernel level (EL1/Ring 0):

1. **Two-stage address translation**: The hypervisor controls the mapping from guest-physical to host-physical addresses. Partitions can have their own page tables (stage-1) while the hypervisor enforces isolation via stage-2 tables. This is strictly more powerful than single-stage translation.

2. **Trap-and-emulate without paravirtualization**: The hypervisor can trap on specific instructions (WFI, MSR, MMIO access) without requiring the partition to be aware it is virtualized. This is essential for running unmodified WASM runtimes.

**Stage-2 page table setup (AArch64):**

```rust
// ruvix-aarch64/src/stage2.rs

/// Stage-2 translation table for a partition.
///
/// Maps Intermediate Physical Addresses (IPA) produced by the partition's
/// stage-1 tables to actual Physical Addresses (PA). The hypervisor
/// controls this mapping exclusively.
pub struct Stage2Tables {
    /// Level-0 table base (4KB aligned)
    root: PhysAddr,
    /// Physical pages backing the table structure
    pages: ArrayVec<PhysAddr, 512>,
    /// IPA range assigned to this partition
    ipa_range: Range<u64>,
}

impl Stage2Tables {
    /// Create stage-2 tables for a partition with the given IPA range.
    ///
    /// The IPA range defines the partition's "view" of physical memory.
    /// All accesses outside this range trap to the hypervisor.
    pub fn new(
        ipa_range: Range<u64>,
        phys: &mut PhysicalAllocator,
    ) -> Result<Self, HypervisorError> {
        let root = phys.allocate_page()?;
        // Zero the root table
        unsafe { core::ptr::write_bytes(root.as_mut_ptr::<u8>(), 0, PAGE_SIZE) };

        Ok(Self {
            root,
            pages: ArrayVec::new(),
            ipa_range,
        })
    }

    /// Map an IPA to a PA with the given attributes.
    ///
    /// Enforces that the IPA falls within the partition's assigned range.
    pub fn map(
        &mut self,
        ipa: u64,
        pa: PhysAddr,
        attrs: Stage2Attrs,
        phys: &mut PhysicalAllocator,
    ) -> Result<(), HypervisorError> {
        if !self.ipa_range.contains(&ipa) {
            return Err(HypervisorError::IpaOutOfRange);
        }
        // Walk/allocate 4-level table and install entry
        self.walk_and_install(ipa, pa, attrs, phys)
    }

    /// Activate these tables for the current vCPU.
    ///
    /// Writes VTTBR_EL2 with the table base and VMID.
    pub unsafe fn activate(&self, vmid: u16) {
        let vttbr = self.root.as_u64() | ((vmid as u64) << 48);
        core::arch::asm!(
            "msr vttbr_el2, {val}",
            "isb",
            val = in(reg) vttbr,
        );
    }
}

/// Stage-2 page attributes.
#[derive(Debug, Clone, Copy)]
pub struct Stage2Attrs {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Device memory (non-cacheable, strongly ordered)
    pub device: bool,
}
```

### 2.4 Stage 3: Capability Table and Kernel Object Initialization

After the MMU is active and hypervisor mode is configured, the kernel initializes its object tables:

```rust
// ruvix-nucleus/src/init.rs

impl Kernel {
    pub fn init(init: KernelInit) -> Self {
        // 1. Capability manager with root capability
        let mut cap_mgr: CapabilityManager<4096> =
            CapabilityManager::new(CapManagerConfig::default());

        // 2. Region manager backed by physical allocator
        let region_mgr = RegionManager::new_baremetal(init.phys);

        // 3. Queue manager (pre-allocate ring buffer pool)
        let queue_mgr = QueueManager::new(init.phys, 256); // 256 queues max

        // 4. Proof engine
        let proof_engine = ProofEngine::new(ProofEngineConfig::default());

        // 5. Witness log (append-only, physically backed)
        let witness_log = WitnessLog::new(init.phys, WITNESS_LOG_SIZE);

        // 6. Partition manager (coherence domain manager)
        let partition_mgr = PartitionManager::new(&mut cap_mgr);

        // 7. CommEdge manager (inter-partition channels)
        let commedge_mgr = CommEdgeManager::new(&queue_mgr);

        // 8. Pressure engine (mincut integration)
        let pressure = PressureEngine::new();

        // 9. Scheduler
        let scheduler = Scheduler::new(SchedulerConfig::default());

        // 10. Vector/graph kernel objects
        let vecgraph = VecGraphManager::new(init.phys, &proof_engine);

        Self {
            cap_mgr, region_mgr, queue_mgr, proof_engine,
            witness_log, partition_mgr, commedge_mgr, pressure,
            scheduler, vecgraph, timer: init.timer.clone(),
        }
    }
}
```

---

## 3. Core Kernel Objects

RVM defines eight first-class kernel objects. The first six (Task, Capability, Region, Queue, Timer, Proof) are inherited from Phase A (ADR-087). The remaining two (Partition, CommEdge) plus the supplementary metric objects (CoherenceScore, CutPressure, DeviceLease) are new to the hypervisor architecture.

### 3.1 Partition (Coherence Domain Container)

A partition is the primary execution container. It is NOT a VM.

```rust
// ruvix-partition/src/partition.rs

/// A coherence domain: the fundamental unit of isolation in RVM.
///
/// A partition groups:
/// - A set of tasks that execute within the domain
/// - A set of memory regions owned by the domain
/// - A capability table scoped to the domain
/// - A set of CommEdges connecting to other partitions
/// - A coherence score measuring internal consistency
/// - A set of device leases for hardware access
///
/// Partitions can be split, merged, migrated, and hibernated.
/// The hypervisor manages stage-2 page tables per partition,
/// ensuring hardware-enforced memory isolation.
pub struct Partition {
    /// Unique partition identifier
    id: PartitionId,

    /// Stage-2 page tables (hardware isolation)
    stage2: Stage2Tables,

    /// Tasks belonging to this partition
    tasks: BTreeMap<TaskHandle, TaskControlBlock>,

    /// Memory regions owned by this partition
    regions: BTreeMap<RegionHandle, RegionDescriptor>,

    /// Capability table for this partition
    cap_table: CapabilityTable,

    /// Communication edges to other partitions
    comm_edges: ArrayVec<CommEdgeHandle, MAX_EDGES_PER_PARTITION>,

    /// Current coherence score (computed by solver crate)
    coherence: CoherenceScore,

    /// Current cut pressure (computed by mincut crate)
    cut_pressure: CutPressure,

    /// Active device leases
    device_leases: ArrayVec<DeviceLease, MAX_DEVICES_PER_PARTITION>,

    /// Partition state
    state: PartitionState,

    /// Witness log segment for this partition
    witness_segment: WitnessSegmentHandle,
}

/// Partition lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionState {
    /// Actively scheduled, tasks running
    Active,
    /// All tasks suspended, state in hot memory
    Suspended,
    /// State compressed and moved to warm tier
    Warm,
    /// State serialized to cold storage, reconstructable
    Dormant,
    /// Being split into two partitions (transient)
    Splitting,
    /// Being merged with another partition (transient)
    Merging,
    /// Being migrated to another physical node (transient)
    Migrating,
}

/// Partition identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PartitionId(u64);

/// Maximum communication edges per partition.
pub const MAX_EDGES_PER_PARTITION: usize = 64;

/// Maximum devices per partition.
pub const MAX_DEVICES_PER_PARTITION: usize = 8;
```

**Partition operations trait:**

```rust
/// Operations on coherence domains.
pub trait PartitionOps {
    /// Create a new empty partition with its own stage-2 address space.
    fn create(
        &mut self,
        config: PartitionConfig,
        parent_cap: CapHandle,
        proof: &ProofToken,
    ) -> Result<PartitionId, HypervisorError>;

    /// Split a partition along a mincut boundary.
    ///
    /// The mincut algorithm identifies the optimal split point.
    /// Tasks, regions, and capabilities are redistributed according
    /// to which side of the cut they fall on.
    fn split(
        &mut self,
        partition: PartitionId,
        cut: &CutResult,
        proof: &ProofToken,
    ) -> Result<(PartitionId, PartitionId), HypervisorError>;

    /// Merge two partitions into one.
    ///
    /// Requires that the partitions share at least one CommEdge
    /// and that the merged coherence score exceeds a threshold.
    fn merge(
        &mut self,
        a: PartitionId,
        b: PartitionId,
        proof: &ProofToken,
    ) -> Result<PartitionId, HypervisorError>;

    /// Transition a partition to the dormant state.
    ///
    /// Serializes all state, releases physical memory, and records
    /// a reconstruction receipt in the witness log.
    fn hibernate(
        &mut self,
        partition: PartitionId,
        proof: &ProofToken,
    ) -> Result<ReconstructionReceipt, HypervisorError>;

    /// Reconstruct a dormant partition from its receipt.
    fn reconstruct(
        &mut self,
        receipt: &ReconstructionReceipt,
        proof: &ProofToken,
    ) -> Result<PartitionId, HypervisorError>;
}
```

### 3.2 Capability (Unforgeable Token)

Capabilities are inherited directly from `ruvix-cap` (Phase A). In the hypervisor context, the capability system is extended with new object types:

```rust
// ruvix-types/src/object.rs (extended)

/// All kernel object types that can be referenced by capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    // Phase A objects
    Task        = 0,
    Region      = 1,
    Queue       = 2,
    Timer       = 3,
    VectorStore = 4,
    GraphStore  = 5,

    // Hypervisor objects (new)
    Partition   = 6,
    CommEdge    = 7,
    DeviceLease = 8,
    WitnessLog  = 9,
    PhysMemPool = 10,
}

/// Capability rights bitmap (extended for hypervisor).
bitflags! {
    pub struct CapRights: u32 {
        // Phase A rights
        const READ       = 1 << 0;
        const WRITE      = 1 << 1;
        const GRANT      = 1 << 2;
        const GRANT_ONCE = 1 << 3;
        const PROVE      = 1 << 4;
        const REVOKE     = 1 << 5;

        // Hypervisor rights (new)
        const SPLIT      = 1 << 6;   // Split a partition
        const MERGE      = 1 << 7;   // Merge partitions
        const MIGRATE    = 1 << 8;   // Migrate partition to another node
        const HIBERNATE  = 1 << 9;   // Hibernate/reconstruct
        const LEASE      = 1 << 10;  // Acquire device lease
        const WITNESS    = 1 << 11;  // Read witness log
    }
}
```

### 3.3 Witness (Audit Record)

Every privileged action produces a witness record. See [Section 8](#8-witness-subsystem) for the full design.

### 3.4 MemoryRegion (Typed, Tiered Memory)

Memory regions from Phase A are extended with tier awareness:

```rust
// ruvix-region/src/tiered.rs

/// Memory tier indicating thermal/access characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MemoryTier {
    /// Actively accessed, in L1/L2 cache working set.
    /// Physical pages pinned, stage-2 mapped.
    Hot = 0,

    /// Recently accessed, in DRAM but not cache-hot.
    /// Physical pages allocated, stage-2 mapped but may be
    /// compressed in background.
    Warm = 1,

    /// Not recently accessed. Pages compressed in-place
    /// using LZ4. Stage-2 mapping points to compressed form.
    /// Access triggers decompression fault handled by hypervisor.
    Dormant = 2,

    /// Evicted to persistent storage (NVMe, SD card, network).
    /// Stage-2 mapping removed. Access triggers reconstruction
    /// via the reconstruction protocol.
    Cold = 3,
}

/// A memory region with ownership tracking and tier management.
pub struct TieredRegion {
    /// Base region (Immutable, AppendOnly, or Slab policy)
    inner: RegionDescriptor,

    /// Current memory tier
    tier: MemoryTier,

    /// Owning partition
    owner: PartitionId,

    /// Sharing bitmap: which partitions have read access via CommEdge
    shared_with: BitSet<256>,

    /// Last access timestamp (for tier promotion/demotion)
    last_access_ns: u64,

    /// Compressed size (if Dormant tier)
    compressed_size: Option<usize>,

    /// Reconstruction receipt (if Cold tier)
    reconstruction: Option<ReconstructionReceipt>,
}
```

See [Section 4](#4-memory-architecture) for the full memory architecture.

### 3.5 CommEdge (Communication Channel)

A CommEdge is a typed, capability-checked communication channel between two partitions:

```rust
// ruvix-commedge/src/lib.rs

/// A communication edge between two partitions.
///
/// CommEdges are the only mechanism for inter-partition communication.
/// They carry typed messages, support zero-copy sharing, and are
/// tracked by the coherence graph.
pub struct CommEdge {
    /// Unique edge identifier
    id: CommEdgeHandle,

    /// Source partition
    source: PartitionId,

    /// Destination partition
    dest: PartitionId,

    /// Underlying queue (from ruvix-queue)
    queue: QueueHandle,

    /// Edge weight in the coherence graph.
    /// Updated on every message send: weight += message_bytes.
    /// Decays over time: weight *= decay_factor per epoch.
    weight: AtomicU64,

    /// Message count since last epoch
    message_count: AtomicU64,

    /// Capability required to send on this edge
    send_cap: CapHandle,

    /// Capability required to receive on this edge
    recv_cap: CapHandle,

    /// Whether this edge supports zero-copy region sharing
    zero_copy: bool,

    /// Shared memory regions (if zero_copy is true)
    shared_regions: ArrayVec<RegionHandle, 16>,
}

/// CommEdge operations.
pub trait CommEdgeOps {
    /// Create a new CommEdge between two partitions.
    ///
    /// Both partitions must hold appropriate capabilities.
    /// The edge is registered in the coherence graph.
    fn create_edge(
        &mut self,
        source: PartitionId,
        dest: PartitionId,
        config: CommEdgeConfig,
        proof: &ProofToken,
    ) -> Result<CommEdgeHandle, HypervisorError>;

    /// Send a message over a CommEdge.
    ///
    /// Updates edge weight in the coherence graph.
    fn send(
        &mut self,
        edge: CommEdgeHandle,
        msg: &[u8],
        priority: MsgPriority,
        cap: CapHandle,
    ) -> Result<(), HypervisorError>;

    /// Receive a message from a CommEdge.
    fn recv(
        &mut self,
        edge: CommEdgeHandle,
        buf: &mut [u8],
        timeout: Duration,
        cap: CapHandle,
    ) -> Result<usize, HypervisorError>;

    /// Share a memory region over a CommEdge (zero-copy).
    ///
    /// Maps the region into the destination partition's stage-2
    /// address space with read-only permissions. The source retains
    /// ownership.
    fn share_region(
        &mut self,
        edge: CommEdgeHandle,
        region: RegionHandle,
        proof: &ProofToken,
    ) -> Result<(), HypervisorError>;

    /// Destroy a CommEdge.
    ///
    /// Unmaps any shared regions and removes the edge from the
    /// coherence graph.
    fn destroy_edge(
        &mut self,
        edge: CommEdgeHandle,
        proof: &ProofToken,
    ) -> Result<(), HypervisorError>;
}
```

### 3.6 DeviceLease (Time-Bounded Device Access)

```rust
// ruvix-partition/src/device_lease.rs

/// A time-bounded, revocable lease granting a partition access to
/// a hardware device.
///
/// Device leases are the hypervisor's mechanism for safe device
/// assignment. Unlike passthrough (where the guest owns the device
/// permanently), leases expire and can be revoked.
pub struct DeviceLease {
    /// Unique lease identifier
    id: LeaseId,

    /// Device being leased
    device: DeviceDescriptor,

    /// Partition holding the lease
    holder: PartitionId,

    /// Lease expiration (absolute time in nanoseconds)
    expires_ns: u64,

    /// Whether the lease has been revoked
    revoked: bool,

    /// MMIO region mapped into the partition's stage-2 space
    mmio_region: Option<RegionHandle>,

    /// Interrupt routing: device IRQ -> partition's virtual IRQ
    irq_routing: Option<(u32, u32)>,  // (physical_irq, virtual_irq)
}

/// Lease operations.
pub trait LeaseOps {
    /// Acquire a lease on a device.
    ///
    /// Requires LEASE capability. The device's MMIO region is mapped
    /// into the partition's stage-2 address space. Interrupts from
    /// the device are routed to the partition.
    fn acquire(
        &mut self,
        device: DeviceDescriptor,
        partition: PartitionId,
        duration_ns: u64,
        cap: CapHandle,
        proof: &ProofToken,
    ) -> Result<LeaseId, HypervisorError>;

    /// Renew an existing lease.
    fn renew(
        &mut self,
        lease: LeaseId,
        additional_ns: u64,
        proof: &ProofToken,
    ) -> Result<(), HypervisorError>;

    /// Revoke a lease (immediate).
    ///
    /// Unmaps MMIO region, disables interrupt routing, resets
    /// device to safe state.
    fn revoke(
        &mut self,
        lease: LeaseId,
        proof: &ProofToken,
    ) -> Result<(), HypervisorError>;
}
```

### 3.7 CoherenceScore

```rust
// ruvix-pressure/src/coherence.rs

/// A coherence score for a partition, computed by the solver crate.
///
/// The score measures how "internally consistent" a partition is:
/// high coherence means the partition's tasks and data are tightly
/// coupled and should stay together. Low coherence signals that
/// the partition may benefit from splitting.
#[derive(Debug, Clone, Copy)]
pub struct CoherenceScore {
    /// Aggregate score in [0.0, 1.0]. Higher = more coherent.
    pub value: f64,

    /// Per-task contribution to the score.
    /// Identifies which tasks are most/least coupled.
    pub task_contributions: [f32; 64],

    /// Timestamp of last computation.
    pub computed_at_ns: u64,

    /// Whether the score is stale (> 1 epoch old).
    pub stale: bool,
}
```

### 3.8 CutPressure

```rust
// ruvix-pressure/src/cut.rs

/// Graph-derived isolation signal for a partition.
///
/// CutPressure is computed by running the ruvector-mincut algorithm
/// on the partition's communication graph. High pressure means the
/// partition has a cheap cut -- it could easily be split into two
/// independent halves.
#[derive(Debug, Clone)]
pub struct CutPressure {
    /// Minimum cut value across all edges in/out of this partition.
    /// Lower value = higher pressure to split.
    pub min_cut_value: f64,

    /// The actual cut: which edges to sever.
    pub cut_edges: ArrayVec<CommEdgeHandle, 32>,

    /// Partition IDs on each side of the proposed cut.
    pub side_a: ArrayVec<TaskHandle, 64>,
    pub side_b: ArrayVec<TaskHandle, 64>,

    /// Estimated coherence scores after split.
    pub predicted_coherence_a: f64,
    pub predicted_coherence_b: f64,

    /// Timestamp.
    pub computed_at_ns: u64,
}
```

---

## 4. Memory Architecture

### 4.1 Two-Stage Address Translation

RVM uses hardware-enforced two-stage address translation for partition isolation:

```
Partition Virtual Address (VA)
    |
    | Stage-1 translation (partition's own page tables, EL1)
    |
    v
Intermediate Physical Address (IPA)
    |
    | Stage-2 translation (hypervisor-controlled, EL2)
    |
    v
Physical Address (PA)
```

Each partition has its own stage-1 page tables (which it controls) and stage-2 page tables (which only the hypervisor can modify). This means:

- A partition cannot access memory outside its assigned IPA range
- The hypervisor can remap, compress, or migrate physical pages without the partition's knowledge
- Zero-copy sharing is implemented by mapping the same PA into two partitions' stage-2 tables

### 4.2 Physical Memory Allocator

The physical allocator uses a buddy system with per-tier free lists:

```rust
// ruvix-physmem/src/buddy.rs

/// Physical memory allocator with tier-aware allocation.
pub struct PhysicalAllocator {
    /// Buddy allocator for each tier
    tiers: [BuddyAllocator; 4],  // Hot, Warm, Dormant, Cold

    /// Total physical memory available
    total_pages: usize,

    /// Per-tier statistics
    stats: [TierStats; 4],
}

impl PhysicalAllocator {
    /// Allocate pages from a specific tier.
    pub fn allocate_pages(
        &mut self,
        count: usize,
        tier: MemoryTier,
    ) -> Result<PhysRange, AllocError> {
        self.tiers[tier as usize].allocate(count)
    }

    /// Promote pages from a colder tier to a warmer tier.
    ///
    /// This is called when a dormant region is accessed.
    pub fn promote(
        &mut self,
        range: PhysRange,
        from: MemoryTier,
        to: MemoryTier,
    ) -> Result<PhysRange, AllocError> {
        assert!(to < from, "promotion must go to a warmer tier");
        let new_range = self.tiers[to as usize].allocate(range.page_count())?;
        // Copy and decompress if needed
        self.copy_and_promote(range, new_range, from, to)?;
        self.tiers[from as usize].free(range);
        Ok(new_range)
    }

    /// Demote pages to a colder tier.
    ///
    /// Pages are compressed (Dormant) or evicted (Cold).
    pub fn demote(
        &mut self,
        range: PhysRange,
        from: MemoryTier,
        to: MemoryTier,
    ) -> Result<DemoteReceipt, AllocError> {
        assert!(to > from, "demotion must go to a colder tier");
        match to {
            MemoryTier::Dormant => self.compress_in_place(range),
            MemoryTier::Cold => self.evict_to_storage(range),
            _ => unreachable!(),
        }
    }
}
```

### 4.3 Memory Ownership via Rust's Type System

Memory ownership is enforced at the type level. A `RegionHandle` is a non-copyable token:

```rust
// ruvix-region/src/ownership.rs

/// A typed memory region handle. Non-copyable, non-clonable.
///
/// Ownership semantics:
/// - Exactly one partition owns a region at any time
/// - Transfer requires a proof and witness record
/// - Sharing creates a read-only view (not an ownership transfer)
/// - Dropping the handle does NOT free the region (the hypervisor manages lifetime)
pub struct OwnedRegion<P: RegionPolicy> {
    handle: RegionHandle,
    owner: PartitionId,
    _policy: PhantomData<P>,
}

/// Immutable region policy marker.
pub struct Immutable;

/// Append-only region policy marker.
pub struct AppendOnly;

/// Slab region policy marker.
pub struct Slab;

impl<P: RegionPolicy> OwnedRegion<P> {
    /// Transfer ownership to another partition.
    ///
    /// Consumes self, ensuring the old owner cannot use the handle.
    /// Updates stage-2 page tables for both partitions.
    pub fn transfer(
        self,
        new_owner: PartitionId,
        proof: &ProofToken,
        witness: &mut WitnessLog,
    ) -> Result<OwnedRegion<P>, HypervisorError> {
        witness.record(WitnessRecord::RegionTransfer {
            region: self.handle,
            from: self.owner,
            to: new_owner,
            proof_tier: proof.tier(),
        });
        // Remap stage-2 tables
        Ok(OwnedRegion {
            handle: self.handle,
            owner: new_owner,
            _policy: PhantomData,
        })
    }
}

/// Zero-copy sharing between partitions.
///
/// Only Immutable and AppendOnly regions can be shared (INV-4 from
/// Phase A: TOCTOU protection). Slab regions are never shared.
impl OwnedRegion<Immutable> {
    pub fn share_readonly(
        &self,
        target: PartitionId,
        edge: CommEdgeHandle,
        witness: &mut WitnessLog,
    ) -> Result<SharedRegionView, HypervisorError> {
        witness.record(WitnessRecord::RegionShare {
            region: self.handle,
            owner: self.owner,
            target,
            edge,
        });
        Ok(SharedRegionView {
            handle: self.handle,
            viewer: target,
        })
    }
}
```

### 4.4 Tier Management

The hypervisor runs a background tier management loop that promotes and demotes regions based on access patterns:

```rust
// ruvix-partition/src/tier_manager.rs

/// Tier management policy.
pub struct TierPolicy {
    /// Promote to Hot if accessed more than this many times per epoch
    pub hot_access_threshold: u32,
    /// Demote to Dormant if not accessed for this many epochs
    pub dormant_after_epochs: u32,
    /// Demote to Cold if dormant for this many epochs
    pub cold_after_epochs: u32,
    /// Maximum Hot tier memory (bytes) before forced demotion
    pub max_hot_bytes: usize,
    /// Compression algorithm for Dormant tier
    pub compression: CompressionAlgorithm,
}

/// Reconstruction protocol for dormant/cold state.
///
/// A reconstruction receipt contains everything needed to rebuild
/// a region from its serialized form plus the witness log.
#[derive(Debug, Clone)]
pub struct ReconstructionReceipt {
    /// Region identity
    pub region: RegionHandle,
    /// Owning partition
    pub partition: PartitionId,
    /// Hash of the serialized state
    pub state_hash: [u8; 32],
    /// Storage location (for Cold tier)
    pub storage_location: StorageLocation,
    /// Witness log range needed for replay
    pub witness_range: Range<u64>,
    /// Proof that the serialization was correct
    pub attestation: ProofAttestation,
}

#[derive(Debug, Clone)]
pub enum StorageLocation {
    /// Compressed in DRAM at the given physical address range
    CompressedDram(PhysRange),
    /// On block device at the given LBA range
    BlockDevice { device: DeviceDescriptor, lba_range: Range<u64> },
    /// On remote node (for distributed RVM)
    Remote { node_id: u64, receipt_id: u64 },
}
```

### 4.5 No Demand Paging

RVM does not implement demand paging, swap, or copy-on-write. All regions are physically backed at creation time. This is a deliberate design choice:

- **Deterministic latency**: No page fault handler in the critical path
- **Simpler correctness proofs**: No hidden state in page tables
- **Better for real-time**: No unbounded delay from swap I/O

The tradeoff is higher memory pressure, which is managed by the tier system: instead of swapping, RVM compresses (Dormant) or serializes (Cold) entire regions with explicit witness records.

---

## 5. Scheduler Design

### 5.1 Three Scheduling Modes

The scheduler operates in one of three modes at any given time:

```rust
// ruvix-sched/src/mode.rs

/// Scheduler operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// Hard real-time mode.
    ///
    /// Activated when any partition has a deadline-critical task.
    /// Uses pure EDF (Earliest Deadline First) within partitions.
    /// No novelty boosting. No coherence-based reordering.
    /// Guaranteed bounded preemption latency.
    Reflex,

    /// Normal operating mode.
    ///
    /// Combines three signals:
    /// 1. Deadline pressure (EDF baseline)
    /// 2. Novelty signal (priority boost for new information)
    /// 3. Structural risk (deprioritize mutations that lower coherence)
    /// 4. Cut pressure (boost partitions near a split boundary)
    Flow,

    /// Recovery mode.
    ///
    /// Activated when coherence drops below a critical threshold
    /// or a partition reconstruction fails. Reduces concurrency,
    /// favors stability over throughput.
    Recovery,
}
```

### 5.2 Graph-Pressure-Driven Scheduling

In Flow mode, the scheduler uses the coherence graph to make decisions:

```rust
// ruvix-sched/src/graph_pressure.rs

/// Priority computation for Flow mode.
///
/// final_priority = deadline_urgency
///                + (novelty_boost * NOVELTY_WEIGHT)
///                - (structural_risk * RISK_WEIGHT)
///                + (cut_pressure_boost * PRESSURE_WEIGHT)
pub fn compute_flow_priority(
    task: &TaskControlBlock,
    partition: &Partition,
    pressure: &PressureEngine,
    now_ns: u64,
) -> FlowPriority {
    // 1. Deadline urgency: how close to missing the deadline
    let deadline_urgency = task.deadline
        .map(|d| {
            let remaining = d.saturating_sub(now_ns);
            // Urgency increases as deadline approaches
            1.0 / (remaining as f64 / 1_000_000.0 + 1.0)
        })
        .unwrap_or(0.0);

    // 2. Novelty boost: is this task processing genuinely new data?
    let novelty_boost = partition.coherence.task_contributions
        [task.handle.index() % 64] as f64;

    // 3. Structural risk: would this task's pending mutations
    //    lower the partition's coherence score?
    let structural_risk = task.pending_mutation_risk();

    // 4. Cut pressure boost: if this partition is near a split
    //    boundary, boost tasks that would reduce the cut cost
    //    (making the partition more internally coherent)
    let cut_boost = if partition.cut_pressure.min_cut_value < SPLIT_THRESHOLD {
        // Boost tasks on the heavier side of the cut
        let on_heavy_side = partition.cut_pressure.side_a.len()
            > partition.cut_pressure.side_b.len();
        if partition.cut_pressure.side_a.contains(&task.handle) == on_heavy_side {
            PRESSURE_BOOST
        } else {
            0.0
        }
    } else {
        0.0
    };

    FlowPriority {
        deadline_urgency,
        novelty_boost: novelty_boost * NOVELTY_WEIGHT,
        structural_risk: structural_risk * RISK_WEIGHT,
        cut_pressure_boost: cut_boost,
        total: deadline_urgency
            + novelty_boost * NOVELTY_WEIGHT
            - structural_risk * RISK_WEIGHT
            + cut_boost,
    }
}

const NOVELTY_WEIGHT: f64 = 0.3;
const RISK_WEIGHT: f64 = 2.0;
const PRESSURE_BOOST: f64 = 0.5;
const SPLIT_THRESHOLD: f64 = 0.2;
```

### 5.3 Partition Split/Merge Triggers

The scheduler monitors cut pressure and triggers structural changes:

```rust
// ruvix-sched/src/structural.rs

/// Structural change triggers evaluated every epoch.
pub fn evaluate_structural_changes(
    partitions: &[Partition],
    pressure: &PressureEngine,
    config: &StructuralConfig,
) -> Vec<StructuralAction> {
    let mut actions = Vec::new();

    for partition in partitions {
        let cp = &partition.cut_pressure;
        let cs = &partition.coherence;

        // SPLIT trigger: low mincut AND low coherence
        if cp.min_cut_value < config.split_cut_threshold
            && cs.value < config.split_coherence_threshold
            && cp.predicted_coherence_a > cs.value
            && cp.predicted_coherence_b > cs.value
        {
            actions.push(StructuralAction::Split {
                partition: partition.id,
                cut: cp.clone(),
            });
        }

        // MERGE trigger: high coherence between two partitions
        // connected by a heavy CommEdge
        for edge_handle in &partition.comm_edges {
            if let Some(edge) = pressure.get_edge(*edge_handle) {
                let weight = edge.weight.load(Ordering::Relaxed);
                if weight > config.merge_edge_threshold {
                    let other = if edge.source == partition.id {
                        edge.dest
                    } else {
                        edge.source
                    };
                    actions.push(StructuralAction::Merge {
                        a: partition.id,
                        b: other,
                        edge_weight: weight,
                    });
                }
            }
        }

        // HIBERNATE trigger: partition has been suspended for too long
        if partition.state == PartitionState::Suspended
            && partition.last_activity_ns + config.hibernate_after_ns < now_ns()
        {
            actions.push(StructuralAction::Hibernate {
                partition: partition.id,
            });
        }
    }

    actions
}
```

### 5.4 Per-CPU Scheduling

On multi-core systems, each CPU runs its own scheduler instance with partition affinity:

```rust
// ruvix-sched/src/percpu.rs

/// Per-CPU scheduler state.
pub struct PerCpuScheduler {
    /// CPU identifier
    cpu_id: u32,

    /// Partitions assigned to this CPU
    assigned: ArrayVec<PartitionId, 32>,

    /// Current time quantum remaining (microseconds)
    quantum_remaining: u32,

    /// Currently running task
    current: Option<TaskHandle>,

    /// Mode
    mode: SchedulerMode,
}

/// Global scheduler coordinates per-CPU instances.
pub struct GlobalScheduler {
    /// Per-CPU schedulers
    per_cpu: ArrayVec<PerCpuScheduler, MAX_CPUS>,

    /// Partition-to-CPU assignment (informed by coherence graph)
    assignment: PartitionAssignment,

    /// Global mode override (Recovery overrides all CPUs)
    global_mode: Option<SchedulerMode>,
}
```

---

## 6. IPC Design

### 6.1 Zero-Copy Message Passing

All inter-partition communication goes through CommEdges, which wrap the `ruvix-queue` ring buffers. Zero-copy is achieved by descriptor passing:

```rust
// ruvix-commedge/src/zerocopy.rs

/// A zero-copy message descriptor.
///
/// Instead of copying data, the sender places a descriptor in the
/// queue that references a shared region. The receiver reads directly
/// from the shared region.
///
/// This is safe because:
/// 1. Only Immutable or AppendOnly regions can be shared (no mutation)
/// 2. The stage-2 page tables enforce read-only access for the receiver
/// 3. The witness log records every share operation
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ZeroCopyDescriptor {
    /// Shared region handle
    pub region: RegionHandle,
    /// Offset within the region
    pub offset: u32,
    /// Length of the data
    pub length: u32,
    /// Schema hash (for type checking)
    pub schema_hash: u64,
}

/// Send a zero-copy message.
///
/// The region must already be shared with the destination partition
/// via `CommEdgeOps::share_region`.
pub fn send_zerocopy(
    edge: &CommEdge,
    desc: ZeroCopyDescriptor,
    cap: CapHandle,
    cap_mgr: &CapabilityManager,
    witness: &mut WitnessLog,
) -> Result<(), HypervisorError> {
    // 1. Capability check
    let cap_entry = cap_mgr.lookup(cap)?;
    if !cap_entry.rights.contains(CapRights::WRITE) {
        return Err(HypervisorError::CapabilityDenied);
    }

    // 2. Verify region is shared with destination
    if !edge.shared_regions.contains(&desc.region) {
        return Err(HypervisorError::RegionNotShared);
    }

    // 3. Validate descriptor bounds
    // (offset + length must be within region size)

    // 4. Enqueue descriptor in ring buffer
    edge.queue.send_raw(
        bytemuck::bytes_of(&desc),
        MsgPriority::Normal,
    )?;

    // 5. Witness
    witness.record(WitnessRecord::ZeroCopySend {
        edge: edge.id,
        region: desc.region,
        offset: desc.offset,
        length: desc.length,
    });

    Ok(())
}
```

### 6.2 Async Notification Mechanism

For lightweight signaling without data transfer (e.g., "new data available"), RVM provides notifications:

```rust
// ruvix-commedge/src/notification.rs

/// A notification word: a bitmask that can be atomically OR'd.
///
/// Notifications are the lightweight alternative to sending a
/// full message. A partition can wait on a notification word
/// and be woken when any bit is set.
///
/// This maps to a virtual interrupt injection at the hypervisor
/// level: setting a notification bit triggers a stage-2 fault
/// that the hypervisor converts to a virtual IRQ in the
/// destination partition.
pub struct NotificationWord {
    /// The notification bits (64 independent signals)
    bits: AtomicU64,

    /// Source partition (who can signal)
    source: PartitionId,

    /// Destination partition (who is waiting)
    dest: PartitionId,

    /// Capability required to signal
    signal_cap: CapHandle,
}

impl NotificationWord {
    /// Signal one or more notification bits.
    pub fn signal(&self, mask: u64, cap: CapHandle) -> Result<(), HypervisorError> {
        // Capability check omitted for brevity
        self.bits.fetch_or(mask, Ordering::Release);
        // Inject virtual interrupt into destination partition
        inject_virtual_irq(self.dest, NOTIFICATION_VIRQ);
        Ok(())
    }

    /// Wait for any bit in the mask to be set.
    ///
    /// Blocks the calling task until a matching bit is set.
    /// Returns the bits that were set.
    pub fn wait(&self, mask: u64) -> u64 {
        loop {
            let current = self.bits.load(Ordering::Acquire);
            let matched = current & mask;
            if matched != 0 {
                // Clear the matched bits
                self.bits.fetch_and(!matched, Ordering::AcqRel);
                return matched;
            }
            // Block task until notification IRQ
            yield_until_irq();
        }
    }
}
```

### 6.3 Shared Memory Regions with Witness Tracking

Every shared memory operation is witnessed:

```rust
// Witness records for IPC operations
pub enum IpcWitnessRecord {
    /// A region was shared between partitions
    RegionShared {
        region: RegionHandle,
        from: PartitionId,
        to: PartitionId,
        permissions: PagePermissions,
        edge: CommEdgeHandle,
    },
    /// A zero-copy message was sent
    ZeroCopySent {
        edge: CommEdgeHandle,
        region: RegionHandle,
        offset: u32,
        length: u32,
    },
    /// A region share was revoked
    ShareRevoked {
        region: RegionHandle,
        from: PartitionId,
        to: PartitionId,
    },
    /// A notification was signaled
    NotificationSignaled {
        source: PartitionId,
        dest: PartitionId,
        mask: u64,
    },
}
```

---

## 7. Device Model

### 7.1 Lease-Based Device Access

RVM does not emulate hardware. Instead, it provides direct device access through time-bounded leases. This is fundamentally different from KVM's device emulation (QEMU) or Firecracker's minimal device model (virtio).

```
Traditional Hypervisor:
    Guest -> emulated device -> host driver -> real hardware

RVM:
    Partition -> [lease check] -> real hardware (via stage-2 MMIO mapping)
```

The hypervisor maps device MMIO regions directly into the partition's stage-2 address space. The partition interacts with real hardware registers. The hypervisor's role is limited to:

1. Granting and revoking leases
2. Routing interrupts
3. Ensuring lease expiration
4. Resetting devices on lease revocation

### 7.2 Device Capability Tokens

```rust
// ruvix-drivers/src/device_cap.rs

/// A device descriptor identifying a hardware device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceDescriptor {
    /// Device class
    pub class: DeviceClass,
    /// MMIO base address (physical)
    pub mmio_base: u64,
    /// MMIO region size
    pub mmio_size: usize,
    /// Primary interrupt number
    pub irq: u32,
    /// Device-specific identifier
    pub device_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceClass {
    Uart,
    Timer,
    InterruptController,
    NetworkVirtio,
    BlockVirtio,
    Gpio,
    Rtc,
    Pci,
}

/// Device registry maintained by the hypervisor.
pub struct DeviceRegistry {
    /// All discovered devices
    devices: ArrayVec<DeviceDescriptor, 64>,

    /// Current leases: device -> (partition, expiration)
    leases: BTreeMap<DeviceDescriptor, DeviceLease>,

    /// Devices reserved for the hypervisor (never leased)
    reserved: ArrayVec<DeviceDescriptor, 8>,
}

impl DeviceRegistry {
    /// Discover devices from the device tree.
    pub fn from_dtb(dtb: &DeviceTree) -> Self {
        let mut reg = Self::new();
        for node in dtb.iter_devices() {
            let desc = DeviceDescriptor::from_dtb_node(node);
            reg.devices.push(desc);
        }
        // Reserve the interrupt controller and hypervisor timer
        reg.reserved.push(reg.find_gic().unwrap());
        reg.reserved.push(reg.find_timer().unwrap());
        reg
    }
}
```

### 7.3 Interrupt Routing

Interrupts from leased devices are routed to the holding partition as virtual interrupts:

```rust
// ruvix-drivers/src/irq_route.rs

/// Interrupt routing table.
///
/// Maps physical IRQs to virtual IRQs in partitions.
/// Only one partition can receive a given physical IRQ at a time.
pub struct IrqRouter {
    /// Physical IRQ -> (partition, virtual IRQ)
    routes: BTreeMap<u32, (PartitionId, u32)>,
}

impl IrqRouter {
    /// Route a physical IRQ to a partition.
    ///
    /// Called when a device lease is acquired.
    pub fn add_route(
        &mut self,
        phys_irq: u32,
        partition: PartitionId,
        virt_irq: u32,
    ) -> Result<(), HypervisorError> {
        if self.routes.contains_key(&phys_irq) {
            return Err(HypervisorError::IrqAlreadyRouted);
        }
        self.routes.insert(phys_irq, (partition, virt_irq));
        Ok(())
    }

    /// Handle a physical IRQ.
    ///
    /// Called from the hypervisor's IRQ handler. Looks up the
    /// route and injects a virtual interrupt into the target
    /// partition.
    pub fn dispatch(&self, phys_irq: u32) -> Option<(PartitionId, u32)> {
        self.routes.get(&phys_irq).copied()
    }
}
```

### 7.4 Virtio-Like Minimal Device Model

For devices that cannot be directly leased (shared devices, emulated devices for testing), RVM provides a minimal virtio-compatible interface:

```rust
// ruvix-drivers/src/virtio_shim.rs

/// Minimal virtio device shim.
///
/// This is NOT full virtio emulation. It provides:
/// - A single virtqueue (descriptor table + available ring + used ring)
/// - Interrupt injection via notification words
/// - Region-backed buffers (no DMA emulation)
///
/// Used for: virtio-console (debug), virtio-net (networking between
/// partitions), virtio-blk (block storage).
pub trait VirtioShim {
    /// Device type (net = 1, blk = 2, console = 3)
    fn device_type(&self) -> u32;

    /// Process available descriptors.
    fn process_queue(&mut self, queue: &VirtQueue) -> usize;

    /// Device-specific configuration read.
    fn read_config(&self, offset: u32) -> u32;

    /// Device-specific configuration write.
    fn write_config(&mut self, offset: u32, value: u32);
}
```

---

## 8. Witness Subsystem

### 8.1 Append-Only Log Design

The witness log is the audit backbone of RVM. Every privileged action produces a witness record. The log is append-only: there is no API to delete or modify records.

```rust
// ruvix-witness/src/log.rs

/// The kernel witness log.
///
/// Backed by a physically contiguous region in DRAM (Hot tier).
/// When the log fills, older segments are compressed to Warm tier
/// and eventually serialized to Cold tier.
///
/// The log is structured as a series of 64-byte records packed
/// into 4KB pages. Each page has a header with a running hash.
pub struct WitnessLog {
    /// Current write position (page index + offset within page)
    write_pos: AtomicU64,

    /// Physical pages backing the log
    pages: ArrayVec<PhysAddr, WITNESS_LOG_MAX_PAGES>,

    /// Running hash over all records (FNV-1a)
    chain_hash: AtomicU64,

    /// Sequence number (monotonically increasing)
    sequence: AtomicU64,

    /// Segment index for archival
    current_segment: u32,
}

/// Maximum log pages before rotation to warm tier.
pub const WITNESS_LOG_MAX_PAGES: usize = 4096; // 16 MB of hot log
```

### 8.2 Compact Binary Format

Each witness record is exactly 64 bytes to align with cache lines and avoid variable-length parsing:

```rust
// ruvix-witness/src/record.rs

/// A witness record. Fixed 64 bytes.
///
/// Layout:
///   [0..8]   sequence number (u64, little-endian)
///   [8..16]  timestamp_ns (u64)
///   [16..17] record_kind (u8)
///   [17..18] proof_tier (u8)
///   [18..20] reserved (2 bytes)
///   [20..28] subject_id (u64, partition/task/region ID)
///   [28..36] object_id (u64, target of the action)
///   [36..44] aux_data (u64, action-specific)
///   [44..52] chain_hash_before (u64, hash of all preceding records)
///   [52..60] record_hash (u64, hash of this record's fields [0..52])
///   [60..64] reserved_flags (u32)
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct WitnessRecord {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub kind: WitnessRecordKind,
    pub proof_tier: u8,
    pub _reserved: [u8; 2],
    pub subject_id: u64,
    pub object_id: u64,
    pub aux_data: u64,
    pub chain_hash_before: u64,
    pub record_hash: u64,
    pub flags: u32,
}

static_assertions::assert_eq_size!(WitnessRecord, [u8; 64]);

/// What kind of action was witnessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WitnessRecordKind {
    // Partition lifecycle
    PartitionCreate    = 0x01,
    PartitionSplit     = 0x02,
    PartitionMerge     = 0x03,
    PartitionHibernate = 0x04,
    PartitionReconstruct = 0x05,
    PartitionMigrate   = 0x06,

    // Capability operations
    CapGrant           = 0x10,
    CapRevoke          = 0x11,
    CapDelegate        = 0x12,

    // Memory operations
    RegionCreate       = 0x20,
    RegionDestroy      = 0x21,
    RegionTransfer     = 0x22,
    RegionShare        = 0x23,
    RegionTierChange   = 0x24,

    // Communication
    CommEdgeCreate     = 0x30,
    CommEdgeDestroy    = 0x31,
    ZeroCopySend       = 0x32,
    NotificationSignal = 0x33,

    // Proof verification
    ProofVerified      = 0x40,
    ProofRejected      = 0x41,
    ProofEscalated     = 0x42,

    // Device operations
    LeaseAcquire       = 0x50,
    LeaseRevoke        = 0x51,
    LeaseExpire        = 0x52,

    // Vector/Graph mutations
    VectorPut          = 0x60,
    GraphMutation      = 0x61,

    // Scheduler events
    TaskSpawn          = 0x70,
    TaskTerminate      = 0x71,
    ModeSwitch         = 0x72,
    StructuralChange   = 0x73,

    // Boot and attestation
    BootAttestation    = 0x80,
    CheckpointCreated  = 0x81,
}
```

### 8.3 What Gets Witnessed

Every action in the following categories:

| Category | Examples | Record Kind |
|----------|----------|-------------|
| Partition lifecycle | Create, split, merge, hibernate, reconstruct, migrate | 0x01-0x06 |
| Capability changes | Grant, revoke, delegate | 0x10-0x12 |
| Memory operations | Region create/destroy/transfer/share, tier changes | 0x20-0x24 |
| Communication | Edge create/destroy, zero-copy send, notification | 0x30-0x33 |
| Proof verification | Verified, rejected, escalated | 0x40-0x42 |
| Device access | Lease acquire/revoke/expire | 0x50-0x52 |
| Data mutation | Vector put, graph mutation | 0x60-0x61 |
| Scheduling | Task spawn/terminate, mode switch, structural change | 0x70-0x73 |
| Boot | Boot attestation, checkpoints | 0x80-0x81 |

### 8.4 Replay and Audit

The witness log supports two operations: audit (verify integrity) and replay (reconstruct state).

```rust
// ruvix-witness/src/replay.rs

/// Verify the integrity of the witness log.
///
/// Walks the log from start to end, recomputing chain hashes.
/// Any break in the chain indicates tampering.
pub fn audit_log(log: &WitnessLog) -> AuditResult {
    let mut expected_hash: u64 = 0;
    let mut record_count: u64 = 0;
    let mut violations: Vec<AuditViolation> = Vec::new();

    for record in log.iter() {
        // Verify chain hash
        if record.chain_hash_before != expected_hash {
            violations.push(AuditViolation::ChainBreak {
                sequence: record.sequence,
                expected: expected_hash,
                found: record.chain_hash_before,
            });
        }

        // Verify record self-hash
        let computed = compute_record_hash(&record);
        if record.record_hash != computed {
            violations.push(AuditViolation::RecordTampered {
                sequence: record.sequence,
            });
        }

        // Advance chain
        expected_hash = fnv1a_combine(expected_hash, record.record_hash);
        record_count += 1;
    }

    AuditResult {
        total_records: record_count,
        violations,
        chain_valid: violations.is_empty(),
    }
}

/// Replay a witness log to reconstruct system state.
///
/// Given a checkpoint and a witness log segment, deterministically
/// reconstructs the system state at any point in the log.
pub fn replay_from_checkpoint(
    checkpoint: &Checkpoint,
    log_segment: &[WitnessRecord],
) -> Result<KernelState, ReplayError> {
    let mut state = checkpoint.restore()?;

    for record in log_segment {
        state.apply_witness_record(record)?;
    }

    Ok(state)
}
```

### 8.5 Integration with Proof Verifier

The witness log and proof engine form a closed loop:

1. A task requests a mutation (e.g., `vector_put_proved`)
2. The proof engine verifies the proof token (3-tier routing)
3. If the proof is valid, the mutation is applied
4. A witness record is emitted (ProofVerified + VectorPut)
5. If the proof is invalid, a rejection record is emitted (ProofRejected)
6. The witness record's chain hash incorporates the proof attestation

This means the witness log contains a complete, tamper-evident history of every proof that was checked and every mutation that was applied.

---

## 9. Agent Runtime Layer

### 9.1 WASM Partition Adapter

Agent workloads run as WASM modules inside partitions. The WASM runtime itself runs in the partition's address space (EL1/EL0), not in the hypervisor.

```rust
// ruvix-agent/src/adapter.rs

/// Configuration for a WASM agent partition.
pub struct AgentPartitionConfig {
    /// WASM module bytes
    pub wasm_module: &'static [u8],

    /// Memory limits
    pub max_memory_pages: u32,  // Each page = 64KB
    pub initial_memory_pages: u32,

    /// Stack size for the WASM execution
    pub stack_size: usize,

    /// Capabilities granted to this agent
    pub capabilities: ArrayVec<CapHandle, 32>,

    /// Communication edges to other agents
    pub comm_edges: ArrayVec<CommEdgeConfig, 16>,

    /// Scheduling priority
    pub priority: TaskPriority,

    /// Optional deadline for real-time agents
    pub deadline: Option<Duration>,
}

/// WASM host functions exposed to agents.
///
/// These are the agent's interface to the hypervisor, mapped to
/// syscalls via the partition's capability table.
pub trait AgentHostFunctions {
    // --- Communication ---

    /// Send a message to another agent via CommEdge.
    fn send(&mut self, edge_id: u32, data: &[u8]) -> Result<(), AgentError>;

    /// Receive a message from a CommEdge.
    fn recv(&mut self, edge_id: u32, buf: &mut [u8]) -> Result<usize, AgentError>;

    /// Signal a notification.
    fn notify(&mut self, edge_id: u32, mask: u64) -> Result<(), AgentError>;

    // --- Memory ---

    /// Request a shared memory region.
    fn request_shared_region(
        &mut self,
        size: usize,
        policy: u32,
    ) -> Result<u32, AgentError>;

    /// Map a shared region from another agent.
    fn map_shared(&mut self, region_id: u32) -> Result<*const u8, AgentError>;

    // --- Vector/Graph ---

    /// Read a vector from the kernel vector store.
    fn vector_get(
        &mut self,
        store_id: u32,
        key: u64,
        buf: &mut [f32],
    ) -> Result<usize, AgentError>;

    /// Write a vector with proof.
    fn vector_put(
        &mut self,
        store_id: u32,
        key: u64,
        data: &[f32],
    ) -> Result<(), AgentError>;

    // --- Lifecycle ---

    /// Spawn a child agent.
    fn spawn_agent(&mut self, config_ptr: u32) -> Result<u32, AgentError>;

    /// Request hibernation.
    fn hibernate(&mut self) -> Result<(), AgentError>;

    /// Yield execution.
    fn yield_now(&mut self);
}
```

### 9.2 Agent-to-Coherence-Domain Mapping

Each agent maps to exactly one partition. Multiple agents can share a partition if they are tightly coupled (high coherence score).

```
Agent A ──┐
          ├── Partition P1 (coherence = 0.92)
Agent B ──┘
               │ CommEdge (weight=1500)
               v
Agent C ──── Partition P2 (coherence = 0.87)
               │ CommEdge (weight=200)
               v
Agent D ──┐
          ├── Partition P3 (coherence = 0.95)
Agent E ──┘
```

When the mincut algorithm detects that Agent B communicates more with Agent C than with Agent A, it will trigger a partition split, moving Agent B from P1 to P2 (or creating a new partition).

### 9.3 Agent Lifecycle

```rust
// ruvix-agent/src/lifecycle.rs

/// Agent lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Being initialized (WASM module loading, capability setup)
    Initializing,

    /// Actively executing within its partition
    Running,

    /// Suspended (waiting on I/O or explicit yield)
    Suspended,

    /// Being migrated to a different partition
    Migrating {
        from: PartitionId,
        to: PartitionId,
    },

    /// Hibernated (state serialized, partition may be dormant)
    Hibernated,

    /// Being reconstructed from hibernated state
    Reconstructing,

    /// Terminated (cleanup complete)
    Terminated,
}

/// Agent migration protocol.
///
/// Migration moves an agent from one partition to another without
/// losing state. This is triggered by the mincut-based placement
/// engine when it detects that an agent is misplaced.
pub fn migrate_agent(
    agent: AgentHandle,
    from: PartitionId,
    to: PartitionId,
    kernel: &mut Kernel,
) -> Result<(), MigrationError> {
    // 1. Suspend agent
    kernel.suspend_task(agent.task)?;

    // 2. Serialize agent state (WASM memory, stack, globals)
    let state = kernel.serialize_wasm_state(agent)?;

    // 3. Create new task in destination partition
    let new_task = kernel.create_task_in_partition(to, agent.config)?;

    // 4. Restore state into new task
    kernel.restore_wasm_state(new_task, &state)?;

    // 5. Transfer owned regions
    for region in agent.owned_regions() {
        kernel.transfer_region(region, from, to)?;
    }

    // 6. Update CommEdge endpoints
    for edge in agent.comm_edges() {
        kernel.update_edge_endpoint(edge, from, to)?;
    }

    // 7. Update coherence graph
    kernel.pressure_engine.agent_migrated(agent, from, to);

    // 8. Witness
    kernel.witness_log.record(WitnessRecord::new(
        WitnessRecordKind::PartitionMigrate,
        from.0,
        to.0,
        agent.0 as u64,
    ));

    // 9. Resume agent in new partition
    kernel.resume_task(new_task)?;

    // 10. Destroy old task
    kernel.destroy_task(agent.task)?;

    Ok(())
}
```

### 9.4 Multi-Agent Communication

Agents communicate exclusively through CommEdges. The communication pattern is recorded in the coherence graph and drives placement decisions:

```rust
// ruvix-agent/src/communication.rs

/// Agent communication layer built on CommEdges.
pub struct AgentComm {
    /// Agent's partition
    partition: PartitionId,

    /// Named edges: edge_name -> CommEdgeHandle
    edges: BTreeMap<&'static str, CommEdgeHandle>,

    /// Message serialization format
    format: MessageFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum MessageFormat {
    /// Raw bytes (no serialization overhead)
    Raw,
    /// WIT Component Model types (schema-validated)
    Wit,
    /// CBOR (compact, self-describing)
    Cbor,
}

impl AgentComm {
    /// Send a typed message to a named edge.
    pub fn send<T: Serialize>(
        &self,
        edge_name: &str,
        message: &T,
    ) -> Result<(), AgentError> {
        let edge = self.edges.get(edge_name)
            .ok_or(AgentError::UnknownEdge)?;
        let bytes = self.serialize(message)?;
        // This goes through CommEdgeOps::send, which updates
        // the coherence graph edge weight
        syscall_queue_send(*edge, &bytes, MsgPriority::Normal)
    }

    /// Receive a typed message from a named edge.
    pub fn recv<T: Deserialize>(
        &self,
        edge_name: &str,
        timeout: Duration,
    ) -> Result<T, AgentError> {
        let edge = self.edges.get(edge_name)
            .ok_or(AgentError::UnknownEdge)?;
        let mut buf = [0u8; 65536];
        let len = syscall_queue_recv(*edge, &mut buf, timeout)?;
        self.deserialize(&buf[..len])
    }
}
```

---

## 10. Hardware Abstraction

### 10.1 HAL Trait Design

The HAL defines platform-agnostic traits. Existing traits from `ruvix-hal` (Console, Timer, InterruptController, Mmu, PowerManagement) are extended with hypervisor-specific traits:

```rust
// ruvix-hal/src/hypervisor.rs

/// Hypervisor-specific hardware abstraction.
///
/// This trait captures the operations that differ between
/// ARM EL2, RISC-V HS-mode, and x86 VMX root mode.
pub trait HypervisorHal {
    /// Stage-2/EPT page table type
    type Stage2Table;

    /// Virtual CPU context type
    type VcpuContext;

    /// Configure the CPU for hypervisor mode.
    ///
    /// Called once during boot. Sets up:
    /// - Stage-2 translation (VTCR_EL2 / hgatp / EPT pointer)
    /// - Trap configuration (HCR_EL2 / hedeleg / VM-execution controls)
    /// - Virtual interrupt delivery
    unsafe fn init_hypervisor_mode(&self) -> Result<(), HalError>;

    /// Create a new stage-2 address space.
    fn create_stage2_table(
        &self,
        phys: &mut dyn PhysicalAllocator,
    ) -> Result<Self::Stage2Table, HalError>;

    /// Map a page in a stage-2 table.
    fn stage2_map(
        &self,
        table: &mut Self::Stage2Table,
        ipa: u64,
        pa: u64,
        attrs: Stage2Attrs,
    ) -> Result<(), HalError>;

    /// Unmap a page from a stage-2 table.
    fn stage2_unmap(
        &self,
        table: &mut Self::Stage2Table,
        ipa: u64,
    ) -> Result<(), HalError>;

    /// Switch to a partition's address space.
    ///
    /// Activates the partition's stage-2 tables and restores
    /// the vCPU context.
    unsafe fn enter_partition(
        &self,
        table: &Self::Stage2Table,
        vcpu: &Self::VcpuContext,
    );

    /// Handle a trap from a partition.
    ///
    /// Called when the partition triggers a stage-2 fault,
    /// HVC/ECALL, or trapped instruction.
    fn handle_trap(
        &self,
        vcpu: &mut Self::VcpuContext,
        trap: TrapInfo,
    ) -> TrapAction;

    /// Inject a virtual interrupt into a partition.
    fn inject_virtual_irq(
        &self,
        vcpu: &mut Self::VcpuContext,
        irq: u32,
    ) -> Result<(), HalError>;

    /// Flush stage-2 TLB entries for a partition.
    fn flush_stage2_tlb(&self, vmid: u16);
}

/// Information about a trap from a partition.
#[derive(Debug)]
pub struct TrapInfo {
    /// Trap cause
    pub cause: TrapCause,
    /// Faulting address (if applicable)
    pub fault_addr: Option<u64>,
    /// Instruction that caused the trap (for emulation)
    pub instruction: Option<u32>,
}

#[derive(Debug)]
pub enum TrapCause {
    /// Stage-2 page fault (IPA not mapped)
    Stage2Fault { ipa: u64, is_write: bool },
    /// Hypercall (HVC/ECALL/VMCALL)
    Hypercall { code: u64, args: [u64; 4] },
    /// MMIO access to an unmapped device
    MmioAccess { addr: u64, is_write: bool, value: u64, size: u8 },
    /// WFI/WFE instruction (idle)
    WaitForInterrupt,
    /// System register access (trapped MSR/CSR)
    SystemRegister { reg: u32, is_write: bool, value: u64 },
}

#[derive(Debug)]
pub enum TrapAction {
    /// Resume the partition
    Resume,
    /// Resume with modified register state
    ResumeModified,
    /// Suspend the partition's current task
    SuspendTask,
    /// Terminate the partition
    Terminate,
}
```

### 10.2 What Must Be in Assembly vs Rust

| Component | Language | Reason |
|-----------|----------|--------|
| Reset vector, stack setup, BSS clear | Assembly | No Rust runtime available yet |
| Exception vector table entry points | Assembly | Fixed hardware-defined layout; must save/restore registers in exact order |
| Context switch (register save/restore) | Assembly | Must atomically save all 31 GPRs + SP + PC + PSTATE |
| TLB invalidation sequences | Inline asm in Rust | Specific instruction sequences with barriers |
| Cache maintenance | Inline asm in Rust | DC/IC instructions |
| Everything else | Rust | Type safety, borrow checker, no_std ecosystem |

Target: less than 500 lines of assembly total per platform.

### 10.3 Platform Abstraction Summary

| Operation | AArch64 (EL2) | RISC-V (HS-mode) | x86-64 (VMX root) |
|-----------|---------------|-------------------|--------------------|
| Stage-2 tables | VTTBR_EL2 + VTT | hgatp + G-stage PT | EPTP + EPT |
| Trap entry | VBAR_EL2 vectors | stvec (VS traps delegate to HS) | VM-exit handler |
| Virtual IRQ | HCR_EL2.VI bit | hvip.VSEIP | Posted interrupts / VM-entry interruption |
| Hypercall | HVC instruction | ECALL from VS-mode | VMCALL instruction |
| VMID/ASID | VTTBR_EL2[63:48] | hgatp.VMID | VPID (16-bit) |
| Cache control | DC CIVAC, IC IALLU | SFENCE.VMA | INVLPG, WBINVD |
| Timer | CNTHP_CTL_EL2 | htimedelta + stimecmp | VMX preemption timer |

### 10.4 QEMU virt as Reference Platform

The QEMU AArch64 virt machine is the first target:

```rust
// ruvix-aarch64/src/qemu_virt.rs

/// QEMU virt machine memory map.
pub const QEMU_VIRT_FLASH_BASE: u64     = 0x0000_0000;
pub const QEMU_VIRT_GIC_DIST_BASE: u64  = 0x0800_0000;
pub const QEMU_VIRT_GIC_CPU_BASE: u64   = 0x0801_0000;
pub const QEMU_VIRT_UART_BASE: u64      = 0x0900_0000;
pub const QEMU_VIRT_RTC_BASE: u64       = 0x0901_0000;
pub const QEMU_VIRT_GPIO_BASE: u64      = 0x0903_0000;
pub const QEMU_VIRT_RAM_BASE: u64       = 0x4000_0000;
pub const QEMU_VIRT_RAM_SIZE: u64       = 0x4000_0000; // 1 GB default

/// QEMU launch command for testing:
///
/// ```sh
/// qemu-system-aarch64 \
///     -machine virt,virtualization=on,gic-version=3 \
///     -cpu cortex-a72 \
///     -m 1G \
///     -nographic \
///     -kernel target/aarch64-unknown-none/release/ruvix \
///     -smp 4
/// ```
///
/// Key flags:
///   virtualization=on  -- enables EL2 (hypervisor mode)
///   gic-version=3      -- GICv3 (supports virtual interrupts)
///   -smp 4             -- 4 cores for multi-partition testing
```

---

## 11. Integration with RuVector

### 11.1 mincut Crate -> Partition Placement Engine

The `ruvector-mincut` crate provides the dynamic minimum cut algorithm that drives partition split/merge decisions. The integration maps the hypervisor's coherence graph to the mincut data structure:

```rust
// ruvix-pressure/src/mincut_bridge.rs

use ruvector_mincut::{MinCutBuilder, DynamicMinCut};

/// Bridge between the hypervisor coherence graph and ruvector-mincut.
pub struct MinCutBridge {
    /// The dynamic mincut structure
    mincut: Box<dyn DynamicMinCut>,

    /// Mapping: PartitionId -> mincut vertex ID
    partition_to_vertex: BTreeMap<PartitionId, usize>,

    /// Mapping: CommEdgeHandle -> mincut edge
    edge_to_mincut: BTreeMap<CommEdgeHandle, (usize, usize)>,

    /// Recomputation epoch
    epoch: u64,
}

impl MinCutBridge {
    pub fn new() -> Self {
        let mincut = MinCutBuilder::new()
            .exact()
            .build()
            .expect("mincut init");
        Self {
            mincut: Box::new(mincut),
            partition_to_vertex: BTreeMap::new(),
            edge_to_mincut: BTreeMap::new(),
            epoch: 0,
        }
    }

    /// Register a new partition as a vertex.
    pub fn add_partition(&mut self, id: PartitionId) -> usize {
        let vertex = self.partition_to_vertex.len();
        self.partition_to_vertex.insert(id, vertex);
        vertex
    }

    /// Register a CommEdge as a weighted edge.
    ///
    /// Called when a CommEdge is created.
    pub fn add_edge(
        &mut self,
        edge: CommEdgeHandle,
        source: PartitionId,
        dest: PartitionId,
        initial_weight: f64,
    ) -> Result<(), PressureError> {
        let u = *self.partition_to_vertex.get(&source)
            .ok_or(PressureError::UnknownPartition)?;
        let v = *self.partition_to_vertex.get(&dest)
            .ok_or(PressureError::UnknownPartition)?;
        self.mincut.insert_edge(u, v, initial_weight)?;
        self.edge_to_mincut.insert(edge, (u, v));
        Ok(())
    }

    /// Update edge weight (called on every message send).
    ///
    /// Uses delete + insert since ruvector-mincut supports dynamic updates.
    pub fn update_weight(
        &mut self,
        edge: CommEdgeHandle,
        new_weight: f64,
    ) -> Result<(), PressureError> {
        let (u, v) = *self.edge_to_mincut.get(&edge)
            .ok_or(PressureError::UnknownEdge)?;
        let _ = self.mincut.delete_edge(u, v);
        self.mincut.insert_edge(u, v, new_weight)?;
        Ok(())
    }

    /// Compute the current minimum cut.
    ///
    /// Returns CutPressure indicating where the system should split.
    pub fn compute_pressure(&self) -> CutPressure {
        let cut = self.mincut.min_cut();
        CutPressure {
            min_cut_value: cut.value,
            cut_edges: self.translate_cut_edges(&cut),
            // ... translate partition sides
            computed_at_ns: now_ns(),
            ..Default::default()
        }
    }
}
```

**API mapping from `ruvector-mincut`:**

| mincut API | Hypervisor Use |
|-----------|----------------|
| `MinCutBuilder::new().exact().build()` | Initialize placement engine |
| `insert_edge(u, v, weight)` | Register CommEdge creation |
| `delete_edge(u, v)` | Register CommEdge destruction |
| `min_cut_value()` | Query current cut pressure |
| `min_cut()` -> `MinCutResult` | Get the actual cut for split decisions |
| `WitnessTree` | Certify that the computed cut is correct |

### 11.2 sparsifier Crate -> Efficient Graph State

The `ruvector-sparsifier` crate maintains a compressed shadow of the coherence graph. When the full graph becomes large (hundreds of partitions, thousands of edges), the sparsifier provides an approximate view that preserves spectral properties:

```rust
// ruvix-pressure/src/sparse_bridge.rs

use ruvector_sparsifier::{AdaptiveGeoSpar, SparseGraph, SparsifierConfig, Sparsifier};

/// Sparsified view of the coherence graph.
///
/// The full coherence graph tracks every CommEdge and its weight.
/// The sparsifier maintains a compressed version that preserves
/// the Laplacian energy within (1 +/- epsilon), enabling efficient
/// coherence score computation on large graphs.
pub struct SparseBridge {
    /// The full graph (source of truth)
    full_graph: SparseGraph,

    /// The sparsifier (compressed view)
    sparsifier: AdaptiveGeoSpar,

    /// Compression ratio
    compression: f64,
}

impl SparseBridge {
    pub fn new(epsilon: f64) -> Self {
        let full_graph = SparseGraph::new();
        let config = SparsifierConfig {
            epsilon,
            ..Default::default()
        };
        let sparsifier = AdaptiveGeoSpar::build(&full_graph, config)
            .expect("sparsifier init");
        Self {
            full_graph,
            sparsifier,
            compression: 1.0,
        }
    }

    /// Add a CommEdge to the graph.
    pub fn add_edge(
        &mut self,
        u: usize,
        v: usize,
        weight: f64,
    ) -> Result<(), PressureError> {
        self.full_graph.add_edge(u, v, weight);
        self.sparsifier.insert_edge(u, v, weight)?;
        self.compression = self.sparsifier.compression_ratio();
        Ok(())
    }

    /// Get the sparsified graph for coherence computation.
    ///
    /// The solver crate operates on this compressed graph,
    /// not the full graph.
    pub fn sparsified(&self) -> &SparseGraph {
        self.sparsifier.sparsifier()
    }

    /// Audit sparsifier quality.
    pub fn audit(&self) -> bool {
        self.sparsifier.audit().passed
    }
}
```

**API mapping from `ruvector-sparsifier`:**

| sparsifier API | Hypervisor Use |
|---------------|----------------|
| `SparseGraph::from_edges()` | Build initial coherence graph |
| `AdaptiveGeoSpar::build()` | Create compressed view |
| `insert_edge()` / `delete_edge()` | Dynamic graph updates |
| `sparsifier()` -> `&SparseGraph` | Feed to solver for coherence |
| `audit()` -> `AuditResult` | Verify compression quality |
| `compression_ratio()` | Monitor graph efficiency |

### 11.3 solver Crate -> Coherence Score Computation

The `ruvector-solver` crate computes coherence scores by solving Laplacian systems on the sparsified coherence graph:

```rust
// ruvix-pressure/src/coherence_solver.rs

use ruvector_solver::traits::{SolverEngine, SparseLaplacianSolver};
use ruvector_solver::neumann::NeumannSolver;
use ruvector_solver::types::{CsrMatrix, ComputeBudget};

/// Coherence score computation via Laplacian solver.
///
/// The coherence score of a partition is derived from the
/// effective resistance between its internal nodes. Low
/// effective resistance = high coherence (tightly coupled).
pub struct CoherenceSolver {
    /// The solver engine
    solver: NeumannSolver,

    /// Compute budget per invocation
    budget: ComputeBudget,
}

impl CoherenceSolver {
    pub fn new() -> Self {
        Self {
            solver: NeumannSolver::new(1e-4, 200), // tolerance, max_iter
            budget: ComputeBudget::default(),
        }
    }

    /// Compute the coherence score for a partition.
    ///
    /// Uses the sparsified Laplacian to compute average effective
    /// resistance between all pairs of tasks in the partition.
    /// Lower resistance = higher coherence.
    pub fn compute_coherence(
        &self,
        partition: &Partition,
        sparse_graph: &SparseGraph,
    ) -> Result<CoherenceScore, PressureError> {
        // 1. Extract the subgraph for this partition
        let subgraph = extract_partition_subgraph(partition, sparse_graph);

        // 2. Build Laplacian matrix
        let laplacian = build_laplacian(&subgraph);

        // 3. Compute effective resistance between task pairs
        let mut total_resistance = 0.0;
        let mut pairs = 0;
        let task_ids: Vec<usize> = partition.tasks.keys()
            .map(|t| t.index())
            .collect();

        for i in 0..task_ids.len() {
            for j in (i+1)..task_ids.len() {
                let r = self.solver.effective_resistance(
                    &laplacian,
                    task_ids[i],
                    task_ids[j],
                    &self.budget,
                )?;
                total_resistance += r;
                pairs += 1;
            }
        }

        // 4. Normalize: coherence = 1 / (1 + avg_resistance)
        let avg_resistance = if pairs > 0 {
            total_resistance / pairs as f64
        } else {
            0.0
        };
        let coherence_value = 1.0 / (1.0 + avg_resistance);

        Ok(CoherenceScore {
            value: coherence_value,
            task_contributions: compute_per_task_contributions(
                &laplacian, &task_ids, &self.solver, &self.budget,
            ),
            computed_at_ns: now_ns(),
            stale: false,
        })
    }
}
```

**API mapping from `ruvector-solver`:**

| solver API | Hypervisor Use |
|-----------|----------------|
| `NeumannSolver::new(tol, max_iter)` | Create solver for coherence computation |
| `solve(&matrix, &rhs)` -> `SolverResult` | General sparse linear solve |
| `effective_resistance(laplacian, s, t)` | Core coherence metric between task pairs |
| `estimate_complexity(profile, n)` | Budget estimation before solving |
| `ComputeBudget` | Bound solver computation per epoch |

### 11.4 Full Pressure Engine Pipeline

The three crates form a pipeline that runs every scheduler epoch:

```
CommEdge weight updates (per message)
        |
        v
[ruvector-sparsifier]  -- maintain compressed coherence graph
        |
        v
[ruvector-solver]      -- compute coherence scores from Laplacian
        |
        v
[ruvector-mincut]      -- compute cut pressure from communication graph
        |
        v
Scheduler decisions:
  - Task priority adjustment (Flow mode)
  - Partition split/merge triggers
  - Agent migration signals
  - Tier promotion/demotion hints
```

```rust
// ruvix-pressure/src/engine.rs

/// The unified pressure engine.
///
/// Combines sparsifier, solver, and mincut into a single subsystem
/// that the scheduler queries every epoch.
pub struct PressureEngine {
    /// Sparsified coherence graph
    sparse: SparseBridge,

    /// Mincut for split/merge decisions
    mincut: MinCutBridge,

    /// Coherence solver
    solver: CoherenceSolver,

    /// Epoch counter
    epoch: u64,

    /// Epoch duration in nanoseconds
    epoch_duration_ns: u64,

    /// Cached results (valid for one epoch)
    cached_coherence: BTreeMap<PartitionId, CoherenceScore>,
    cached_pressure: Option<CutPressure>,
}

impl PressureEngine {
    /// Called every scheduler epoch.
    ///
    /// Recomputes coherence scores and cut pressure.
    pub fn tick(
        &mut self,
        partitions: &[Partition],
    ) -> EpochResult {
        self.epoch += 1;

        // 1. Decay edge weights (exponential decay per epoch)
        self.sparse.decay_weights(0.95);
        self.mincut.decay_weights(0.95);

        // 2. Audit sparsifier quality
        if !self.sparse.audit() {
            self.sparse.rebuild();
        }

        // 3. Recompute coherence scores
        for partition in partitions {
            let score = self.solver.compute_coherence(
                partition,
                self.sparse.sparsified(),
            );
            if let Ok(s) = score {
                self.cached_coherence.insert(partition.id, s);
            }
        }

        // 4. Recompute cut pressure
        self.cached_pressure = Some(self.mincut.compute_pressure());

        // 5. Evaluate structural changes
        let actions = evaluate_structural_changes(
            partitions,
            self,
            &StructuralConfig::default(),
        );

        EpochResult {
            epoch: self.epoch,
            actions,
            coherence_scores: self.cached_coherence.clone(),
            cut_pressure: self.cached_pressure.clone(),
        }
    }

    /// Called on every CommEdge message send.
    ///
    /// Incrementally updates edge weights in both the sparsifier
    /// and the mincut structure.
    pub fn on_message_sent(
        &mut self,
        edge: CommEdgeHandle,
        bytes: usize,
    ) {
        if let Some((u, v)) = self.mincut.edge_to_mincut.get(&edge) {
            let new_weight = bytes as f64; // Simplified; real impl accumulates
            let _ = self.sparse.update_weight(*u, *v, new_weight);
            let _ = self.mincut.update_weight(edge, new_weight);
        }
    }
}
```

---

## 12. What Makes RVM Different

### 12.1 Comparison Matrix

| Property | KVM/QEMU | Firecracker | seL4 | RVM |
|----------|----------|-------------|------|-------|
| **Abstraction unit** | VM (full hardware) | microVM (minimal HW) | Thread + address space | Coherence domain (partition) |
| **Device model** | Full QEMU emulation | Minimal virtio | Passthrough | Time-bounded leases |
| **Isolation basis** | EPT/stage-2 | EPT/stage-2 | Capabilities + page tables | Capabilities + stage-2 + graph theory |
| **Scheduling** | Linux CFS | Linux CFS | Priority-based | Graph-pressure-driven, 3 modes |
| **IPC** | Virtio rings | VSOCK | Synchronous IPC | Zero-copy CommEdges with coherence tracking |
| **Audit** | None built-in | None built-in | Formal proof (binary level) | Witness log (every privileged action) |
| **Mutation control** | None | None | Capability rights | Proof-gated (3-tier cryptographic verification) |
| **Memory model** | Demand paging | Demand paging (host) | Typed memory objects | Tiered (Hot/Warm/Dormant/Cold), no demand paging |
| **Dynamic reconfiguration** | VM migration (external) | Snapshot/restore | Static CNode tree | Mincut-driven split/merge/migrate |
| **Graph awareness** | None | None | None | Native: mincut, sparsifier, solver integrated |
| **Agent-native** | No | No (but fast boot) | No | Yes: WASM partitions, lifecycle management |
| **Written in** | C (QEMU) + C (Linux) | Rust (VMM) + C (Linux) | C + Isabelle/HOL proofs | Rust (< 500 lines asm per platform) |
| **Host OS dependency** | Linux required | Linux required | None (standalone) | None (standalone) |

### 12.2 Key Differentiators

**1. Graph-theory-native isolation.** No other hypervisor uses mincut algorithms to determine isolation boundaries. KVM and Firecracker rely on the human to define VM boundaries. seL4 relies on the human to define CNode trees. RVM computes boundaries dynamically from observed communication patterns.

**2. Proof-gated mutation.** seL4 has formal verification of the kernel binary, but does not gate runtime state mutations with proofs. RVM requires a cryptographic proof for every mutation, checked at three tiers (Reflex < 100ns, Standard < 100us, Deep < 10ms).

**3. Witness-native auditability.** The witness log is not an optional feature or an afterthought. It is woven into every syscall path. Every privileged action produces a 64-byte witness record with a chained hash. The log is tamper-evident and supports deterministic replay.

**4. Coherence-driven scheduling.** The scheduler does not just balance CPU load. It considers the graph structure of partition communication, novelty of incoming data, and structural risk of pending mutations. This is a fundamentally different optimization target.

**5. Tiered memory without demand paging.** By eliminating page faults from the critical path and replacing them with explicit tier transitions, RVM achieves deterministic latency while still supporting memory overcommit through compression and serialization.

**6. Agent-native runtime.** WASM agents are first-class entities with defined lifecycle states (spawn, execute, migrate, hibernate, reconstruct). The hypervisor understands agent communication patterns and uses them to optimize placement.

### 12.3 Threat Model

RVM assumes:

- **Trusted**: The hypervisor binary (verified boot with ML-DSA-65 signatures), hardware
- **Untrusted**: All partition code, all agent WASM modules, all inter-partition messages
- **Partially trusted**: Device firmware (isolated via leases with bounded time)

The capability system ensures that a compromised partition cannot:
- Access memory outside its stage-2 address space
- Send messages on edges it does not hold capabilities for
- Mutate kernel state without a valid proof
- Read the witness log without WITNESS capability
- Acquire devices without LEASE capability
- Modify another partition's coherence score

### 12.4 Performance Targets

| Operation | Target Latency | Bound |
|-----------|---------------|-------|
| Hypercall (syscall) round-trip | < 1 us | Hardware trap + capability check |
| Zero-copy message send | < 500 ns | Ring buffer enqueue + witness record |
| Notification signal | < 200 ns | Atomic OR + virtual IRQ inject |
| Proof verification (Reflex) | < 100 ns | Hash comparison |
| Proof verification (Standard) | < 100 us | Merkle witness verification |
| Proof verification (Deep) | < 10 ms | Full coherence check via solver |
| Partition split | < 50 ms | Stage-2 table creation + region remapping |
| Agent migration | < 100 ms | State serialize + transfer + restore |
| Coherence score computation | < 5 ms per epoch | Laplacian solve on sparsified graph |
| Witness record write | < 50 ns | Cache-line-aligned append |

---

## Appendix A: Syscall Table (Extended for Hypervisor)

The Phase A syscall table (12 syscalls) is extended with hypervisor-specific operations:

| # | Syscall | Phase | Proof Required | Witnessed |
|---|---------|-------|----------------|-----------|
| 0 | `task_spawn` | A | No | Yes |
| 1 | `cap_grant` | A | No | Yes |
| 2 | `region_map` | A | No | Yes |
| 3 | `queue_send` | A | No | Yes |
| 4 | `queue_recv` | A | No | No (read-only) |
| 5 | `timer_wait` | A | No | No |
| 6 | `rvf_mount` | A | Yes | Yes |
| 7 | `attest_emit` | A | Yes | Yes |
| 8 | `vector_get` | A | No | No (read-only) |
| 9 | `vector_put_proved` | A | Yes | Yes |
| 10 | `graph_apply_proved` | A | Yes | Yes |
| 11 | `sensor_subscribe` | A | No | Yes |
| 12 | `partition_create` | B+ | Yes | Yes |
| 13 | `partition_split` | B+ | Yes | Yes |
| 14 | `partition_merge` | B+ | Yes | Yes |
| 15 | `partition_hibernate` | B+ | Yes | Yes |
| 16 | `partition_reconstruct` | B+ | Yes | Yes |
| 17 | `commedge_create` | B+ | Yes | Yes |
| 18 | `commedge_destroy` | B+ | Yes | Yes |
| 19 | `device_lease_acquire` | B+ | Yes | Yes |
| 20 | `device_lease_revoke` | B+ | Yes | Yes |
| 21 | `witness_read` | B+ | No | No (read-only) |
| 22 | `notify_signal` | B+ | No | Yes |
| 23 | `notify_wait` | B+ | No | No |

## Appendix B: New Crate Summary

| Crate | Purpose | Dependencies | Est. Lines |
|-------|---------|-------------|------------|
| `ruvix-partition` | Coherence domain manager | types, cap, region, hal | ~2,000 |
| `ruvix-commedge` | Inter-partition communication | types, cap, queue | ~1,200 |
| `ruvix-pressure` | mincut/sparsifier/solver bridge | ruvector-mincut, ruvector-sparsifier, ruvector-solver | ~1,800 |
| `ruvix-witness` | Append-only audit log + replay | types, physmem | ~1,500 |
| `ruvix-agent` | WASM agent runtime adapter | types, cap, partition, commedge | ~2,500 |
| `ruvix-riscv` | RISC-V HS-mode HAL | hal, types | ~2,000 |
| `ruvix-x86_64` | x86 VMX root HAL | hal, types | ~2,500 |

**Total new code: ~13,500 lines (Rust) + ~1,500 lines (assembly, 3 platforms)**

## Appendix C: Build and Test

```sh
# Build for QEMU AArch64 virt (hypervisor mode)
cargo build --target aarch64-unknown-none \
    --release \
    -p ruvix-nucleus \
    --features "baremetal,aarch64,hypervisor"

# Run on QEMU
qemu-system-aarch64 \
    -machine virt,virtualization=on,gic-version=3 \
    -cpu cortex-a72 \
    -m 1G \
    -smp 4 \
    -nographic \
    -kernel target/aarch64-unknown-none/release/ruvix

# Run unit tests (hosted, std feature)
cargo test --workspace --features "std,test-hosted"

# Run integration tests (QEMU)
cargo test --test qemu_integration --features "qemu-test"
```
