# RVM Security Model

## Status

**Draft** -- Research document for RVM bare-metal microhypervisor security architecture.

## Date

2026-04-04

## Scope

This document specifies the security model for RVM as a standalone, bare-metal, Rust-first
microhypervisor for agents and edge computing. RVM does NOT depend on Linux or KVM. It boots
directly on hardware (AArch64 primary, x86_64 secondary) and enforces all isolation through its
own MMU page tables, capability system, and proof-gated mutation protocol.

The security model builds on the primitives already implemented in Phase A (ruvix-types,
ruvix-cap, ruvix-proof, ruvix-region, ruvix-queue, ruvix-vecgraph, ruvix-nucleus) and extends
them for bare-metal operation with hardware-enforced isolation.

---

## 1. Capability-Based Authority

### 1.1 Design Philosophy

RVM enforces the principle of least authority through capabilities. There is no ambient
authority anywhere in the system. Every syscall requires an explicit capability handle that
authorizes the operation. This means:

- No global namespaces (no filesystem paths, no PIDs, no network ports accessible by name)
- No superuser or root -- the root task holds initial capabilities but cannot bypass the model
- No default permissions -- a newly spawned task has exactly the capabilities its parent
  explicitly grants via `cap_grant`
- No ambient access to hardware -- device MMIO regions, interrupt lines, and DMA channels
  are all gated by capabilities

### 1.2 Capability Structure

Capabilities are kernel-resident objects. User-space code never sees the raw capability; it
holds an opaque `CapHandle` that the kernel resolves through a per-task capability table.

```rust
/// The kernel-side capability. User space never sees this directly.
/// File: crates/ruvix/crates/types/src/capability.rs
#[repr(C)]
pub struct Capability {
    pub object_id: u64,          // Kernel object being referenced
    pub object_type: ObjectType, // Region, Queue, VectorStore, Task, etc.
    pub rights: CapRights,       // Bitmap of permitted operations
    pub badge: u64,              // Caller-visible demux identifier
    pub epoch: u64,              // Revocation epoch (stale handles detected)
}
```

**Rights bitmap** (from `crates/ruvix/crates/types/src/capability.rs`):

| Right | Bit | Authorizes |
|-------|-----|------------|
| `READ` | 0 | `vector_get`, `queue_recv`, region read |
| `WRITE` | 1 | `queue_send`, region append/slab write |
| `GRANT` | 2 | `cap_grant` to another task |
| `REVOKE` | 3 | Revoke capabilities derived from this one |
| `EXECUTE` | 4 | Task entry point, RVF component execution |
| `PROVE` | 5 | Generate proof tokens (`vector_put_proved`, `graph_apply_proved`) |
| `GRANT_ONCE` | 6 | Non-transitive grant (derived cap cannot re-grant) |

### 1.3 Capability Delegation and Attenuation

Delegation follows strict monotonic attenuation: a task can only grant capabilities it holds,
and the granted rights must be a subset of the held rights. This is enforced at the type level
in `Capability::derive()`:

```rust
/// Derive a capability with equal or fewer rights.
/// Returns None if rights escalation is attempted or GRANT right is absent.
pub fn derive(&self, new_rights: CapRights, new_badge: u64) -> Option<Self> {
    if !self.has_rights(CapRights::GRANT) { return None; }
    if !new_rights.is_subset_of(self.rights) { return None; }
    // GRANT_ONCE strips GRANT from the derived cap
    let final_rights = if self.rights.contains(CapRights::GRANT_ONCE) {
        new_rights.difference(CapRights::GRANT).difference(CapRights::GRANT_ONCE)
    } else {
        new_rights
    };
    Some(Self { rights: final_rights, badge: new_badge, ..*self })
}
```

**Delegation depth limit**: Maximum 8 levels (configurable per RVF manifest). The derivation
tree tracks the full chain, and audit flags chains deeper than 4 (AUDIT_DEPTH_WARNING_THRESHOLD).

### 1.4 Capability Revocation

Revocation propagates through the derivation tree. When a capability is revoked:

1. The capability's epoch is incremented in the kernel's object table
2. All entries in the derivation tree rooted at the revoked capability are invalidated
3. Any held `CapHandle` referencing the old epoch returns `KernelError::StaleCapability`

This is O(d) where d is the number of derived capabilities, bounded by the delegation depth
limit and the per-task capability table size (1024 entries max).

### 1.5 How This Differs from DAC/MAC

| Property | DAC (Unix) | MAC (SELinux) | Capability (RVM) |
|----------|-----------|---------------|-------------------|
| Authority source | User identity | System-wide policy labels | Explicit token per object |
| Ambient authority | Yes (UID 0) | Yes (unconfined domain) | None |
| Confused deputy | Possible | Mitigated by labels | Prevented by design |
| Delegation | chmod/chown | Policy reload | `cap_grant` with attenuation |
| Revocation | File permission change | Policy reload | Tree-propagating, epoch-based |
| Granularity | File/directory | Type/role/level | Per-object, per-right |

The critical difference: in RVM, authority is carried by the message, not the sender's
identity. A task cannot access a resource simply because of "who it is" -- it must present
a valid capability handle that was explicitly granted to it through a traceable delegation chain.

---

## 2. Proof-Gated Mutation

### 2.1 Invariant

**No state mutation without a valid proof token.** This is a kernel invariant, not a policy.
The kernel physically prevents mutation of vector stores, graph stores, and RVF mounts without
a `ProofToken` that passes all verification steps. Read operations (`vector_get`, `queue_recv`)
do not require proofs.

### 2.2 What Constitutes a Valid Proof

A proof token must pass six verification steps (implemented in
`crates/ruvix/crates/vecgraph/src/proof_policy.rs` `ProofVerifier::verify()`):

1. **Capability check**: The calling task must hold a capability with `PROVE` right on the
   target object
2. **Hash match**: `proof.mutation_hash == expected_mutation_hash` -- the proof authorizes
   exactly the mutation being applied
3. **Tier satisfaction**: `proof.tier >= policy.required_tier` -- higher tiers satisfy lower
   requirements (Deep satisfies Standard satisfies Reflex)
4. **Time bound**: `current_time_ns <= proof.valid_until_ns` -- proofs expire
5. **Validity window**: The window `proof.valid_until_ns - current_time_ns` must not exceed
   `policy.max_validity_window_ns` (prevents pre-computing proofs far in advance)
6. **Nonce uniqueness**: Each nonce can be consumed exactly once (ring buffer of 64 recent
   nonces prevents replay)

### 2.3 Proof Tiers

Three tiers provide a latency/assurance tradeoff:

| Tier | Name | Latency Budget | Payload | Use Case |
|------|------|---------------|---------|----------|
| 0 | Reflex | <1 us | SHA-256 hash | High-frequency vector updates |
| 1 | Standard | <100 us | Merkle witness (root + path) | Graph mutations |
| 2 | Deep | <10 ms | Coherence certificate (scores + partition + signature) | Structural changes |

### 2.4 Proof Lifecycle

```
  Task                    Proof Engine (RVF component)              Kernel
    |                              |                                  |
    |-- prepare mutation --------->|                                  |
    |   (compute mutation_hash)    |                                  |
    |                              |-- evaluate coherence state ----->|
    |                              |<-- current state ----------------|
    |                              |                                  |
    |<-- ProofToken ---------------|                                  |
    |   (hash, tier, payload,      |                                  |
    |    expiry, nonce)            |                                  |
    |                              |                                  |
    |-- syscall (token) ------------------------------------------>|
    |                                                               |
    |                              Kernel verifies 6 steps:         |
    |                              1. PROVE right on cap            |
    |                              2. Hash match                    |
    |                              3. Tier >= policy                |
    |                              4. Not expired                   |
    |                              5. Window not too wide           |
    |                              6. Nonce not reused              |
    |                                                               |
    |<-- ProofAttestation (82 bytes) -------------------------------|
    |                              |                                  |
    |                              |   Witness record appended       |
```

### 2.5 What Requires a Proof

| Operation | Proof Required | Minimum Tier |
|-----------|---------------|-------------|
| `region_map` | Yes (capability proof) | N/A -- capability check only |
| `vector_put_proved` | Yes | Per-store ProofPolicy |
| `graph_apply_proved` | Yes | Per-store ProofPolicy |
| `rvf_mount` | Yes | Deep (signature verification) |
| `vector_get` | No | N/A |
| `queue_send` / `queue_recv` | No | N/A (capability-gated only) |
| `task_spawn` | No | N/A (capability-gated only) |
| `cap_grant` | No | N/A (GRANT right required) |
| `timer_wait` | No | N/A |
| `attest_emit` | Yes (proof consumed) | Per-operation |
| `sensor_subscribe` | No | N/A (capability-gated only) |

### 2.6 Proof-Gated Device Mapping (Bare-Metal Extension)

On bare metal, device MMIO regions are mapped into a task's address space through `region_map`
with a `RegionPolicy::DeviceMmio` variant (new for Phase B). This mapping requires:

1. A capability with `READ` and/or `WRITE` rights on the device object
2. A `ProofToken` with tier >= Standard proving the task's intent matches the device mapping
3. The device must not already be mapped to another partition (exclusive lease)

```rust
/// Extended region policy for bare-metal device access.
/// New for Phase B -- extends the existing RegionPolicy enum.
pub enum RegionPolicy {
    Immutable,
    AppendOnly { max_size: usize },
    Slab { slot_size: usize, slot_count: usize },
    /// Device MMIO region. Mapped as uncacheable, device memory.
    /// Requires proof-gated capability for mapping.
    DeviceMmio {
        phys_base: u64,    // Physical base address of MMIO range
        size: usize,       // Size in bytes
        device_id: u32,    // Kernel-assigned device identifier
    },
}
```

### 2.7 Proof-Gated Migration

Partition migration (moving a task and its state from one physical node to another in a RVM
mesh) requires a Deep-tier proof containing:

- Coherence certificate showing the partition's state is consistent
- Source and destination node attestation (both nodes are trusted)
- Hash of the serialized partition state

Without this proof, the kernel refuses to serialize or deserialize partition state.

```rust
/// Trait for migration authorization. Implemented by the migration subsystem.
pub trait MigrationAuthority {
    /// Verify that migration of this partition is authorized.
    /// Returns the serialized partition state only if proof validates.
    fn authorize_migration(
        &mut self,
        partition_id: u32,
        destination_attestation: &ProofAttestation,
        proof: &ProofToken,
    ) -> Result<SerializedPartition, KernelError>;

    /// Accept an incoming migrated partition.
    /// Verifies the source attestation and proof before instantiating.
    fn accept_migration(
        &mut self,
        serialized: &SerializedPartition,
        source_attestation: &ProofAttestation,
        proof: &ProofToken,
    ) -> Result<PartitionHandle, KernelError>;
}
```

### 2.8 Proof-Gated Partition Merge/Split

Graph partitions (mincut boundaries in the vecgraph store) can only be merged or split with a
Deep-tier proof that includes the coherence impact analysis:

```rust
pub enum GraphMutationKind {
    AddNode { /* ... */ },
    RemoveNode { /* ... */ },
    AddEdge { /* ... */ },
    RemoveEdge { /* ... */ },
    UpdateWeight { /* ... */ },
    /// Merge two partitions. Requires Deep-tier proof with coherence cert.
    MergePartitions {
        source_partition: u32,
        target_partition: u32,
    },
    /// Split a partition at a mincut boundary. Requires Deep-tier proof.
    SplitPartition {
        partition: u32,
        cut_specification: MinCutSpec,
    },
}
```

---

## 3. Witness-Native Audit

### 3.1 Design Principle

Every privileged action in RVM emits a witness record to the kernel's append-only witness
log. "Privileged action" means any syscall that mutates kernel state: vector writes, graph
mutations, RVF mounts, task spawns, capability grants, region mappings.

### 3.2 Witness Record Format

Each record is 96 bytes, compact enough to sustain thousands of records per second on embedded
hardware without blocking the syscall path:

```rust
/// 96-byte witness record.
/// File: crates/ruvix/crates/nucleus/src/witness_log.rs
#[repr(C)]
pub struct WitnessRecord {
    pub sequence: u64,            // Monotonically increasing (8 bytes)
    pub kind: WitnessRecordKind,  // Boot, Mount, VectorMutation, etc. (1 byte)
    pub timestamp_ns: u64,        // Nanoseconds since boot (8 bytes)
    pub mutation_hash: [u8; 32],  // SHA-256 of the mutation data (32 bytes)
    pub attestation_hash: [u8; 32], // Hash of the proof attestation (32 bytes)
    pub resource_id: u64,         // Object identifier (8 bytes)
    // 7 bytes padding to 96
}
```

**Record kinds**:

| Kind | Value | Emitted By |
|------|-------|-----------|
| `Boot` | 0 | `kernel_entry` at boot completion |
| `Mount` | 1 | `rvf_mount` syscall |
| `VectorMutation` | 2 | `vector_put_proved` syscall |
| `GraphMutation` | 3 | `graph_apply_proved` syscall |
| `Checkpoint` | 4 | Periodic state snapshots |
| `ReplayComplete` | 5 | After replaying from checkpoint |
| `CapGrant` | 6 | `cap_grant` syscall (proposed extension) |
| `CapRevoke` | 7 | Capability revocation (proposed extension) |
| `TaskSpawn` | 8 | `task_spawn` syscall (proposed extension) |
| `DeviceMap` | 9 | Device MMIO mapping (proposed extension) |

### 3.3 Tamper Evidence

The witness log must be tamper-evident. The current Phase A implementation uses simple
append-only semantics with FNV-1a hashing. For bare-metal, the following extensions are
required:

**Hash chaining**: Each witness record includes the hash of the previous record, forming a
Merkle-like chain. Tampering with any record invalidates all subsequent records.

```rust
/// Extended witness record with hash chaining for tamper evidence.
pub struct ChainedWitnessRecord {
    /// The base witness record (96 bytes).
    pub record: WitnessRecord,
    /// SHA-256 hash of the previous record's serialized bytes.
    /// For the first record (sequence 0), this is all zeros.
    pub prev_hash: [u8; 32],
    /// SHA-256(serialize(record) || prev_hash). Computed by the kernel.
    pub chain_hash: [u8; 32],
}
```

**TEE signing (when available)**: On hardware with TrustZone (Raspberry Pi 4/5), witness
records can be signed by the Secure World using a device-unique key. This means even a
compromised kernel (EL1) cannot forge witness entries:

```rust
/// Trait for hardware-backed witness signing.
pub trait WitnessSigner {
    /// Sign a chained witness record using hardware-bound key.
    /// On AArch64 with TrustZone, this issues an SMC to Secure World.
    /// On platforms without TEE, returns None (software chain only).
    fn sign_witness(&self, record: &ChainedWitnessRecord) -> Option<[u8; 64]>;

    /// Verify a signed witness record.
    fn verify_witness_signature(
        &self,
        record: &ChainedWitnessRecord,
        signature: &[u8; 64],
    ) -> bool;
}
```

### 3.4 Replayability and Forensics

The witness log, combined with periodic checkpoints, enables deterministic replay:

1. **Checkpoint**: The kernel serializes all vector stores, graph stores, capability tables,
   and scheduler state to an immutable region. A `WitnessRecordKind::Checkpoint` record
   captures the state hash and the witness sequence number at checkpoint time.

2. **Replay**: Starting from a checkpoint, the kernel replays all witness records in sequence
   order, re-applying each mutation. Because mutations are deterministic (same proof token +
   same state = same result), the final state is identical.

3. **Forensic query**: External tools can load the witness log and answer questions like:
   - "Which task mutated vector store X between timestamps T1 and T2?"
   - "What was the coherence score before and after each graph mutation?"
   - "Has the hash chain been broken?" (indicates tampering)

### 3.5 Witness-Enabled Rollback/Recovery

If a coherence violation is detected (coherence score drops below the configured threshold),
the kernel can:

1. Stop accepting new mutations to the affected partition
2. Find the most recent checkpoint where coherence was above threshold
3. Replay witnesses from that checkpoint, skipping the offending mutation
4. Resume normal operation from the corrected state

This requires the offending mutation to be identified by its witness record (the mutation_hash
and attestation_hash pinpoint exactly which operation caused the violation).

---

## 4. Isolation Model

### 4.1 Partition Isolation Guarantees

RVM partitions are the unit of isolation. Each partition consists of:

- One or more tasks sharing a capability namespace
- A set of regions (memory objects) accessible only through capabilities held by those tasks
- Queue endpoints for controlled inter-partition communication

**Isolation guarantee**: A partition cannot access any memory, device, or kernel object for
which it does not hold a valid capability. This is enforced at two levels:

1. **Software**: The capability table lookup in every syscall rejects invalid or stale handles
2. **Hardware**: MMU page tables enforce that each partition's regions are mapped only in that
   partition's address space, with no overlapping physical pages between partitions
   (except explicitly shared immutable regions)

### 4.2 MMU-Enforced Memory Isolation (Bare Metal)

On bare metal, RVM directly controls the AArch64 MMU. Each partition gets its own translation
tables loaded via `TTBR0_EL1` on context switch:

```rust
/// Per-partition page table management.
/// Kernel mappings use TTBR1_EL1 (shared across all partitions).
/// Partition mappings use TTBR0_EL1 (swapped on context switch).
pub trait PartitionAddressSpace {
    /// Create a new empty address space for a partition.
    fn create() -> Result<Self, KernelError> where Self: Sized;

    /// Map a region into this partition's address space.
    /// Physical pages are allocated from the kernel's physical allocator.
    /// Page table entries enforce the region's policy:
    ///   Immutable  -> PTE_USER | PTE_RO | PTE_CACHEABLE
    ///   AppendOnly -> PTE_KERNEL_RW | PTE_CACHEABLE (user writes via syscall)
    ///   Slab       -> PTE_KERNEL_RW | PTE_CACHEABLE (user writes via syscall)
    ///   DeviceMmio -> PTE_USER | PTE_DEVICE | PTE_nG (non-global, per-partition)
    fn map_region(
        &mut self,
        region: &RegionDescriptor,
        phys_pages: &[PhysFrame],
    ) -> Result<VirtAddr, KernelError>;

    /// Unmap a region, invalidating all TLB entries for those pages.
    fn unmap_region(&mut self, virt_addr: VirtAddr, size: usize) -> Result<(), KernelError>;

    /// Activate this address space (write to TTBR0_EL1 + TLBI).
    unsafe fn activate(&self);
}
```

**Critical invariant**: The kernel NEVER maps the same physical page as writable in two
different partitions' address spaces simultaneously. Immutable regions may be shared read-only
(content-addressable deduplication is safe for immutable data).

### 4.3 EL1/EL0 Separation

- **EL1 (kernel mode)**: All kernel code, syscall handlers, interrupt handlers, scheduler,
  capability table, proof verifier, witness log
- **EL0 (user mode)**: All RVF components, WASM runtimes, AgentDB, all application code

Syscalls transition EL0 -> EL1 via the SVC instruction. The exception handler in EL1 validates
the capability before dispatching to the syscall implementation. Return to EL0 uses ERET.

No EL0 code can:
- Read or write kernel memory (TTBR1_EL1 mappings are PTE_KERNEL_RW)
- Modify page tables (page table pages are not mapped in EL0)
- Disable interrupts (only EL1 can mask IRQs via DAIF)
- Access device MMIO unless explicitly mapped through a capability

### 4.4 Side-Channel Mitigation

#### 4.4.1 Spectre v1 (Bounds Check Bypass)

- All array accesses in the kernel use bounds-checked indexing (Rust's default)
- The `CapabilityTable` uses `get()` returning `Option<&T>`, never unchecked indexing
- Critical paths include an `lfence` / `csdb` barrier after bounds checks on the syscall
  dispatch path

```rust
/// Spectre-safe capability table lookup.
/// The index is bounds-checked, and a speculation barrier follows.
pub fn lookup(&self, handle: CapHandle) -> Option<&Capability> {
    let idx = handle.raw().id as usize;
    if idx >= self.entries.len() {
        return None;
    }
    // AArch64: CSDB (Consumption of Speculative Data Barrier)
    // Prevents speculative use of the result before bounds check resolves
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("csdb"); }
    self.entries.get(idx).and_then(|e| e.as_ref())
}
```

#### 4.4.2 Spectre v2 (Branch Target Injection)

- AArch64: Enable branch prediction barriers via `SCTLR_EL1` configuration
- On context switch between partitions: flush branch predictor state
  (`IC IALLU` + `TLBI VMALLE1IS` + `DSB ISH` + `ISB`)
- Kernel compiled with `-Zbranch-protection=bti` (Branch Target Identification)

#### 4.4.3 Meltdown (Rogue Data Cache Load)

- AArch64 is not vulnerable to Meltdown when Privileged Access Never (PAN) is enabled
- RVM enables PAN via `SCTLR_EL1.PAN = 1` at boot
- Kernel accesses user memory only through explicit copy routines that temporarily disable PAN

#### 4.4.4 Microarchitectural Data Sampling (MDS)

- On x86_64 (secondary target): `VERW`-based buffer clearing on every kernel exit
- On AArch64 (primary target): Not vulnerable to known MDS variants
- Defense in depth: all sensitive kernel data structures are allocated in dedicated slab
  regions that are never shared across partitions

### 4.5 Time Isolation

Timing side channels are mitigated through several mechanisms:

1. **Fixed-time capability lookup**: The capability table lookup path executes in constant
   time regardless of whether the capability is found or not (compare all entries, select
   result at the end)

2. **Scheduler noise injection**: The scheduler adds a small random jitter (0-10 us) to
   context switch timing to prevent a partition from inferring another partition's behavior
   from scheduling patterns

3. **Timer virtualization**: Each partition sees a virtual timer (`CNTVCT_EL0`) that advances
   at the configured rate but does not leak information about other partitions' execution.
   The kernel programs `CNTV_CVAL_EL0` per-partition.

4. **Constant-time proof verification**: The `ProofVerifier::verify()` path is written to
   avoid early returns that would leak information about which check failed. All six checks
   execute, and only the final result is returned.

```rust
/// Constant-time proof verification to prevent timing side channels.
/// All checks execute regardless of early failures.
pub fn verify_constant_time(
    &mut self,
    proof: &ProofToken,
    expected_hash: &[u8; 32],
    current_time_ns: u64,
    capability: &Capability,
) -> Result<ProofAttestation, KernelError> {
    let mut valid = true;

    // All checks execute -- no early return
    valid &= capability.has_rights(CapRights::PROVE);
    valid &= proof.mutation_hash == *expected_hash;
    valid &= self.policy.tier_satisfies(proof.tier);
    valid &= !proof.is_expired(current_time_ns);
    valid &= (proof.valid_until_ns.saturating_sub(current_time_ns))
        <= self.policy.max_validity_window_ns;
    let nonce_ok = self.nonce_tracker.check_and_mark(proof.nonce);
    valid &= nonce_ok;

    if valid {
        Ok(self.create_attestation(proof, current_time_ns))
    } else {
        // Roll back nonce if overall verification failed
        if nonce_ok {
            self.nonce_tracker.unmark(proof.nonce);
        }
        Err(KernelError::ProofRejected)
    }
}
```

### 4.6 Coherence Domain Isolation

Each vector store and graph store belongs to a coherence domain. Coherence domains provide an
additional layer of isolation at the semantic level:

- Mutations within a coherence domain are evaluated against that domain's coherence config
- Cross-domain references require explicit capability-mediated linking
- Coherence violations in one domain do not affect other domains
- Each domain has its own proof policy, nonce tracker, and witness region

```rust
/// Coherence domain configuration.
pub struct CoherenceDomain {
    pub domain_id: u32,
    pub vector_stores: &[VectorStoreHandle],
    pub graph_stores: &[GraphHandle],
    pub proof_policy: ProofPolicy,
    pub min_coherence_score: u16,  // 0-10000 (0.00-1.00)
    pub isolation_level: DomainIsolationLevel,
}

pub enum DomainIsolationLevel {
    /// Stores in this domain share no physical pages with other domains.
    Full,
    /// Read-only immutable data may be shared across domains.
    SharedImmutable,
}
```

---

## 5. Device Security

### 5.1 Lease-Based Device Access

Devices are not permanently assigned to partitions. Instead, RVM uses time-bounded,
revocable leases:

```rust
/// A time-bounded, revocable lease on a device.
pub struct DeviceLease {
    /// Capability handle authorizing device access.
    pub cap: CapHandle,
    /// Device identifier (kernel-assigned, not hardware address).
    pub device_id: DeviceId,
    /// Lease start time (nanoseconds since boot).
    pub granted_at_ns: u64,
    /// Lease expiry (0 = no expiry, must be explicitly revoked).
    pub expires_at_ns: u64,
    /// Rights on the device (READ for sensors, WRITE for actuators, both for DMA).
    pub rights: CapRights,
    /// The MMIO region mapped for this lease (None if not yet mapped).
    pub mmio_region: Option<RegionHandle>,
}

/// Trait for the device lease manager.
pub trait DeviceLeaseManager {
    /// Request a lease on a device. Requires a capability with appropriate rights.
    /// The lease is time-bounded; after expiry, the mapping is automatically torn down.
    fn request_lease(
        &mut self,
        device_id: DeviceId,
        cap: CapHandle,
        duration_ns: u64,
    ) -> Result<DeviceLease, KernelError>;

    /// Renew an existing lease. Must be called before expiry.
    fn renew_lease(
        &mut self,
        lease: &mut DeviceLease,
        additional_ns: u64,
    ) -> Result<(), KernelError>;

    /// Revoke a lease immediately. Tears down MMIO mapping and flushes DMA.
    fn revoke_lease(&mut self, lease: DeviceLease) -> Result<(), KernelError>;

    /// Check if a lease is still valid.
    fn is_lease_valid(&self, lease: &DeviceLease, current_time_ns: u64) -> bool;
}
```

**Lease lifecycle**:

1. Partition requests a lease via `request_lease()` with a capability
2. Kernel checks the capability has appropriate rights on the device object
3. Kernel maps the device's MMIO region into the partition's address space as
   `RegionPolicy::DeviceMmio` with PTE_DEVICE (uncacheable) flags
4. Kernel programs an expiry timer; when it fires, the lease is automatically torn down
5. On teardown: MMIO pages are unmapped, TLB is flushed, DMA channels are reset

### 5.2 DMA Isolation

DMA is the most dangerous hardware capability because DMA engines can read/write arbitrary
physical memory. RVM uses a layered defense:

#### 5.2.1 With IOMMU (Preferred)

On platforms with an IOMMU (ARM SMMU, Intel VT-d), the kernel programs the IOMMU's page
tables to restrict each device's DMA to only the physical pages belonging to the leaseholder's
regions:

```rust
/// IOMMU-based DMA isolation.
pub trait IommuController {
    /// Create a DMA mapping for a device, restricting it to the given physical pages.
    /// The device can only DMA to/from these pages and no others.
    fn map_device_dma(
        &mut self,
        device_id: DeviceId,
        allowed_pages: &[PhysFrame],
        direction: DmaDirection,
    ) -> Result<DmaMapping, KernelError>;

    /// Remove a DMA mapping, preventing the device from accessing those pages.
    fn unmap_device_dma(
        &mut self,
        device_id: DeviceId,
        mapping: DmaMapping,
    ) -> Result<(), KernelError>;

    /// Invalidate all DMA mappings for a device (called on lease revocation).
    fn invalidate_device(&mut self, device_id: DeviceId) -> Result<(), KernelError>;
}
```

#### 5.2.2 Without IOMMU (Bounce Buffers)

On platforms without an IOMMU (early Raspberry Pi models), DMA isolation uses bounce buffers:

1. The kernel allocates a dedicated physical region for DMA operations
2. Before a device-to-memory transfer, the kernel prepares the bounce buffer
3. After transfer completion, the kernel copies data from the bounce buffer to the
   partition's region (after validation)
4. The device never has direct access to partition memory

This is slower (extra copy) but maintains the isolation invariant. The
`crates/ruvix/crates/dma/` crate provides the abstraction layer.

```rust
/// Bounce buffer DMA isolation (fallback when no IOMMU).
pub struct BounceBufferDma {
    /// Kernel-owned physical region for DMA bounce.
    bounce_region: PhysRegion,
    /// Maximum bounce buffer size.
    max_bounce_size: usize,
}

impl BounceBufferDma {
    /// Execute a DMA transfer through the bounce buffer.
    /// The device only ever sees the bounce buffer's physical address.
    pub fn transfer(
        &mut self,
        device: DeviceId,
        partition_region: &RegionHandle,
        offset: usize,
        length: usize,
        direction: DmaDirection,
    ) -> Result<(), KernelError> {
        if length > self.max_bounce_size {
            return Err(KernelError::LimitExceeded);
        }
        match direction {
            DmaDirection::MemToDevice => {
                // Copy from partition region to bounce buffer
                self.copy_to_bounce(partition_region, offset, length)?;
                // Program DMA from bounce buffer to device
                self.start_dma(device, direction)?;
            }
            DmaDirection::DeviceToMem => {
                // Program DMA from device to bounce buffer
                self.start_dma(device, direction)?;
                // Wait for completion
                self.wait_completion()?;
                // Copy from bounce buffer to partition region (validated)
                self.copy_from_bounce(partition_region, offset, length)?;
            }
            DmaDirection::MemToMem => {
                return Err(KernelError::InvalidArgument);
            }
        }
        Ok(())
    }
}
```

### 5.3 Interrupt Routing Security

Each interrupt line is a kernel object accessed through capabilities:

1. **Interrupt capability**: A partition must hold a capability with `READ` right on an
   interrupt object to receive interrupts from that line
2. **Interrupt-to-queue routing**: Interrupts are delivered as messages on a queue
   (via `sensor_subscribe`), not as direct callbacks. This maintains the queue-based IPC
   model and prevents a malicious interrupt handler from running in kernel context.
3. **Priority ceiling**: Interrupt processing tasks have bounded priority to prevent a
   flood of interrupts from starving other partitions
4. **Rate limiting**: The kernel enforces a maximum interrupt rate per device. Interrupts
   exceeding the rate are queued and delivered at the rate limit.

```rust
/// Interrupt routing configuration.
pub struct InterruptRoute {
    /// Hardware interrupt number (e.g., GIC SPI number).
    pub irq_number: u32,
    /// Capability authorizing access to this interrupt.
    pub cap: CapHandle,
    /// Queue where interrupt messages are delivered.
    pub target_queue: QueueHandle,
    /// Maximum interrupt rate (interrupts per second). 0 = unlimited.
    pub rate_limit_hz: u32,
    /// Priority ceiling for the interrupt processing task.
    pub priority_ceiling: TaskPriority,
}
```

### 5.4 Device Capability Model

Every device in the system is represented as a kernel object with its own capability:

```rust
pub enum ObjectType {
    Task,
    Region,
    Queue,
    Timer,
    VectorStore,
    GraphStore,
    RvfMount,
    Sensor,
    /// A hardware device (UART, DMA controller, GPU, NIC, etc.)
    Device,
    /// An interrupt line (GIC SPI/PPI/SGI)
    Interrupt,
}
```

The root task (first task created at boot) receives capabilities to all devices discovered
during boot (from DTB parsing). It then distributes device capabilities to appropriate
partitions according to the RVF manifest's resource policy.

---

## 6. Boot Security

### 6.1 Secure Boot Chain

RVM implements a four-stage secure boot chain:

```
Stage 0: Hardware ROM / eFUSE
  |  Root of trust: device-unique key burned in silicon
  |  Measures and verifies Stage 1
  v
Stage 1: RVM Boot Stub (ruvix-aarch64/src/boot.S + boot.rs)
  |  Minimal assembly: set up stack, clear BSS, jump to Rust
  |  Rust entry: initialize MMU, verify Stage 2 signature
  |  Verifies using trusted keys embedded in Stage 1 image
  v
Stage 2: RVM Kernel (ruvix-nucleus)
  |  Full kernel initialization: cap table, proof engine, scheduler
  |  Verifies RVF package signature (ML-DSA-65 or Ed25519)
  |  SEC-001: Signature failure -> PANIC (no fallback)
  v
Stage 3: Boot RVF Package
  |  Contains all initial RVF components
  |  Loaded into immutable regions
  |  Queue wiring and capability distribution per manifest
  v
Stage 4: Application RVF Components
     Runtime-mounted RVF packages, each signature-verified
```

### 6.2 Signature Verification

The existing `verify_boot_signature_or_panic()` in `crates/ruvix/crates/cap/src/security.rs`
implements SEC-001: signature failure panics the system with no fallback path. The security
feature flag `disable-boot-verify` is blocked at compile time for release builds:

```rust
// CVE-001 FIX: Prevent disable-boot-verify in release builds
#[cfg(all(feature = "disable-boot-verify", not(debug_assertions)))]
compile_error!(
    "SECURITY ERROR [CVE-001]: The 'disable-boot-verify' feature cannot be used \
     in release builds."
);
```

**Supported algorithms**:

| Algorithm | Status | Use Case |
|-----------|--------|----------|
| Ed25519 | Implemented | Primary boot signature |
| ECDSA P-256 | Supported | Legacy compatibility |
| RSA-PSS 2048 | Supported | Legacy compatibility |
| ML-DSA-65 | Planned | Post-quantum RVF signatures |

### 6.3 Measured Boot with Witness Log

Every boot stage emits a witness record:

1. **Stage 1 measurement**: Hash of the kernel image, stored as `WitnessRecordKind::Boot`
2. **Stage 2 initialization**: Each subsystem (cap manager, proof engine, scheduler)
   records its initialized state
3. **Stage 3 RVF mount**: Each mounted RVF package is recorded as `WitnessRecordKind::Mount`
   with the package hash and attestation

The boot witness log forms the root of the system's audit trail. All subsequent witness
records chain from it.

### 6.4 Remote Attestation for Edge Deployment

For edge deployments where RVM nodes must prove their integrity to a remote verifier:

```rust
/// Remote attestation protocol.
pub trait RemoteAttestor {
    /// Generate an attestation report that a remote verifier can check.
    /// The report includes:
    ///   - Platform identity (device-unique key signed measurement)
    ///   - Boot chain hashes (all four stages)
    ///   - Current witness log root hash
    ///   - Loaded RVF component inventory
    ///   - Nonce from the challenger (prevents replay)
    fn generate_attestation_report(
        &self,
        challenge_nonce: &[u8; 32],
    ) -> Result<AttestationReport, KernelError>;

    /// Verify an attestation report from another node.
    /// Used in mesh deployments where nodes must mutually attest.
    fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        expected_measurements: &MeasurementPolicy,
    ) -> Result<AttestationVerdict, KernelError>;
}

pub struct AttestationReport {
    /// Platform identifier (public key of device).
    pub platform_id: [u8; 32],
    /// Boot chain measurement (hash of all four stages).
    pub boot_measurement: [u8; 32],
    /// Current witness log chain hash (latest chain_hash).
    pub witness_root: [u8; 32],
    /// List of loaded RVF component hashes.
    pub component_inventory: Vec<[u8; 32]>,
    /// Challenge nonce from the verifier.
    pub nonce: [u8; 32],
    /// Signature over all of the above using the platform key.
    pub signature: [u8; 64],
}
```

### 6.5 Code Signing for Partition Images

All RVF packages must be signed before they can be mounted. The signature is verified by the
kernel's boot loader (`crates/ruvix/crates/boot/src/signature.rs`):

- The RVF manifest specifies the signing key ID and algorithm
- The kernel maintains a `TrustedKeyStore` (up to 8 keys, expirable)
- Keys can be rotated by mounting a key-update RVF signed by an existing trusted key
- The signing key hierarchy supports a two-level PKI:
  - **Root key**: Burned in eFUSE or compiled into Stage 1 (immutable)
  - **Signing keys**: Derived from root key, time-bounded, rotatable

---

## 7. Agent-Specific Security

### 7.1 WASM Sandbox Security Within Partitions

RVF components execute as WASM modules within partitions. The WASM sandbox provides a second
layer of isolation inside the capability boundary:

```
                Partition A (capability-isolated)
   +--------------------------------------------------+
   |  +-----------+  +-----------+  +-----------+     |
   |  | WASM      |  | WASM      |  | WASM      |     |
   |  | Module 1  |  | Module 2  |  | Module 3  |     |
   |  | (Agent)   |  | (Agent)   |  | (Service) |     |
   |  +-----------+  +-----------+  +-----------+     |
   |        |              |              |            |
   |        +--- WASM Host Interface (WASI-like) ----+|
   |                       |                           |
   |  +--------------------------------------------+  |
   |  | RVM Syscall Shim                         |  |
   |  | Maps WASM imports -> cap-gated syscalls     |  |
   |  +--------------------------------------------+  |
   +--------------------------------------------------+
   |  Kernel capability boundary (MMU-enforced)        |
   +--------------------------------------------------+
```

**WASM security properties**:

1. **Linear memory isolation**: Each WASM module has its own linear memory; it cannot access
   memory of other modules or the host
2. **Import-only system access**: WASM modules can only call functions explicitly imported
   from the host. The host provides a minimal syscall shim that maps WASM calls to
   capability-gated RVM syscalls
3. **Resource limits**: Each WASM module has configured limits on memory size, stack depth,
   execution fuel (instruction count), and table size
4. **No raw pointer access**: WASM's type system prevents arbitrary memory access. Pointers
   are offsets into the linear memory, bounds-checked by the runtime

```rust
/// WASM module resource limits.
pub struct WasmResourceLimits {
    /// Maximum linear memory size in pages (64 KiB per page).
    pub max_memory_pages: u32,
    /// Maximum call stack depth.
    pub max_stack_depth: u32,
    /// Maximum execution fuel (instructions). 0 = unlimited.
    pub max_fuel: u64,
    /// Maximum number of table entries.
    pub max_table_elements: u32,
    /// Maximum number of globals.
    pub max_globals: u32,
}

/// The host interface exposed to WASM modules.
/// Every function here validates capabilities before performing the operation.
pub trait WasmHostInterface {
    fn vector_get(&self, store: u32, key: u64) -> Result<WasmVectorRef, WasmTrap>;
    fn vector_put(&self, store: u32, key: u64, data: &[f32], proof: WasmProofRef)
        -> Result<(), WasmTrap>;
    fn queue_send(&self, queue: u32, msg: &[u8], priority: u8) -> Result<(), WasmTrap>;
    fn queue_recv(&self, queue: u32, buf: &mut [u8], timeout_ms: u64)
        -> Result<usize, WasmTrap>;
    fn log(&self, level: u8, message: &str);
}
```

### 7.2 Inter-Agent Communication Security

Agents communicate exclusively through typed queues. Security properties of queue-based IPC:

1. **Capability-gated**: Both sender and receiver must hold capabilities on the queue
2. **Typed messages**: Queue schema (WIT types) is validated at send time. Malformed
   messages are rejected before reaching the receiver
3. **Zero-copy safety**: Zero-copy messages use descriptors pointing into immutable or
   append-only regions. The kernel rejects descriptors pointing into slab regions
   (TOCTOU mitigation -- SEC-004)
4. **No covert channels**: Queue capacity is bounded and visible. The kernel does not
   leak information about queue occupancy to tasks that do not hold the queue's capability
5. **Message ordering**: Messages within a priority level are delivered in FIFO order.
   Cross-priority ordering is by priority (higher first). This is deterministic and
   does not leak information.

### 7.3 Agent Identity and Authentication

Agents do not have traditional identities (no UIDs, no usernames). Instead, agent identity
is established through the capability chain:

1. **Boot-time identity**: An agent's initial capabilities are assigned by the RVF manifest.
   The manifest is signed, so the identity is rooted in the code signer.
2. **Runtime identity**: An agent can prove its identity by demonstrating possession of
   specific capabilities. A "who are you?" query is answered by "I hold capability X with
   badge Y", and the verifier checks that badge against its expected value.
3. **Attestation identity**: An agent can emit an `attest_emit` record that binds its
   capability badge to a witness entry. External verifiers can trace this back through the
   witness chain to the boot attestation.

```rust
/// Agent identity is derived from capability badges, not global names.
pub struct AgentIdentity {
    /// The agent's task handle (ephemeral, changes across reboots).
    pub task: TaskHandle,
    /// Badge on the agent's primary capability (stable across reboots if
    /// assigned by the RVF manifest).
    pub primary_badge: u64,
    /// RVF component ID that spawned this agent.
    pub component_id: RvfComponentId,
    /// Hash of the WASM module binary (code identity).
    pub code_hash: [u8; 32],
}
```

### 7.4 Resource Limits and DoS Prevention

Each partition and each WASM module within a partition has enforceable resource limits:

```rust
/// Per-partition resource quota.
pub struct PartitionQuota {
    /// Maximum physical memory (bytes).
    pub max_memory_bytes: usize,
    /// Maximum number of tasks.
    pub max_tasks: u32,
    /// Maximum number of capabilities.
    pub max_capabilities: u32,
    /// Maximum number of queue endpoints.
    pub max_queues: u32,
    /// Maximum number of region mappings.
    pub max_regions: u32,
    /// CPU time budget per scheduling epoch (microseconds). 0 = unlimited.
    pub cpu_budget_us: u64,
    /// Maximum interrupt rate across all devices (per second).
    pub max_interrupt_rate_hz: u32,
    /// Maximum witness log entries per epoch (prevents log flooding).
    pub max_witness_entries_per_epoch: u32,
}

/// Enforcement mechanism.
pub trait QuotaEnforcer {
    /// Check if an allocation would exceed the partition's quota.
    fn check_allocation(
        &self,
        partition: PartitionHandle,
        resource: ResourceKind,
        amount: usize,
    ) -> Result<(), KernelError>;

    /// Record a resource allocation against the quota.
    fn record_allocation(
        &mut self,
        partition: PartitionHandle,
        resource: ResourceKind,
        amount: usize,
    ) -> Result<(), KernelError>;

    /// Release a resource allocation.
    fn release_allocation(
        &mut self,
        partition: PartitionHandle,
        resource: ResourceKind,
        amount: usize,
    );
}

pub enum ResourceKind {
    Memory,
    Tasks,
    Capabilities,
    Queues,
    Regions,
    CpuTime,
    WitnessEntries,
}
```

**DoS prevention mechanisms**:

| Attack Vector | Defense |
|--------------|---------|
| Memory exhaustion | Per-partition memory quota, `region_map` returns `OutOfMemory` |
| CPU starvation | Per-partition CPU budget, preemptive scheduler with budget enforcement |
| Queue flooding | Bounded queue capacity, backpressure on `queue_send` |
| Interrupt storm | Per-device rate limiting, priority ceiling |
| Capability table exhaustion | Per-partition cap table limit (1024 max) |
| Witness log flooding | Per-partition witness entry budget per epoch |
| Fork bomb | `task_spawn` checks per-partition task count against quota |
| Proof spam | Proof cache limited to 64 entries, nonce tracker bounded |

---

## 8. Threat Model

### 8.1 What RVM Defends Against

#### Attacks from Partitions Against Other Partitions

| Attack | Defense |
|--------|---------|
| Read another partition's memory | MMU page tables (TTBR0 per-partition) |
| Write another partition's memory | MMU + capability-gated region mapping |
| Forge a capability | Capabilities are kernel-resident, handles are opaque + epoch-checked |
| Escalate capability rights | `derive()` enforces monotonic attenuation |
| Replay a proof token | Single-use nonces in ProofVerifier |
| Use an expired proof | Time-bounded validity check |
| Tamper with witness log | Append-only region + hash chaining + optional TEE signing |
| Spoof another agent's identity | Identity is derived from capability badge, not forgeable name |
| Starve other partitions of CPU | Per-partition CPU budget + preemptive scheduling |
| Exhaust system memory | Per-partition memory quota |
| Flood queues | Bounded capacity + backpressure |
| DMA attack | IOMMU page tables or bounce buffers |
| Interrupt storm DoS | Rate limiting + priority ceiling |

#### Attacks from Partitions Against the Kernel

| Attack | Defense |
|--------|---------|
| Corrupt kernel memory | EL1/EL0 separation, PAN enabled |
| Modify page tables | Page table pages not mapped in EL0 |
| Disable interrupts | DAIF masking only in EL1 |
| Exploit kernel vulnerability | Rust's memory safety, `#![forbid(unsafe_code)]` on most crates |
| Spectre/Meltdown | CSDB barriers, BTI, PAN, branch predictor flush |
| Supply crafted syscall args | All syscall args validated, bounds-checked |
| Time a kernel operation to leak info | Constant-time critical paths, timer virtualization |

#### Boot-Time Attacks

| Attack | Defense |
|--------|---------|
| Boot unsigned kernel | SEC-001: panic on signature failure |
| Tamper with kernel image | Boot measurement chain, hash verification |
| Downgrade attack | Algorithm allowlist in TrustedKeyStore |
| Replay old signed image | Boot nonce from hardware RNG, version checking |
| Compromise signing key | Key rotation via signed key-update RVF |

#### Network/Remote Attacks (Multi-Node Mesh)

| Attack | Defense |
|--------|---------|
| Impersonate a node | Mutual attestation with device-unique keys |
| Migrate malicious partition | Deep-tier proof with source/destination attestation |
| Replay migration | Nonce in migration proof |
| Man-in-the-middle on migration | Encrypted channel + attestation binding |

### 8.2 What Is Out of Scope for v1

The following are explicitly NOT defended against in v1. They are acknowledged risks that
will be addressed in future iterations:

1. **Physical access attacks**: An attacker with physical access to the hardware (JTAG,
   bus probing, cold boot attacks) is out of scope. Hardware security modules (HSMs) and
   tamper-resistant packaging are future work.

2. **Rowhammer / DRAM disturbance**: RVM does not implement guard rows or ECC
   requirements in v1. Edge hardware with ECC RAM is recommended but not enforced.

3. **Supply chain attacks on the compiler**: RVM trusts the Rust compiler. Reproducible
   builds are recommended but not verified in v1.

4. **Formal verification of the kernel**: Unlike seL4, RVM is not formally verified in v1.
   The kernel is written in safe Rust (with minimal `unsafe` in the HAL layer), but there
   is no machine-checked proof of correctness.

5. **Covert channels via power consumption**: Power analysis side channels are out of scope.
   RVM does not implement constant-power execution.

6. **GPU/accelerator isolation**: v1 targets CPU-only execution. GPU and accelerator DMA
   isolation is future work.

7. **Encrypted memory (SEV-SNP/TDX)**: v1 does not implement memory encryption. The
   hypervisor trusts the physical memory bus.

8. **Multi-tenant adversarial scheduling**: The scheduler provides time isolation through
   budgets and jitter, but does not defend against a sophisticated adversary performing
   cache-timing analysis across many scheduling quanta.

### 8.3 Trust Boundaries

```
+================================================================+
|                    UNTRUSTED                                    |
|  +----------------------------------------------------------+  |
|  |  RVF Components (WASM agents, services, drivers)          |  |
|  |  - May be malicious                                       |  |
|  |  - May exploit any vulnerability                          |  |
|  |  - Constrained by: capabilities, quotas, WASM sandbox     |  |
|  +----------------------------------------------------------+  |
|                          | syscall                              |
|                          v                                      |
|  +----------------------------------------------------------+  |
|  |  TRUSTED: RVM Kernel (ruvix-nucleus)                    |  |
|  |  - Capability manager, proof verifier, scheduler          |  |
|  |  - Witness log, region manager, queue IPC                 |  |
|  |  - Bug here = system compromise                           |  |
|  |  - Minimized: 12 syscalls, ~15K lines Rust                |  |
|  +----------------------------------------------------------+  |
|                          | hardware interface                   |
|                          v                                      |
|  +----------------------------------------------------------+  |
|  |  TRUSTED: Hardware                                        |  |
|  |  - MMU, GIC, IOMMU, timers                               |  |
|  |  - Assumed correct (no hardware bugs modeled in v1)       |  |
|  +----------------------------------------------------------+  |
|                          | optional                              |
|                          v                                      |
|  +----------------------------------------------------------+  |
|  |  TRUSTED: TrustZone Secure World (when available)         |  |
|  |  - Device-unique key storage                              |  |
|  |  - Witness signing                                        |  |
|  |  - Boot measurement anchoring                             |  |
|  +----------------------------------------------------------+  |
+================================================================+
```

**Key trust assumptions**:

- The kernel is correct (not formally verified, but written in safe Rust)
- The hardware functions as documented (MMU enforces page permissions, IOMMU restricts DMA)
- The boot signing key has not been compromised
- The Rust compiler generates correct code
- The WASM runtime (Wasmtime or WAMR) correctly enforces sandboxing

### 8.4 Comparison to KVM and seL4 Threat Models

| Property | KVM | seL4 | RVM |
|----------|-----|------|-------|
| TCB size | ~2M lines (Linux kernel) | ~8.7K lines (C) | ~15K lines (Rust) |
| Formal verification | No | Yes (full functional correctness) | No (safe Rust, not verified) |
| Memory safety | C (manual) | C (verified) | Rust (compiler-enforced) |
| Capability model | No (uses DAC/MAC) | Yes (unforgeable tokens) | Yes (seL4-inspired) |
| Proof-gated mutation | No | No | Yes (unique to RVM) |
| Witness audit log | No (relies on external logging) | No | Yes (kernel-native) |
| DMA isolation | VT-d/SMMU | IOMMU-dependent | IOMMU + bounce buffer fallback |
| Side-channel defense | KPTI, IBRS, MDS mitigations | Limited (depends on platform) | CSDB, BTI, PAN, const-time paths |
| Agent-native primitives | No | No | Yes (vectors, graphs, coherence) |
| Hot-code loading | Module loading (large TCB) | No | RVF mount (capability-gated) |

**Key differentiators**:

1. **RVM vs. KVM**: RVM has a 100x smaller TCB. KVM inherits the entire Linux kernel as
   its TCB, including filesystems, networking, drivers, and hundreds of syscalls. RVM has
   12 syscalls and no ambient authority. KVM relies on Linux's DAC/MAC; RVM uses
   capabilities with proof-gated mutation.

2. **RVM vs. seL4**: seL4 has formal verification, which RVM does not. However, RVM
   has proof-gated mutation (no mutation without cryptographic authorization), kernel-native
   witness logging, and agent-specific primitives (vector stores, graph stores, coherence
   scoring). seL4 would require these as userspace servers communicating through IPC,
   reintroducing overhead and expanding the trusted codebase.

---

## 9. Security Invariants Summary

The following invariants MUST hold at all times. Violation of any invariant indicates a
security breach.

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SEC-001 | Boot signature failure -> PANIC | `verify_boot_signature_or_panic()`, compile-time block on `disable-boot-verify` in release |
| SEC-002 | Proof cache: 64 entries max, 100ms TTL, single-use nonces | `ProofCache` + `NonceTracker` |
| SEC-003 | Capability delegation depth <= 8 | `DerivationTree` depth check |
| SEC-004 | Zero-copy IPC descriptors cannot point into Slab regions | Queue descriptor validation |
| SEC-005 | No writable physical page shared between partitions | `PartitionAddressSpace::map_region()` exclusivity check |
| SEC-006 | Capability rights can only decrease through delegation | `Capability::derive()` subset check |
| SEC-007 | Every mutating syscall emits a witness record | Witness log append in syscall path |
| SEC-008 | Device MMIO access requires active lease + capability | `DeviceLeaseManager` check |
| SEC-009 | DMA restricted to leaseholder's physical pages | IOMMU or bounce buffer |
| SEC-010 | Per-partition resource quotas enforced | `QuotaEnforcer` checks before allocation |
| SEC-011 | Witness log is append-only with hash chaining | `ChainedWitnessRecord`, region policy enforcement |
| SEC-012 | No EL0 code can access kernel memory | TTBR1 mappings are PTE_KERNEL_RW, PAN enabled |

---

## 10. Implementation Roadmap

### Phase A (Complete): Linux-Hosted Prototype

Already implemented and tested (760 tests passing):
- Capability manager with derivation trees
- 3-tier proof engine with nonce tracking
- Witness log with serialization
- 12-syscall nucleus with checkpoint/replay

### Phase B (In Progress): Bare-Metal AArch64

Security-specific deliverables:
- MMU-enforced partition isolation (TTBR0 per-partition)
- EL1/EL0 separation for kernel/user code
- PAN + BTI + CSDB speculation barriers
- Hardware timer virtualization
- Device capability model with lease management

### Phase C (Planned): SMP + DMA

Security-specific deliverables:
- IOMMU programming for DMA isolation
- Bounce buffer fallback for platforms without IOMMU
- Per-CPU TLB management for partition switches
- IPI-based remote TLB invalidation
- SpinLock with timing-attack-resistant implementation

### Phase D (Planned): Mesh + Attestation

Security-specific deliverables:
- Remote attestation protocol
- Mutual node authentication
- Proof-gated migration
- Encrypted partition state transfer
- Distributed witness log with cross-node hash chaining

---

## References

- ADR-087: RVM Cognition Kernel (accepted, Phase A implemented)
- ADR-042: Security RVF -- AIDefence + TEE Hardened Cognitive Container
- ADR-047: Proof-gated mutation protocol
- ADR-029: RVF canonical binary format
- ADR-030: RVF cognitive container / self-booting vector files
- seL4 Reference Manual (capability model inspiration)
- ARM Architecture Reference Manual (AArch64 exception levels, MMU, PAN, BTI)
- NIST SP 800-147B: BIOS Protection Guidelines for Servers (measured boot)
- Dennis & Van Horn, "Programming Semantics for Multiprogrammed Computations" (1966)
  -- original capability concept
