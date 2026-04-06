# ADR-150: Device Lease Lifecycle Protocol

**Status**: Accepted
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core), ADR-134 (Witness Schema), ADR-144 (GPU Compute Support)

---

## Context

RVM partitions access hardware devices through time-bounded, revocable leases
managed by `DeviceLeaseManager`. The deep review identified that while the
lease manager is implemented and tested, the full lifecycle protocol --
registration, grant, revocation, expiry, witness logging, GPU device handling,
and DMA budget integration -- is not formally specified.

### Problem Statement

1. **Registration semantics are incomplete**: `register_device()` assigns sequential IDs but does not validate MMIO region overlaps or IRQ conflicts.
2. **Capability gating is by hash only**: `ActiveLease::capability_hash` records the authorizing capability but the grant path does not validate the capability itself.
3. **Single-holder exclusivity is implemented but not specified**: `grant_lease()` checks `device.available` but the exclusivity invariant is not documented.
4. **Lease expiry is passive**: `expire_leases(current_epoch)` must be called explicitly; there is no automatic expiry mechanism.
5. **GPU devices have no special handling**: `DeviceClass::Graphics` exists but GPU-specific MMIO mapping, IOMMU isolation, and command queue management are not addressed.
6. **DMA budget integration is missing**: device DMA transfers should count against the partition's `DmaBudget` but there is no enforcement path.

---

## Decision

### 1. Device Registration Protocol

`DeviceLeaseManager::register_device(info)` registers a hardware device. It assigns a sequential `u32` id, sets `available = true`, and stores the `DeviceInfo` descriptor (id, `DeviceClass`, mmio_base, mmio_size, irq). Returns `Err(RvmError::ResourceLimitExceeded)` if the device table (fixed-size, `MAX_DEVICES` slots) is full. Devices are registered at boot time by the HAL (ADR-147).

### 2. Lease Grant: Capability-Gated, Epoch-Based, Exclusive

Lease grant follows `grant_lease(device_id, partition, duration_epochs, current_epoch, cap_hash)`:

**Preconditions**:
1. `device_id` must refer to a registered device (`DeviceLeaseNotFound` otherwise).
2. The device must be available (`DeviceLeaseConflict` if already leased).
3. The lease table must have capacity (`ResourceLimitExceeded` if full).

**Grant semantics**:
- A new `ActiveLease` is created with `granted_epoch = current_epoch` and
  `expiry_epoch = current_epoch + duration_epochs` (saturating add).
- The device is marked `available = false`.
- The lease is assigned a monotonically increasing `DeviceLeaseId`.
- `capability_hash` records the truncated FNV-1a hash of the capability token
  that authorized the grant, providing audit linkage.

**Single-holder exclusivity**: a device may be leased to at most one partition
at any time. This is enforced by the `available` flag on `DeviceInfo`. The
invariant: `device.available == false` if and only if there exists an
`ActiveLease` with `lease.device_id == device.id`.

### 3. Lease Revocation: Immediate, Cascading

`revoke_lease(lease_id)` immediately terminates a lease:

1. The `ActiveLease` is removed from the lease table.
2. The underlying device is marked `available = true`.
3. Returns `Err(RvmError::DeviceLeaseNotFound)` if the lease does not exist.

**Cascading revocation**: when a partition is destroyed (ADR-148 F3 recovery),
all leases held by that partition must be revoked. The caller iterates
`leases` and revokes each matching `partition_id`. This also revokes any
derived capabilities that reference the lease.

**Immediate effect**: the partition loses MMIO access at revocation time.
Any in-flight DMA transfers to/from the device continue to completion (hardware
cannot be interrupted mid-transfer), but no new transfers are permitted.

### 4. Lease Expiry: Automatic Collection

`expire_leases(current_epoch)` scans the lease table and collects all leases where `current_epoch >= expiry_epoch`, removes them, releases devices back to the available pool, and returns the count of expired leases. The scheduler calls this at each epoch boundary (passive -- no background timer).

`check_lease(lease_id, current_epoch)` validates a lease: returns `Ok(&ActiveLease)` if valid, `Err(DeviceLeaseExpired)` if expired, or `Err(DeviceLeaseNotFound)` if absent.

### 5. GPU Devices: DeviceClass::Graphics

GPU devices are registered with `DeviceClass::Graphics` and have additional
lifecycle requirements (ADR-144):

| Concern | Protocol |
|---------|----------|
| MMIO mapping | GPU register aperture (`mmio_base`, `mmio_size`) is mapped into the partition's stage-2 address space via `MmuOps::map_page()` at lease grant time. Unmapped at revocation. |
| IOMMU isolation | GPU page table base (`SwitchContext::gpu_pt_base`) is set to the partition's GPU-specific page table. Other partitions cannot access this partition's GPU memory. |
| Command queue | `SwitchContext::gpu_queue_head` tracks the partition's position in the GPU command queue. Saved/restored during context switch. |
| Budget | GPU operations count against both `DmaBudget` (DMA transfers) and `GpuBudget` (compute time, GPU memory). |

GPU lease duration should be conservative (shorter epochs) because GPU resources
are scarce and high-value. The recommended default for Graphics devices is 10
epochs, compared to 100+ for Network or Storage devices.

### 6. Witness Logging of Lease Transitions

All lease lifecycle events are witness-logged (ADR-134):

| Event | Trigger | Witness Fields |
|-------|---------|---------------|
| `DeviceRegistered` | `register_device()` returns `Ok(id)` | device_id, class, mmio_base, mmio_size, irq |
| `LeaseGranted` | `grant_lease()` returns `Ok(lease_id)` | lease_id, device_id, partition_id, granted_epoch, expiry_epoch, capability_hash |
| `LeaseRevoked` | `revoke_lease()` returns `Ok(())` | lease_id, device_id, partition_id, epoch_at_revocation |
| `LeaseExpired` | `expire_leases()` collects a lease | lease_id, device_id, partition_id, expiry_epoch |
| `LeaseCheckFailed` | `check_lease()` returns `Err` | lease_id, error_variant, current_epoch |

Witness records are batched per epoch (DC-10). Lease events are low-frequency
(compared to IPC messages) so the witness overhead is negligible.

### 7. DMA Budget Integration

Device DMA transfers count against the partition's `DmaBudget` (`rvm-security/src/budget.rs`). Before each transfer of `N` bytes, the hypervisor calls `DmaBudget::try_consume(N)`: if `used_bytes + N <= max_bytes` the transfer proceeds, otherwise `Err(RvmError::ResourceLimitExceeded)` is returned. The budget resets at each epoch boundary.

For GPU devices (`DeviceClass::Graphics`), both `DmaBudget` (raw DMA bytes) and `GpuBudget` (compute nanoseconds, GPU memory bytes) must pass. The `ResourceQuota` composite in `rvm-security` bundles `DmaBudget` with other per-partition quotas.

### 8. Zero-Heap Invariant

`DeviceLeaseManager<MAX_DEVICES, MAX_LEASES>` uses const generics for all storage. Both `devices` and `leases` arrays are `[Option<T>; N]` initialized with `None` sentinels. No heap allocation occurs at any lifecycle stage. Expiry uses a stack-allocated `expired_device_ids` buffer of size `MAX_LEASES`. This makes the lease manager suitable for `#![no_std]` bare-metal environments.

---

## Consequences

### Positive

- Single-holder exclusivity prevents device sharing conflicts between partitions.
- Epoch-based expiry provides automatic lease cleanup without background threads.
- Zero-heap implementation is compatible with all deployment tiers.
- Witness logging of all transitions provides complete audit trail.
- DMA budget enforcement prevents partition-level DMA bus monopolization.

### Negative

- No MMIO overlap validation at registration time; overlapping devices could cause conflicts.
- Passive expiry requires the scheduler to call `expire_leases()` at each epoch boundary.
- No lease renewal mechanism; a partition must re-acquire after expiry.
- `capability_hash` is stored but not verified against the capability subsystem at grant time.

### Risks

- If `expire_leases()` is not called regularly, expired leases accumulate and
  devices remain unavailable.
- GPU lease revocation during active GPU operations may leave the GPU in an
  inconsistent state; a GPU reset protocol is needed (ADR-144 future work).
- DMA budget enforcement adds overhead to every DMA transfer path.

---

## References

- `rvm-partition/src/device.rs` -- `DeviceLeaseManager`, `DeviceInfo`, `ActiveLease`
- `rvm-types/src/device.rs` -- `DeviceLeaseId`, `DeviceClass`, `DeviceLease`, `GpuMemoryType`, `GpuQueuePriority`
- `rvm-security/src/budget.rs` -- `DmaBudget`, `ResourceQuota`
- `rvm-sched/src/switch.rs` -- `SwitchContext::gpu_queue_head`, `SwitchContext::gpu_pt_base`
- ADR-132 -- Hypervisor core design constraints
- ADR-134 -- Witness schema and log format (DC-10 batching)
- ADR-144 -- GPU compute support (GpuBudget, IOMMU isolation)
- ADR-148 -- Error model and recovery (F3 cascading revocation)
