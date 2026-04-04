//! Device lease management per ADR-132.
//!
//! Leases are time-bounded, revocable, and capability-gated.
//! A device may only be leased to one partition at a time.
//! Expired leases are automatically reclaimable.

use rvm_types::{DeviceClass, DeviceLeaseId, PartitionId, RvmError, RvmResult};

/// Information about a registered hardware device.
#[derive(Debug, Clone, Copy)]
pub struct DeviceInfo {
    /// Unique device identifier (assigned on registration).
    pub id: u32,
    /// Device classification.
    pub class: DeviceClass,
    /// MMIO base physical address.
    pub mmio_base: u64,
    /// MMIO region size in bytes.
    pub mmio_size: u64,
    /// Interrupt line, if wired.
    pub irq: Option<u32>,
    /// Whether the device is currently available for leasing.
    pub available: bool,
}

/// A currently active device lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveLease {
    /// Unique lease identifier.
    pub lease_id: DeviceLeaseId,
    /// The device being leased.
    pub device_id: u32,
    /// The partition that holds the lease.
    pub partition_id: PartitionId,
    /// Epoch at which the lease was granted.
    pub granted_epoch: u64,
    /// Epoch at which the lease expires.
    pub expiry_epoch: u64,
    /// Hash of the capability token that authorised the grant.
    pub capability_hash: u32,
}

/// Manages device registration and lease lifecycle.
///
/// All storage is inline -- no heap allocation.
///
/// # Type Parameters
///
/// * `MAX_DEVICES` -- maximum number of registered devices.
/// * `MAX_LEASES` -- maximum number of concurrent active leases.
pub struct DeviceLeaseManager<const MAX_DEVICES: usize, const MAX_LEASES: usize> {
    devices: [Option<DeviceInfo>; MAX_DEVICES],
    leases: [Option<ActiveLease>; MAX_LEASES],
    device_count: usize,
    lease_count: usize,
    next_lease_id: u64,
}

impl<const MAX_DEVICES: usize, const MAX_LEASES: usize> Default
    for DeviceLeaseManager<MAX_DEVICES, MAX_LEASES>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_DEVICES: usize, const MAX_LEASES: usize>
    DeviceLeaseManager<MAX_DEVICES, MAX_LEASES>
{
    /// Sentinel for empty device slots.
    const NO_DEVICE: Option<DeviceInfo> = None;
    /// Sentinel for empty lease slots.
    const NO_LEASE: Option<ActiveLease> = None;

    /// Create a new, empty device lease manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: [Self::NO_DEVICE; MAX_DEVICES],
            leases: [Self::NO_LEASE; MAX_LEASES],
            device_count: 0,
            lease_count: 0,
            next_lease_id: 1,
        }
    }

    /// Register a hardware device and return its assigned device id.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the device table is full.
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_device(&mut self, mut info: DeviceInfo) -> RvmResult<u32> {
        if self.device_count >= MAX_DEVICES {
            return Err(RvmError::ResourceLimitExceeded);
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                // device_count < MAX_DEVICES <= u32::MAX in practice.
                let id = self.device_count as u32;
                info.id = id;
                info.available = true;
                *slot = Some(info);
                self.device_count += 1;
                return Ok(id);
            }
        }
        Err(RvmError::InternalError)
    }

    /// Grant a lease on a device to a partition.
    ///
    /// The lease is valid from `current_epoch` to `current_epoch + duration_epochs`.
    ///
    /// # Errors
    ///
    /// * [`RvmError::DeviceLeaseNotFound`] -- device id is invalid.
    /// * [`RvmError::DeviceLeaseConflict`] -- the device is already leased.
    /// * [`RvmError::ResourceLimitExceeded`] -- the lease table is full.
    pub fn grant_lease(
        &mut self,
        device_id: u32,
        partition: PartitionId,
        duration_epochs: u64,
        current_epoch: u64,
        cap_hash: u32,
    ) -> RvmResult<DeviceLeaseId> {
        // Find device index and validate availability.
        let dev_idx = self
            .find_device_index(device_id)
            .ok_or(RvmError::DeviceLeaseNotFound)?;

        // find_device_index guarantees the slot is Some.
        let device = self.devices[dev_idx]
            .as_ref()
            .ok_or(RvmError::InternalError)?;

        if !device.available {
            return Err(RvmError::DeviceLeaseConflict);
        }

        if self.lease_count >= MAX_LEASES {
            return Err(RvmError::ResourceLimitExceeded);
        }

        let lease_id = DeviceLeaseId::new(self.next_lease_id);
        self.next_lease_id += 1;

        let lease = ActiveLease {
            lease_id,
            device_id,
            partition_id: partition,
            granted_epoch: current_epoch,
            expiry_epoch: current_epoch.saturating_add(duration_epochs),
            capability_hash: cap_hash,
        };

        // Mark device as unavailable.
        if let Some(dev) = self.devices[dev_idx].as_mut() {
            dev.available = false;
        }

        // Insert lease.
        for slot in &mut self.leases {
            if slot.is_none() {
                *slot = Some(lease);
                self.lease_count += 1;
                return Ok(lease_id);
            }
        }

        // Shouldn't happen: we checked lease_count above.
        Err(RvmError::InternalError)
    }

    /// Revoke an active lease, releasing the device back to the pool.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::DeviceLeaseNotFound`] if the lease does not exist.
    pub fn revoke_lease(&mut self, lease_id: DeviceLeaseId) -> RvmResult<()> {
        let mut found_device_id = None;
        for slot in &mut self.leases {
            if let Some(lease) = slot {
                if lease.lease_id == lease_id {
                    found_device_id = Some(lease.device_id);
                    *slot = None;
                    self.lease_count -= 1;
                    break;
                }
            }
        }

        match found_device_id {
            Some(device_id) => {
                if let Some(idx) = self.find_device_index(device_id) {
                    if let Some(dev) = self.devices[idx].as_mut() {
                        dev.available = true;
                    }
                }
                Ok(())
            }
            None => Err(RvmError::DeviceLeaseNotFound),
        }
    }

    /// Check that a lease is still valid at the given epoch.
    ///
    /// # Errors
    ///
    /// * [`RvmError::DeviceLeaseNotFound`] -- the lease does not exist.
    /// * [`RvmError::DeviceLeaseExpired`] -- the lease has expired.
    pub fn check_lease(
        &self,
        lease_id: DeviceLeaseId,
        current_epoch: u64,
    ) -> RvmResult<&ActiveLease> {
        for lease in self.leases.iter().flatten() {
            if lease.lease_id == lease_id {
                if current_epoch >= lease.expiry_epoch {
                    return Err(RvmError::DeviceLeaseExpired);
                }
                return Ok(lease);
            }
        }
        Err(RvmError::DeviceLeaseNotFound)
    }

    /// Expire all leases whose `expiry_epoch` <= `current_epoch`.
    ///
    /// Releases the underlying devices back to the available pool.
    /// Returns the number of leases expired.
    pub fn expire_leases(&mut self, current_epoch: u64) -> u32 {
        let mut expired = 0u32;

        // Collect device ids for expired leases, then release them.
        // We use a fixed-size buffer to avoid allocation.
        let mut expired_device_ids = [0u32; MAX_LEASES];
        let mut expired_count = 0usize;

        for slot in &mut self.leases {
            let device_id = match slot.as_ref() {
                Some(l) if current_epoch >= l.expiry_epoch => l.device_id,
                _ => continue,
            };
            *slot = None;
            self.lease_count -= 1;
            expired += 1;
            if expired_count < MAX_LEASES {
                expired_device_ids[expired_count] = device_id;
                expired_count += 1;
            }
        }

        // Release devices.
        for &dev_id in &expired_device_ids[..expired_count] {
            if let Some(idx) = self.find_device_index(dev_id) {
                if let Some(dev) = self.devices[idx].as_mut() {
                    dev.available = true;
                }
            }
        }

        expired
    }

    /// Return the partition that currently holds a lease on the given device,
    /// or `None` if the device is unleased.
    #[must_use]
    pub fn get_lease_holder(&self, device_id: u32) -> Option<PartitionId> {
        self.leases
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|l| l.device_id == device_id)
            .map(|l| l.partition_id)
    }

    /// Whether a device is available for leasing.
    ///
    /// Returns `false` if the device id is invalid.
    #[must_use]
    pub fn is_device_available(&self, device_id: u32) -> bool {
        self.find_device(device_id)
            .is_some_and(|d| d.available)
    }

    /// Return the number of registered devices.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return the number of active leases.
    #[must_use]
    pub fn lease_count(&self) -> usize {
        self.lease_count
    }

    // --- private helpers ---

    fn find_device(&self, device_id: u32) -> Option<&DeviceInfo> {
        self.devices
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|d| d.id == device_id)
    }

    fn find_device_index(&self, device_id: u32) -> Option<usize> {
        self.devices
            .iter()
            .position(|s| s.as_ref().is_some_and(|d| d.id == device_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(class: DeviceClass, mmio_base: u64, mmio_size: u64) -> DeviceInfo {
        DeviceInfo {
            id: 0, // assigned on registration
            class,
            mmio_base,
            mmio_size,
            irq: Some(32),
            available: false, // set to true on registration
        }
    }

    fn pid(id: u32) -> PartitionId {
        PartitionId::new(id)
    }

    // --- Registration tests ---

    #[test]
    fn test_register_device() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let id = mgr
            .register_device(make_info(DeviceClass::Network, 0x4000_0000, 0x1000))
            .unwrap();
        assert_eq!(id, 0);
        assert!(mgr.is_device_available(id));
        assert_eq!(mgr.device_count(), 1);
    }

    #[test]
    fn test_register_device_full() {
        let mut mgr: DeviceLeaseManager<2, 2> = DeviceLeaseManager::new();
        mgr.register_device(make_info(DeviceClass::Network, 0x4000_0000, 0x1000))
            .unwrap();
        mgr.register_device(make_info(DeviceClass::Storage, 0x5000_0000, 0x2000))
            .unwrap();
        let result =
            mgr.register_device(make_info(DeviceClass::Serial, 0x6000_0000, 0x100));
        assert_eq!(result, Err(RvmError::ResourceLimitExceeded));
    }

    // --- Grant / Revoke cycle ---

    #[test]
    fn test_grant_and_revoke_cycle() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let dev_id = mgr
            .register_device(make_info(DeviceClass::Network, 0x4000_0000, 0x1000))
            .unwrap();

        // Grant lease.
        let lease_id = mgr.grant_lease(dev_id, pid(1), 100, 0, 0xDEAD).unwrap();
        assert!(!mgr.is_device_available(dev_id));
        assert_eq!(mgr.get_lease_holder(dev_id), Some(pid(1)));

        // Lease is valid.
        let lease = mgr.check_lease(lease_id, 50).unwrap();
        assert_eq!(lease.partition_id, pid(1));
        assert_eq!(lease.capability_hash, 0xDEAD);

        // Revoke.
        mgr.revoke_lease(lease_id).unwrap();
        assert!(mgr.is_device_available(dev_id));
        assert_eq!(mgr.get_lease_holder(dev_id), None);
    }

    // --- Lease expiry ---

    #[test]
    fn test_lease_expiry() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let dev_id = mgr
            .register_device(make_info(DeviceClass::Storage, 0x5000_0000, 0x2000))
            .unwrap();
        let lease_id = mgr.grant_lease(dev_id, pid(2), 10, 100, 0).unwrap();

        // Before expiry -- ok.
        assert!(mgr.check_lease(lease_id, 109).is_ok());

        // At expiry boundary.
        assert_eq!(
            mgr.check_lease(lease_id, 110),
            Err(RvmError::DeviceLeaseExpired)
        );

        // Expire leases.
        let count = mgr.expire_leases(110);
        assert_eq!(count, 1);
        assert!(mgr.is_device_available(dev_id));
        assert_eq!(mgr.lease_count(), 0);
    }

    #[test]
    fn test_expire_leases_none_expired() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let dev_id = mgr
            .register_device(make_info(DeviceClass::Timer, 0x1000, 0x100))
            .unwrap();
        mgr.grant_lease(dev_id, pid(1), 1000, 0, 0).unwrap();
        let count = mgr.expire_leases(500);
        assert_eq!(count, 0);
        assert_eq!(mgr.lease_count(), 1);
    }

    // --- Double-grant rejection ---

    #[test]
    fn test_double_grant_rejected() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let dev_id = mgr
            .register_device(make_info(DeviceClass::Graphics, 0x6000_0000, 0x10000))
            .unwrap();
        mgr.grant_lease(dev_id, pid(1), 100, 0, 0).unwrap();

        // Second grant to a different partition must fail.
        let result = mgr.grant_lease(dev_id, pid(2), 100, 0, 0);
        assert_eq!(result, Err(RvmError::DeviceLeaseConflict));
    }

    // --- Partition isolation ---

    #[test]
    fn test_partition_isolation() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let dev_a = mgr
            .register_device(make_info(DeviceClass::Network, 0x4000_0000, 0x1000))
            .unwrap();
        let dev_b = mgr
            .register_device(make_info(DeviceClass::Storage, 0x5000_0000, 0x2000))
            .unwrap();

        mgr.grant_lease(dev_a, pid(1), 100, 0, 0).unwrap();
        mgr.grant_lease(dev_b, pid(2), 100, 0, 0).unwrap();

        assert_eq!(mgr.get_lease_holder(dev_a), Some(pid(1)));
        assert_eq!(mgr.get_lease_holder(dev_b), Some(pid(2)));

        // Each partition only sees its own device.
        assert_ne!(
            mgr.get_lease_holder(dev_a),
            mgr.get_lease_holder(dev_b)
        );
    }

    // --- Error paths ---

    #[test]
    fn test_grant_nonexistent_device() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let result = mgr.grant_lease(99, pid(1), 100, 0, 0);
        assert_eq!(result, Err(RvmError::DeviceLeaseNotFound));
    }

    #[test]
    fn test_revoke_nonexistent_lease() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let result = mgr.revoke_lease(DeviceLeaseId::new(999));
        assert_eq!(result, Err(RvmError::DeviceLeaseNotFound));
    }

    #[test]
    fn test_check_nonexistent_lease() {
        let mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let result = mgr.check_lease(DeviceLeaseId::new(1), 0);
        assert_eq!(result, Err(RvmError::DeviceLeaseNotFound));
    }

    #[test]
    fn test_unavailable_device_reports_false() {
        let mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        // Non-existent device.
        assert!(!mgr.is_device_available(42));
    }

    #[test]
    fn test_lease_table_full() {
        let mut mgr: DeviceLeaseManager<4, 1> = DeviceLeaseManager::new();
        let dev_a = mgr
            .register_device(make_info(DeviceClass::Network, 0x1000, 0x100))
            .unwrap();
        let dev_b = mgr
            .register_device(make_info(DeviceClass::Serial, 0x2000, 0x100))
            .unwrap();

        mgr.grant_lease(dev_a, pid(1), 100, 0, 0).unwrap();

        // Lease table is full (MAX_LEASES = 1).
        let result = mgr.grant_lease(dev_b, pid(2), 100, 0, 0);
        assert_eq!(result, Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn test_re_lease_after_revoke() {
        let mut mgr: DeviceLeaseManager<8, 8> = DeviceLeaseManager::new();
        let dev_id = mgr
            .register_device(make_info(DeviceClass::Network, 0x4000_0000, 0x1000))
            .unwrap();

        let lease_id = mgr.grant_lease(dev_id, pid(1), 100, 0, 0).unwrap();
        mgr.revoke_lease(lease_id).unwrap();

        // Should be able to lease again.
        let new_lease = mgr.grant_lease(dev_id, pid(2), 50, 100, 0xBEEF);
        assert!(new_lease.is_ok());
        assert_eq!(mgr.get_lease_holder(dev_id), Some(pid(2)));
    }
}
