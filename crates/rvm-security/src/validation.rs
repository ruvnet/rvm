//! Input validation for security-critical parameters.
//!
//! All validation functions return `RvmResult` so callers can
//! propagate errors uniformly. Validation is performed at system
//! boundaries before any state mutation.

use rvm_types::{CapRights, RvmError, RvmResult};

/// Maximum valid partition ID (DC-12: 4096 logical partitions).
const MAX_PARTITION_ID: u32 = 4096;

/// Page size for alignment checks (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Validate that a partition ID is within the allowed range.
///
/// Partition 0 is reserved for the hypervisor. Valid IDs are `1..=4096`.
///
/// # Errors
///
/// Returns [`RvmError::InvalidPartitionState`] if `id` is zero.
/// Returns [`RvmError::PartitionLimitExceeded`] if `id` exceeds 4096.
pub fn validate_partition_id(id: u32) -> RvmResult<()> {
    if id == 0 {
        return Err(RvmError::InvalidPartitionState);
    }
    if id > MAX_PARTITION_ID {
        return Err(RvmError::PartitionLimitExceeded);
    }
    Ok(())
}

/// Validate that a memory region described by `(addr, size)` does not
/// overflow and is properly aligned.
///
/// Both `addr` and `size` must be page-aligned (4 KiB boundary), and
/// `addr + size` must not overflow `u64`.
///
/// # Errors
///
/// Returns [`RvmError::AlignmentError`] if addresses are unaligned or size is zero.
/// Returns [`RvmError::MemoryOverlap`] if `addr + size` overflows.
pub fn validate_region_bounds(addr: u64, size: u64) -> RvmResult<()> {
    // Size must be non-zero
    if size == 0 {
        return Err(RvmError::AlignmentError);
    }

    // Page alignment check
    if addr % PAGE_SIZE != 0 {
        return Err(RvmError::AlignmentError);
    }
    if size % PAGE_SIZE != 0 {
        return Err(RvmError::AlignmentError);
    }

    // Overflow check
    if addr.checked_add(size).is_none() {
        return Err(RvmError::MemoryOverlap);
    }

    Ok(())
}

/// Validate that the requested capability rights are a subset of the
/// rights actually held.
///
/// A caller may only exercise rights they possess. This is the
/// foundational capability check before any operation proceeds.
///
/// # Errors
///
/// Returns [`RvmError::InsufficientCapability`] if `requested` is not a subset of `held`.
pub fn validate_capability_rights(requested: CapRights, held: CapRights) -> RvmResult<()> {
    if held.contains(requested) {
        Ok(())
    } else {
        Err(RvmError::InsufficientCapability)
    }
}

/// Validate that a device lease has not expired.
///
/// `lease_expiry_epoch` is the epoch at which the lease expires.
/// `current_epoch` is the current system epoch. The lease is valid
/// if `current_epoch < lease_expiry_epoch`.
///
/// # Errors
///
/// Returns [`RvmError::DeviceLeaseExpired`] if the lease has expired.
pub fn validate_lease_expiry(lease_expiry_epoch: u32, current_epoch: u32) -> RvmResult<()> {
    if current_epoch >= lease_expiry_epoch {
        Err(RvmError::DeviceLeaseExpired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Partition ID validation ---

    #[test]
    fn test_valid_partition_id() {
        assert!(validate_partition_id(1).is_ok());
        assert!(validate_partition_id(100).is_ok());
        assert!(validate_partition_id(4096).is_ok());
    }

    #[test]
    fn test_partition_id_zero_rejected() {
        assert_eq!(
            validate_partition_id(0),
            Err(RvmError::InvalidPartitionState)
        );
    }

    #[test]
    fn test_partition_id_too_large() {
        assert_eq!(
            validate_partition_id(4097),
            Err(RvmError::PartitionLimitExceeded)
        );
        assert_eq!(
            validate_partition_id(u32::MAX),
            Err(RvmError::PartitionLimitExceeded)
        );
    }

    // --- Region bounds validation ---

    #[test]
    fn test_valid_region_bounds() {
        assert!(validate_region_bounds(0x1000, 0x1000).is_ok());
        assert!(validate_region_bounds(0, 0x1000).is_ok());
        assert!(validate_region_bounds(0x1_0000, 0x10_0000).is_ok());
    }

    #[test]
    fn test_region_unaligned_addr() {
        assert_eq!(
            validate_region_bounds(0x1001, 0x1000),
            Err(RvmError::AlignmentError)
        );
    }

    #[test]
    fn test_region_unaligned_size() {
        assert_eq!(
            validate_region_bounds(0x1000, 0x1001),
            Err(RvmError::AlignmentError)
        );
    }

    #[test]
    fn test_region_zero_size() {
        assert_eq!(
            validate_region_bounds(0x1000, 0),
            Err(RvmError::AlignmentError)
        );
    }

    #[test]
    fn test_region_overflow() {
        // Unaligned address
        assert_eq!(
            validate_region_bounds(0x1001, 0x1000),
            Err(RvmError::AlignmentError)
        );
        // Aligned but overflows: 0xFFFF_FFFF_FFFF_F000 + 0x2000 > u64::MAX
        let high_addr = u64::MAX - 0x1000 + 1; // 0xFFFF_FFFF_FFFF_F000
        assert_eq!(
            validate_region_bounds(high_addr, 0x2000),
            Err(RvmError::MemoryOverlap)
        );
        // Just at the boundary: should succeed (addr+size == 0)
        // 0xFFFF_FFFF_FFFF_F000 + 0x1000 wraps to 0 -- that's overflow
        assert_eq!(
            validate_region_bounds(high_addr, 0x1000),
            Err(RvmError::MemoryOverlap)
        );
    }

    // --- Capability rights validation ---

    #[test]
    fn test_valid_capability_rights() {
        let held = CapRights::READ | CapRights::WRITE | CapRights::GRANT;
        assert!(validate_capability_rights(CapRights::READ, held).is_ok());
        assert!(validate_capability_rights(CapRights::READ | CapRights::WRITE, held).is_ok());
    }

    #[test]
    fn test_insufficient_capability_rights() {
        let held = CapRights::READ;
        assert_eq!(
            validate_capability_rights(CapRights::WRITE, held),
            Err(RvmError::InsufficientCapability)
        );
        assert_eq!(
            validate_capability_rights(CapRights::READ | CapRights::WRITE, held),
            Err(RvmError::InsufficientCapability)
        );
    }

    #[test]
    fn test_exact_rights_match() {
        let rights = CapRights::READ | CapRights::EXECUTE;
        assert!(validate_capability_rights(rights, rights).is_ok());
    }

    #[test]
    fn test_empty_requested_rights() {
        let held = CapRights::READ;
        assert!(validate_capability_rights(CapRights::empty(), held).is_ok());
    }

    // --- Lease expiry validation ---

    #[test]
    fn test_valid_lease() {
        assert!(validate_lease_expiry(100, 50).is_ok());
        assert!(validate_lease_expiry(100, 99).is_ok());
    }

    #[test]
    fn test_expired_lease() {
        assert_eq!(
            validate_lease_expiry(100, 100),
            Err(RvmError::DeviceLeaseExpired)
        );
        assert_eq!(
            validate_lease_expiry(100, 200),
            Err(RvmError::DeviceLeaseExpired)
        );
    }

    #[test]
    fn test_lease_edge_case() {
        // Expiry at epoch 1, current epoch 0 — still valid
        assert!(validate_lease_expiry(1, 0).is_ok());
    }
}
