//! Device lease types.

/// Unique identifier for a device lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeviceLeaseId(u64);

impl DeviceLeaseId {
    /// Create a new device lease identifier.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw identifier value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Classification of device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DeviceClass {
    /// Network interface controller.
    Network = 0,
    /// Block storage device.
    Storage = 1,
    /// GPU or display controller.
    Graphics = 2,
    /// Serial / UART console.
    Serial = 3,
    /// Timer / clock device.
    Timer = 4,
    /// Interrupt controller.
    InterruptController = 5,
    /// Generic MMIO device.
    Generic = 255,
}

/// A time-bounded, revocable device lease.
#[derive(Debug, Clone, Copy)]
pub struct DeviceLease {
    /// Unique lease identifier.
    pub id: DeviceLeaseId,
    /// Device class.
    pub class: DeviceClass,
    /// MMIO base address.
    pub mmio_base: u64,
    /// MMIO region size in bytes.
    pub mmio_size: u64,
    /// Lease expiry timestamp (nanoseconds, 0 = no expiry).
    pub expiry_ns: u64,
    /// Epoch when the lease was granted.
    pub epoch: u32,
}
