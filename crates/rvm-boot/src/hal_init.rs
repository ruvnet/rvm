//! HAL initialization stubs for early boot.
//!
//! These are trait-based stubs that define the hardware initialization
//! interface. Actual hardware-specific implementations reside in `rvm-hal`.
//! During boot, these stubs are called in sequence to bring up UART,
//! MMU, and the interrupt controller.

use rvm_types::{PhysAddr, RvmResult};

/// Early UART configuration for boot-time serial output.
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// Base address of the UART peripheral.
    pub base_addr: PhysAddr,
    /// Baud rate (e.g., 115200).
    pub baud_rate: u32,
}

impl UartConfig {
    /// Create a default UART configuration for a common QEMU virt board.
    #[must_use]
    pub const fn default_qemu() -> Self {
        Self {
            base_addr: PhysAddr::new(0x0900_0000),
            baud_rate: 115_200,
        }
    }
}

/// MMU configuration for stage-2 page table setup.
#[derive(Debug, Clone, Copy)]
pub struct MmuConfig {
    /// Physical address of the page table base.
    pub page_table_base: PhysAddr,
    /// Number of levels in the page table (typically 3 or 4).
    pub levels: u8,
    /// Page size in bytes (4096, 16384, or 65536).
    pub page_size: u32,
}

/// Interrupt controller configuration.
#[derive(Debug, Clone, Copy)]
pub struct InterruptConfig {
    /// Number of IRQ lines to configure.
    pub irq_count: u32,
}

/// Trait for early hardware initialization during boot.
///
/// Implementations of this trait provide the platform-specific code
/// to bring up the hardware during the boot sequence. The generic
/// stubs in this module define the interface; actual implementations
/// live in `rvm-hal`.
pub trait HalInit {
    /// Initialize the UART for early debug serial output.
    ///
    /// Called during the `ResetVector` or `HardwareDetect` phase to
    /// enable serial output as early as possible.
    fn init_uart(&mut self, config: &UartConfig) -> RvmResult<()>;

    /// Initialize the MMU with the given page table base.
    ///
    /// Called during the `MmuSetup` phase. Sets up stage-2 page tables
    /// for guest-to-host address translation.
    fn init_mmu(&mut self, config: &MmuConfig) -> RvmResult<()>;

    /// Initialize the interrupt controller (GIC / PLIC / APIC).
    ///
    /// Called during the `HypervisorMode` phase to configure exception
    /// vectors and enable interrupt routing.
    fn init_interrupts(&mut self, config: &InterruptConfig) -> RvmResult<()>;
}

/// A no-op HAL stub for testing and simulation.
///
/// All methods succeed immediately without touching hardware.
#[derive(Debug, Default)]
pub struct StubHal {
    /// Whether UART has been initialized.
    pub uart_initialized: bool,
    /// Whether MMU has been initialized.
    pub mmu_initialized: bool,
    /// Whether interrupts have been initialized.
    pub interrupts_initialized: bool,
}

impl StubHal {
    /// Create a new stub HAL with nothing initialized.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            uart_initialized: false,
            mmu_initialized: false,
            interrupts_initialized: false,
        }
    }
}

impl HalInit for StubHal {
    fn init_uart(&mut self, _config: &UartConfig) -> RvmResult<()> {
        self.uart_initialized = true;
        Ok(())
    }

    fn init_mmu(&mut self, _config: &MmuConfig) -> RvmResult<()> {
        self.mmu_initialized = true;
        Ok(())
    }

    fn init_interrupts(&mut self, _config: &InterruptConfig) -> RvmResult<()> {
        self.interrupts_initialized = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_hal_init_uart() {
        let mut hal = StubHal::new();
        assert!(!hal.uart_initialized);

        let config = UartConfig::default_qemu();
        hal.init_uart(&config).unwrap();
        assert!(hal.uart_initialized);
    }

    #[test]
    fn test_stub_hal_init_mmu() {
        let mut hal = StubHal::new();
        assert!(!hal.mmu_initialized);

        let config = MmuConfig {
            page_table_base: PhysAddr::new(0x4_0000),
            levels: 4,
            page_size: 4096,
        };
        hal.init_mmu(&config).unwrap();
        assert!(hal.mmu_initialized);
    }

    #[test]
    fn test_stub_hal_init_interrupts() {
        let mut hal = StubHal::new();
        assert!(!hal.interrupts_initialized);

        let config = InterruptConfig { irq_count: 256 };
        hal.init_interrupts(&config).unwrap();
        assert!(hal.interrupts_initialized);
    }

    #[test]
    fn test_full_hal_init_sequence() {
        let mut hal = StubHal::new();

        hal.init_uart(&UartConfig::default_qemu()).unwrap();
        hal.init_mmu(&MmuConfig {
            page_table_base: PhysAddr::new(0x4_0000),
            levels: 4,
            page_size: 4096,
        })
        .unwrap();
        hal.init_interrupts(&InterruptConfig { irq_count: 256 }).unwrap();

        assert!(hal.uart_initialized);
        assert!(hal.mmu_initialized);
        assert!(hal.interrupts_initialized);
    }
}
