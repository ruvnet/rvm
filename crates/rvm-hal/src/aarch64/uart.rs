//! PL011 UART driver for QEMU virt (AArch64).
//!
//! The QEMU virt machine provides a PL011 UART at base address 0x0900_0000.
//! This driver provides minimal early-boot serial output for diagnostics.
//!
//! All functions in this module use raw pointer writes to MMIO addresses.
//! This is the hardware boundary where unsafe is acceptable and expected.

/// QEMU virt PL011 base address.
const UART_BASE: usize = 0x0900_0000;

/// Data Register offset.
const UART_DR: usize = 0x000;

/// Flag Register offset.
const UART_FR: usize = 0x018;

/// Integer Baud Rate Register offset.
const UART_IBRD: usize = 0x024;

/// Fractional Baud Rate Register offset.
const UART_FBRD: usize = 0x028;

/// Line Control Register offset.
const UART_LCR_H: usize = 0x02C;

/// Control Register offset.
const UART_CR: usize = 0x030;

/// Interrupt Mask Set/Clear Register offset.
const UART_IMSC: usize = 0x038;

// Flag register bits
/// Transmit FIFO full.
const FR_TXFF: u32 = 1 << 5;

/// Receive FIFO empty.
#[allow(dead_code)]
const FR_RXFE: u32 = 1 << 4;

/// UART busy.
const FR_BUSY: u32 = 1 << 3;

// Control register bits
/// UART enable.
const CR_UARTEN: u32 = 1 << 0;

/// Transmit enable.
const CR_TXE: u32 = 1 << 8;

/// Receive enable.
const CR_RXE: u32 = 1 << 9;

// Line control bits
/// Enable FIFOs.
const LCR_FEN: u32 = 1 << 4;

/// 8-bit word length (WLEN = 0b11).
const LCR_WLEN_8: u32 = 3 << 5;

/// Maximum number of iterations to spin waiting for the TX FIFO.
///
/// If the UART hardware is wedged or the MMIO mapping is broken, an
/// unbounded loop would hang the hypervisor. This timeout is generous
/// enough for real hardware (PL011 drains at baud rate) while still
/// preventing an infinite hang.
const UART_TX_TIMEOUT: u32 = 1_000_000;

/// Write a 32-bit value to a UART register.
///
/// # Safety
///
/// `offset` must be a valid PL011 register offset. The UART base address
/// must be mapped as device memory (nGnRnE) before calling this function.
#[inline]
unsafe fn uart_write(offset: usize, val: u32) {
    let addr = (UART_BASE + offset) as *mut u32;
    // SAFETY: Caller guarantees UART is mapped. Volatile write ensures
    // the store reaches the device and is not elided by the compiler.
    unsafe {
        core::ptr::write_volatile(addr, val);
    }
}

/// Read a 32-bit value from a UART register.
///
/// # Safety
///
/// `offset` must be a valid PL011 register offset. The UART base address
/// must be mapped as device memory before calling this function.
#[inline]
unsafe fn uart_read(offset: usize) -> u32 {
    let addr = (UART_BASE + offset) as *const u32;
    // SAFETY: Caller guarantees UART is mapped. Volatile read ensures
    // the load actually reaches the device.
    unsafe { core::ptr::read_volatile(addr) }
}

/// Initialize the PL011 UART for 115200 baud, 8N1.
///
/// QEMU's PL011 emulation accepts output immediately, but this function
/// performs a proper initialization sequence for hardware correctness:
/// 1. Disable the UART
/// 2. Set baud rate (based on 24 MHz UARTCLK typical for virt)
/// 3. Configure line control (8 bits, FIFO enabled)
/// 4. Enable UART, TX, and RX
///
/// # Safety
///
/// Must be called at most once during boot. The UART MMIO region
/// (0x0900_0000) must be accessible (identity-mapped or pre-MMU).
pub unsafe fn uart_init() {
    // SAFETY: Boot-time UART initialization. MMIO region is accessible
    // in the initial identity-mapped (or flat) address space provided
    // by QEMU before stage-2 is enabled.
    unsafe {
        // Disable UART before configuration.
        uart_write(UART_CR, 0);

        // Wait for any pending transmission to complete (bounded).
        let mut timeout = UART_TX_TIMEOUT;
        while uart_read(UART_FR) & FR_BUSY != 0 {
            timeout -= 1;
            if timeout == 0 {
                break;
            }
        }

        // Mask all interrupts (we poll, not interrupt-driven at boot).
        uart_write(UART_IMSC, 0);

        // Set baud rate for 115200 with 24 MHz clock:
        // BRD = 24_000_000 / (16 * 115200) = 13.0208...
        // IBRD = 13, FBRD = round(0.0208 * 64) = 1
        uart_write(UART_IBRD, 13);
        uart_write(UART_FBRD, 1);

        // 8 bits, FIFO enabled, no parity, 1 stop bit.
        uart_write(UART_LCR_H, LCR_WLEN_8 | LCR_FEN);

        // Enable UART, TX, and RX.
        uart_write(UART_CR, CR_UARTEN | CR_TXE | CR_RXE);
    }
}

/// Write a single byte to the UART.
///
/// Spins until the transmit FIFO has space (up to [`UART_TX_TIMEOUT`]
/// iterations), then writes the byte. If the timeout is exceeded the
/// character is silently dropped to prevent hanging the hypervisor.
///
/// # Safety
///
/// The UART must have been initialized via [`uart_init`]. The MMIO
/// region must be accessible.
pub unsafe fn uart_putc(c: u8) {
    // SAFETY: UART is initialized and MMIO region is accessible.
    // We spin-wait on the flag register until TX FIFO is not full,
    // bounded by UART_TX_TIMEOUT to prevent infinite hangs if the
    // hardware is unresponsive.
    unsafe {
        let mut timeout = UART_TX_TIMEOUT;
        while uart_read(UART_FR) & FR_TXFF != 0 {
            timeout -= 1;
            if timeout == 0 {
                // Hardware is not draining -- drop the character
                // rather than hanging the hypervisor.
                return;
            }
        }
        uart_write(UART_DR, c as u32);
    }
}

/// Write a string to the UART, byte by byte.
///
/// Converts `\n` to `\r\n` for terminal compatibility.
///
/// # Safety
///
/// The UART must have been initialized via [`uart_init`].
pub unsafe fn uart_puts(s: &str) {
    for byte in s.bytes() {
        // SAFETY: UART is initialized, forwarding to uart_putc.
        unsafe {
            if byte == b'\n' {
                uart_putc(b'\r');
            }
            uart_putc(byte);
        }
    }
}

/// Write a 64-bit value as hexadecimal to the UART.
///
/// Outputs "0x" followed by 16 hex digits.
///
/// # Safety
///
/// The UART must have been initialized via [`uart_init`].
pub unsafe fn uart_put_hex(val: u64) {
    const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

    // SAFETY: UART is initialized, forwarding to uart_putc.
    unsafe {
        uart_putc(b'0');
        uart_putc(b'x');
        // Print 16 nibbles, MSB first.
        let mut i: i32 = 60;
        while i >= 0 {
            let nibble = ((val >> i) & 0xF) as usize;
            uart_putc(HEX_CHARS[nibble]);
            i -= 4;
        }
    }
}

/// Write a 32-bit value as hexadecimal to the UART.
///
/// Outputs "0x" followed by 8 hex digits.
///
/// # Safety
///
/// The UART must have been initialized via [`uart_init`].
pub unsafe fn uart_put_hex32(val: u32) {
    const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

    // SAFETY: UART is initialized, forwarding to uart_putc.
    unsafe {
        uart_putc(b'0');
        uart_putc(b'x');
        let mut i: i32 = 28;
        while i >= 0 {
            let nibble = ((val >> i) & 0xF) as usize;
            uart_putc(HEX_CHARS[nibble]);
            i -= 4;
        }
    }
}
