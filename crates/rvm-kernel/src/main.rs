//! RVM kernel binary entry point for AArch64 bare-metal boot.
//!
//! This is the `#![no_main]` binary that the linker script places at
//! `_start` (0x4000_0000 on QEMU virt). The assembly stub sets up the
//! stack, clears BSS, then jumps to [`rvm_main`] which initializes
//! hardware and enters the scheduler loop.
//!
//! When compiled for the host (e.g. `cargo test`), this binary provides
//! a trivial `main()` stub so that the test harness does not conflict
//! with `no_std` / `no_main`.
//!
//! Build (bare-metal):
//! ```bash
//! cargo build --target aarch64-unknown-none -p rvm-kernel --release
//! ```
//!
//! Run:
//! ```bash
//! qemu-system-aarch64 -M virt -cpu cortex-a72 -m 128M -nographic \
//!     -kernel target/aarch64-unknown-none/release/rvm
//! ```

// Bare-metal attributes -- only active when there is no OS.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(unsafe_code)]

// ===========================================================================
// Host-target stub (cargo test / cargo build on macOS/Linux)
// ===========================================================================

/// Trivial main for host builds so `cargo test --workspace` can compile
/// this binary without `no_main` / panic_handler conflicts.
#[cfg(test)]
fn main() {}

// ===========================================================================
// AArch64 bare-metal entry (the real kernel)
// ===========================================================================

// The `_start` symbol is the entry point from the linker script (`rvm.ld`).
//
// On AArch64 QEMU virt, execution begins at EL1 (or EL2 with `-machine
// virtualization=on`) with:
// - x0 = DTB pointer
// - PC at the ENTRY address (0x4000_0000)
//
// This stub:
// 1. Clears BSS
// 2. Sets up the stack pointer from `__stack_top`
// 3. Jumps to `rvm_main` (Rust entry)
// 4. If `rvm_main` ever returns, parks the CPU via WFE loop
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    // x0 holds DTB pointer from firmware -- preserve it
    // Clear BSS: load __bss_start and __bss_end from linker symbols
    "    adrp x1, __bss_start",
    "    add  x1, x1, :lo12:__bss_start",
    "    adrp x2, __bss_end",
    "    add  x2, x2, :lo12:__bss_end",
    "1:  cmp  x1, x2",
    "    b.ge 2f",
    "    str  xzr, [x1], #8",
    "    b    1b",
    "2:",
    // Set stack pointer
    "    adrp x1, __stack_top",
    "    add  x1, x1, :lo12:__stack_top",
    "    mov  sp, x1",
    // Jump to Rust entry (x0 = DTB pointer is first argument)
    "    bl   rvm_main",
    // If rvm_main returns, park CPU
    "3:  wfe",
    "    b    3b",
);

// ---------------------------------------------------------------------------
// Rust entry point
// ---------------------------------------------------------------------------

/// Main Rust entry point called from the assembly boot stub.
///
/// At this point BSS is zeroed and the stack is live. UART MMIO region
/// is identity-mapped by QEMU before any MMU setup, so we can write
/// to it immediately.
///
/// # Arguments
///
/// * `_dtb_ptr` - Physical address of the device tree blob (from x0).
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rvm_main(_dtb_ptr: u64) -> ! {
    // Phase 1: UART init -- first visible output
    #[cfg(target_arch = "aarch64")]
    unsafe {
        rvm_hal::aarch64::uart::uart_init();
        rvm_hal::aarch64::uart::uart_puts("[RVM] Booting...\n");
    }

    // Phase 2: Report exception level
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let el = rvm_hal::aarch64::boot::current_el();
        rvm_hal::aarch64::uart::uart_puts("[RVM] Exception level: EL");
        rvm_hal::aarch64::uart::uart_putc(b'0' + el);
        rvm_hal::aarch64::uart::uart_puts("\n");
    }

    // Phase 3: Run the kernel boot sequence (BootTracker-based)
    let mut kernel = rvm_kernel::Kernel::with_defaults();
    match kernel.boot() {
        Ok(()) => {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                rvm_hal::aarch64::uart::uart_puts("[RVM] Boot complete. First witness emitted.\n");
            }
        }
        Err(_e) => {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                rvm_hal::aarch64::uart::uart_puts("[RVM] ERROR: Boot sequence failed!\n");
            }
        }
    }

    // Phase 4: Report boot statistics
    #[cfg(target_arch = "aarch64")]
    unsafe {
        rvm_hal::aarch64::uart::uart_puts("[RVM] Witness records: ");
        rvm_hal::aarch64::uart::uart_put_hex32(kernel.witness_count() as u32);
        rvm_hal::aarch64::uart::uart_puts("\n");
        rvm_hal::aarch64::uart::uart_puts("[RVM] Entering scheduler loop...\n");
    }

    // Phase 5: Scheduler idle loop
    loop {
        // Tick the scheduler if booted
        if kernel.is_booted() {
            let _ = kernel.tick();
        }

        // WFE -- wait for event (low-power idle until next interrupt)
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }

        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Panic handler (bare-metal only)
// ---------------------------------------------------------------------------

/// Bare-metal panic handler -- prints to UART and halts.
///
/// Only compiled when not under the test harness (which provides its own).
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        rvm_hal::aarch64::uart::uart_puts("\n[RVM] !!! PANIC !!!\n");
        if let Some(loc) = info.location() {
            rvm_hal::aarch64::uart::uart_puts("[RVM]   at ");
            rvm_hal::aarch64::uart::uart_puts(loc.file());
            rvm_hal::aarch64::uart::uart_puts(":");
            // Print line number as decimal
            let line = loc.line();
            if line == 0 {
                rvm_hal::aarch64::uart::uart_putc(b'0');
            } else {
                // Convert line number to decimal string (max 10 digits for u32)
                let mut buf = [0u8; 10];
                let mut n = line;
                let mut i = 0usize;
                while n > 0 {
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                    i += 1;
                }
                // Print digits in reverse (MSB first)
                while i > 0 {
                    i -= 1;
                    rvm_hal::aarch64::uart::uart_putc(buf[i]);
                }
            }
            rvm_hal::aarch64::uart::uart_puts("\n");
        }
        rvm_hal::aarch64::uart::uart_puts("[RVM] System halted.\n");
    }

    loop {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}
