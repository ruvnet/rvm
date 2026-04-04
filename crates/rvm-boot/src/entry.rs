//! Rust entry point for the RVM boot sequence.
//!
//! `rvm_entry` is the first Rust function called after the assembly
//! boot stub has:
//! 1. Confirmed we are at EL2
//! 2. Set up the stack
//! 3. Cleared BSS
//!
//! This function implements the 7-phase deterministic boot sequence
//! from ADR-137, using the platform HAL for hardware initialization
//! and emitting witness records at each phase boundary.

use crate::hal_init::{HalInit, InterruptConfig, MmuConfig, UartConfig};
use crate::measured::MeasuredBootState;
use crate::sequence::{BootSequence, BootStage};
use rvm_types::PhysAddr;

/// Boot context holding all state needed during the boot sequence.
///
/// This struct is stack-allocated inside `rvm_entry` and threaded
/// through each boot phase. It collects timing data, witness hashes,
/// and configuration discovered during hardware detection.
pub struct BootContext {
    /// The 7-phase boot sequence manager.
    pub sequence: BootSequence,
    /// Measured boot hash chain for attestation.
    pub measured: MeasuredBootState,
    /// DTB pointer passed from firmware (x0 on AArch64).
    pub dtb_ptr: u64,
    /// Detected RAM size in bytes.
    pub ram_size: u64,
    /// Whether UART is available for debug output.
    pub uart_ready: bool,
}

impl BootContext {
    /// Create a new boot context with the given DTB pointer.
    #[must_use]
    pub const fn new(dtb_ptr: u64) -> Self {
        Self {
            sequence: BootSequence::new(),
            measured: MeasuredBootState::new(),
            dtb_ptr,
            ram_size: 0,
            uart_ready: false,
        }
    }
}

/// Execute the 7-phase deterministic boot sequence.
///
/// This function drives the boot through all phases using the provided
/// HAL implementation. Each phase:
/// 1. Begins via `sequence.begin_stage()`
/// 2. Performs its work
/// 3. Extends the measured boot chain
/// 4. Completes via `sequence.complete_stage()`
///
/// # Arguments
///
/// * `ctx` - The boot context (mutable, accumulates state)
/// * `hal` - The platform HAL implementation
/// * `tick_fn` - Function returning the current tick counter
///
/// After all 7 phases complete, `ctx.sequence.is_complete()` is true
/// and the system is ready for the scheduler to take over.
///
/// # Errors
///
/// Returns an error if any boot phase fails or phases execute out
/// of order.
pub fn run_boot_sequence<H, F>(
    ctx: &mut BootContext,
    hal: &mut H,
    mut tick_fn: F,
) -> rvm_types::RvmResult<()>
where
    H: HalInit,
    F: FnMut() -> u64,
{
    // --- Phase 0: Reset Vector ---
    // Assembly has already handled the actual reset vector. We record
    // the Rust entry as the completion of this phase.
    {
        let tick = tick_fn();
        ctx.sequence.begin_stage(BootStage::ResetVector, tick)?;
        let digest = phase_digest(BootStage::ResetVector, &[]);
        ctx.measured
            .extend_measurement(BootStage::ResetVector, &digest);
        ctx.sequence
            .complete_stage(BootStage::ResetVector, tick_fn(), digest)?;
    }

    // --- Phase 1: Hardware Detect ---
    // Parse DTB, enumerate CPUs, discover RAM size.
    {
        let tick = tick_fn();
        ctx.sequence
            .begin_stage(BootStage::HardwareDetect, tick)?;

        // For QEMU virt with 128 MB RAM (from Makefile -m 128M).
        // A real implementation would parse the DTB at ctx.dtb_ptr.
        ctx.ram_size = 128 * 1024 * 1024;

        // Initialize UART for early debug output.
        let uart_config = UartConfig::default_qemu();
        hal.init_uart(&uart_config)?;
        ctx.uart_ready = true;

        let digest = phase_digest(BootStage::HardwareDetect, &ctx.ram_size.to_le_bytes());
        ctx.measured
            .extend_measurement(BootStage::HardwareDetect, &digest);
        ctx.sequence
            .complete_stage(BootStage::HardwareDetect, tick_fn(), digest)?;
    }

    // --- Phase 2: MMU Setup ---
    // Configure stage-2 page tables and install in VTTBR_EL2.
    {
        let tick = tick_fn();
        ctx.sequence.begin_stage(BootStage::MmuSetup, tick)?;

        let mmu_config = MmuConfig {
            page_table_base: PhysAddr::new(0), // Placeholder; real base set by HAL.
            levels: 2,
            page_size: 4096,
        };
        hal.init_mmu(&mmu_config)?;

        let digest = phase_digest(BootStage::MmuSetup, &mmu_config.page_size.to_le_bytes());
        ctx.measured
            .extend_measurement(BootStage::MmuSetup, &digest);
        ctx.sequence
            .complete_stage(BootStage::MmuSetup, tick_fn(), digest)?;
    }

    // --- Phase 3: Hypervisor Mode ---
    // Configure HCR_EL2, exception vectors, interrupt controller.
    {
        let tick = tick_fn();
        ctx.sequence
            .begin_stage(BootStage::HypervisorMode, tick)?;

        let int_config = InterruptConfig { irq_count: 256 };
        hal.init_interrupts(&int_config)?;

        let digest = phase_digest(
            BootStage::HypervisorMode,
            &int_config.irq_count.to_le_bytes(),
        );
        ctx.measured
            .extend_measurement(BootStage::HypervisorMode, &digest);
        ctx.sequence
            .complete_stage(BootStage::HypervisorMode, tick_fn(), digest)?;
    }

    // --- Phase 4: Kernel Object Init ---
    // Initialize partition table, capability table, witness buffer.
    {
        let tick = tick_fn();
        ctx.sequence
            .begin_stage(BootStage::KernelObjectInit, tick)?;

        // Kernel object initialization is handled by rvm-kernel after
        // this boot sequence returns. We record the phase for the
        // measured boot chain.
        let digest = phase_digest(BootStage::KernelObjectInit, &[0xCA, 0xFE]);
        ctx.measured
            .extend_measurement(BootStage::KernelObjectInit, &digest);
        ctx.sequence
            .complete_stage(BootStage::KernelObjectInit, tick_fn(), digest)?;
    }

    // --- Phase 5: First Witness ---
    // Emit the genesis attestation record (BOOT_COMPLETE).
    {
        let tick = tick_fn();
        ctx.sequence
            .begin_stage(BootStage::FirstWitness, tick)?;

        let attestation = ctx.measured.get_attestation_digest();
        let digest = phase_digest(BootStage::FirstWitness, &attestation);
        ctx.measured
            .extend_measurement(BootStage::FirstWitness, &digest);
        ctx.sequence
            .complete_stage(BootStage::FirstWitness, tick_fn(), digest)?;
    }

    // --- Phase 6: Scheduler Entry ---
    // Hand off to the scheduler (never returns in production).
    {
        let tick = tick_fn();
        ctx.sequence
            .begin_stage(BootStage::SchedulerEntry, tick)?;

        let digest = phase_digest(BootStage::SchedulerEntry, &[]);
        ctx.measured
            .extend_measurement(BootStage::SchedulerEntry, &digest);
        ctx.sequence
            .complete_stage(BootStage::SchedulerEntry, tick_fn(), digest)?;
    }

    debug_assert!(ctx.sequence.is_complete());
    Ok(())
}

/// Compute a simple phase digest from the stage index and input data.
///
/// Uses FNV-1a to fill a 32-byte digest. This is a lightweight hash
/// suitable for `no_std` boot attestation (matching the pattern in
/// `measured.rs`).
fn phase_digest(stage: BootStage, data: &[u8]) -> [u8; 32] {
    use rvm_types::fnv1a_64;

    let mut input = [0u8; 64];
    input[0] = stage as u8;
    let copy_len = data.len().min(63);
    input[1..=copy_len].copy_from_slice(&data[..copy_len]);

    let h0 = fnv1a_64(&input);
    let h1 = fnv1a_64(&input[8..]);
    let h2 = fnv1a_64(&input[16..]);
    let h3 = fnv1a_64(&input[24..]);

    let mut digest = [0u8; 32];
    digest[..8].copy_from_slice(&h0.to_le_bytes());
    digest[8..16].copy_from_slice(&h1.to_le_bytes());
    digest[16..24].copy_from_slice(&h2.to_le_bytes());
    digest[24..32].copy_from_slice(&h3.to_le_bytes());
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal_init::StubHal;

    #[test]
    fn test_boot_context_new() {
        let ctx = BootContext::new(0x4000_0000);
        assert_eq!(ctx.dtb_ptr, 0x4000_0000);
        assert_eq!(ctx.ram_size, 0);
        assert!(!ctx.uart_ready);
        assert!(!ctx.sequence.is_complete());
    }

    #[test]
    fn test_full_boot_sequence_with_stub_hal() {
        let mut ctx = BootContext::new(0);
        let mut hal = StubHal::new();
        let mut tick = 0u64;

        let result = run_boot_sequence(&mut ctx, &mut hal, || {
            tick += 10;
            tick
        });

        assert!(result.is_ok());
        assert!(ctx.sequence.is_complete());
        assert!(ctx.uart_ready);
        assert_eq!(ctx.ram_size, 128 * 1024 * 1024);

        // All 7 phases produced non-zero witness digests.
        for stage in BootStage::all() {
            assert_ne!(*ctx.measured.phase_hash(stage), [0u8; 32]);
        }
    }

    #[test]
    fn test_measured_boot_non_zero() {
        let mut ctx = BootContext::new(0);
        let mut hal = StubHal::new();

        run_boot_sequence(&mut ctx, &mut hal, || 0).unwrap();

        assert!(!ctx.measured.is_virgin());
        assert_eq!(ctx.measured.measurement_count(), 7);
    }

    #[test]
    fn test_phase_digest_determinism() {
        let d1 = phase_digest(BootStage::ResetVector, &[1, 2, 3]);
        let d2 = phase_digest(BootStage::ResetVector, &[1, 2, 3]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_phase_digest_sensitivity() {
        let d1 = phase_digest(BootStage::ResetVector, &[1, 2, 3]);
        let d2 = phase_digest(BootStage::HardwareDetect, &[1, 2, 3]);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_boot_timing() {
        let mut ctx = BootContext::new(0);
        let mut hal = StubHal::new();
        let mut tick = 0u64;

        run_boot_sequence(&mut ctx, &mut hal, || {
            tick += 100;
            tick
        })
        .unwrap();

        // Each phase takes 2 ticks (begin + complete), 7 phases = 14 calls.
        // Total ticks: first start=100, last end=1400.
        assert!(ctx.sequence.total_ticks() > 0);
    }
}
