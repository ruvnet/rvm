//! Boot sequence manager implementing the 7-phase deterministic boot
//! specified in ADR-137.
//!
//! Each phase transitions only forward and emits a witness record on
//! completion. The sequence is designed to complete within 250 ms.

use rvm_types::{RvmError, RvmResult};

/// The seven deterministic boot phases (ADR-137).
///
/// Phases must execute strictly in order. Each phase emits a witness
/// record upon completion before the next phase may begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BootStage {
    /// Phase 0: Processor reset vector — initial entry from firmware.
    ResetVector = 0,
    /// Phase 1: Hardware detection — enumerate CPUs, memory, devices.
    HardwareDetect = 1,
    /// Phase 2: MMU setup — configure stage-2 page tables.
    MmuSetup = 2,
    /// Phase 3: Enter hypervisor mode (EL2 on AArch64).
    HypervisorMode = 3,
    /// Phase 4: Initialize kernel objects (cap table, IPC, etc.).
    KernelObjectInit = 4,
    /// Phase 5: Emit first witness — genesis attestation record.
    FirstWitness = 5,
    /// Phase 6: Scheduler entry — hand off to the scheduler loop.
    SchedulerEntry = 6,
}

/// Total number of boot stages.
pub const BOOT_STAGE_COUNT: usize = 7;

/// Target maximum boot time in milliseconds (ADR-137).
pub const TARGET_BOOT_MS: u64 = 250;

impl BootStage {
    /// Return the next stage, or `None` if this is the final stage.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::ResetVector => Some(Self::HardwareDetect),
            Self::HardwareDetect => Some(Self::MmuSetup),
            Self::MmuSetup => Some(Self::HypervisorMode),
            Self::HypervisorMode => Some(Self::KernelObjectInit),
            Self::KernelObjectInit => Some(Self::FirstWitness),
            Self::FirstWitness => Some(Self::SchedulerEntry),
            Self::SchedulerEntry => None,
        }
    }

    /// Return the human-readable name of this stage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ResetVector => "reset vector",
            Self::HardwareDetect => "hardware detect",
            Self::MmuSetup => "MMU setup",
            Self::HypervisorMode => "hypervisor mode",
            Self::KernelObjectInit => "kernel object init",
            Self::FirstWitness => "first witness",
            Self::SchedulerEntry => "scheduler entry",
        }
    }

    /// Return all stages in order as a static array.
    #[must_use]
    pub const fn all() -> [Self; BOOT_STAGE_COUNT] {
        [
            Self::ResetVector,
            Self::HardwareDetect,
            Self::MmuSetup,
            Self::HypervisorMode,
            Self::KernelObjectInit,
            Self::FirstWitness,
            Self::SchedulerEntry,
        ]
    }
}

/// Per-phase timing record for boot profiling.
#[derive(Debug, Clone, Copy)]
pub struct PhaseTiming {
    /// Tick at which the phase began (platform-specific counter).
    pub start_tick: u64,
    /// Tick at which the phase completed, or 0 if not yet finished.
    pub end_tick: u64,
}

impl PhaseTiming {
    /// Create a zeroed timing record.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            start_tick: 0,
            end_tick: 0,
        }
    }

    /// Duration in ticks, or 0 if incomplete.
    #[must_use]
    pub const fn duration_ticks(&self) -> u64 {
        self.end_tick.saturating_sub(self.start_tick)
    }
}

/// Boot sequence manager tracking the 7-phase deterministic boot.
///
/// Phases must advance strictly forward. Skipping or re-entering a
/// phase is an error. Each completed phase records its timing for
/// profiling and emits a witness digest via the measured boot layer.
#[derive(Debug)]
pub struct BootSequence {
    /// The stage currently expected to run next.
    current: Option<BootStage>,
    /// Per-stage completion flags.
    completed: [bool; BOOT_STAGE_COUNT],
    /// Per-stage timing data.
    timings: [PhaseTiming; BOOT_STAGE_COUNT],
    /// Witness hashes emitted at the end of each stage (32 bytes each).
    witness_digests: [[u8; 32]; BOOT_STAGE_COUNT],
}

impl BootSequence {
    /// Create a new boot sequence starting at the reset vector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current: Some(BootStage::ResetVector),
            completed: [false; BOOT_STAGE_COUNT],
            timings: [PhaseTiming::zeroed(); BOOT_STAGE_COUNT],
            witness_digests: [[0u8; 32]; BOOT_STAGE_COUNT],
        }
    }

    /// Return the current stage, or `None` if boot is complete.
    #[must_use]
    pub const fn current_stage(&self) -> Option<BootStage> {
        self.current
    }

    /// Begin a stage, recording its start tick.
    ///
    /// Returns an error if the stage is not the expected next stage.
    pub fn begin_stage(&mut self, stage: BootStage, tick: u64) -> RvmResult<()> {
        match self.current {
            Some(expected) if expected as u8 == stage as u8 => {
                self.timings[stage as usize].start_tick = tick;
                Ok(())
            }
            Some(_) => Err(RvmError::InternalError),
            None => Err(RvmError::Unsupported),
        }
    }

    /// Complete the current stage with a witness digest and end tick.
    ///
    /// Advances to the next stage. Returns the completed stage on success.
    pub fn complete_stage(
        &mut self,
        stage: BootStage,
        tick: u64,
        witness_digest: [u8; 32],
    ) -> RvmResult<BootStage> {
        match self.current {
            Some(expected) if expected as u8 == stage as u8 => {
                self.timings[stage as usize].end_tick = tick;
                self.completed[stage as usize] = true;
                self.witness_digests[stage as usize] = witness_digest;
                self.current = stage.next();
                Ok(stage)
            }
            Some(_) => Err(RvmError::InternalError),
            None => Err(RvmError::Unsupported),
        }
    }

    /// Check whether all boot stages have completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.current.is_none() && self.completed.iter().all(|&c| c)
    }

    /// Check whether a specific stage has been completed.
    #[must_use]
    pub fn stage_completed(&self, stage: BootStage) -> bool {
        self.completed[stage as usize]
    }

    /// Return timing data for a specific stage.
    #[must_use]
    pub const fn timing(&self, stage: BootStage) -> &PhaseTiming {
        &self.timings[stage as usize]
    }

    /// Return the witness digest emitted at the end of a stage.
    #[must_use]
    pub const fn witness_digest(&self, stage: BootStage) -> &[u8; 32] {
        &self.witness_digests[stage as usize]
    }

    /// Compute total boot duration in ticks (first start to last end).
    #[must_use]
    pub fn total_ticks(&self) -> u64 {
        let first_start = self.timings[0].start_tick;
        let last_end = self.timings[BOOT_STAGE_COUNT - 1].end_tick;
        last_end.saturating_sub(first_start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stage_ordering() {
        assert!(BootStage::ResetVector < BootStage::HardwareDetect);
        assert!(BootStage::HardwareDetect < BootStage::MmuSetup);
        assert!(BootStage::MmuSetup < BootStage::HypervisorMode);
        assert!(BootStage::HypervisorMode < BootStage::KernelObjectInit);
        assert!(BootStage::KernelObjectInit < BootStage::FirstWitness);
        assert!(BootStage::FirstWitness < BootStage::SchedulerEntry);
    }

    #[test]
    fn test_boot_stage_next() {
        assert_eq!(BootStage::ResetVector.next(), Some(BootStage::HardwareDetect));
        assert_eq!(BootStage::SchedulerEntry.next(), None);
    }

    #[test]
    fn test_full_sequence() {
        let mut seq = BootSequence::new();
        assert!(!seq.is_complete());

        let stages = BootStage::all();
        for (i, &stage) in stages.iter().enumerate() {
            let start = (i as u64) * 100;
            let end = start + 50;
            let digest = [i as u8; 32];

            assert_eq!(seq.current_stage(), Some(stage));
            seq.begin_stage(stage, start).unwrap();
            seq.complete_stage(stage, end, digest).unwrap();
            assert!(seq.stage_completed(stage));
        }

        assert!(seq.is_complete());
        assert_eq!(seq.current_stage(), None);
    }

    #[test]
    fn test_out_of_order_fails() {
        let mut seq = BootSequence::new();
        let result = seq.begin_stage(BootStage::MmuSetup, 0);
        assert_eq!(result, Err(RvmError::InternalError));
    }

    #[test]
    fn test_complete_wrong_stage_fails() {
        let mut seq = BootSequence::new();
        seq.begin_stage(BootStage::ResetVector, 0).unwrap();
        let result = seq.complete_stage(BootStage::HardwareDetect, 10, [0; 32]);
        assert_eq!(result, Err(RvmError::InternalError));
    }

    #[test]
    fn test_complete_after_finished_fails() {
        let mut seq = BootSequence::new();
        let stages = BootStage::all();
        for (i, &stage) in stages.iter().enumerate() {
            seq.begin_stage(stage, i as u64 * 10).unwrap();
            seq.complete_stage(stage, i as u64 * 10 + 5, [0; 32]).unwrap();
        }
        assert!(seq.is_complete());
        let result = seq.begin_stage(BootStage::ResetVector, 0);
        assert_eq!(result, Err(RvmError::Unsupported));
    }

    #[test]
    fn test_timing() {
        let mut seq = BootSequence::new();
        seq.begin_stage(BootStage::ResetVector, 100).unwrap();
        seq.complete_stage(BootStage::ResetVector, 200, [0; 32]).unwrap();

        let t = seq.timing(BootStage::ResetVector);
        assert_eq!(t.start_tick, 100);
        assert_eq!(t.end_tick, 200);
        assert_eq!(t.duration_ticks(), 100);
    }

    #[test]
    fn test_total_ticks() {
        let mut seq = BootSequence::new();
        let stages = BootStage::all();
        for (i, &stage) in stages.iter().enumerate() {
            let start = (i as u64) * 100;
            let end = start + 50;
            seq.begin_stage(stage, start).unwrap();
            seq.complete_stage(stage, end, [0; 32]).unwrap();
        }
        // First start=0, last end=650
        assert_eq!(seq.total_ticks(), 650);
    }

    #[test]
    fn test_witness_digest_stored() {
        let mut seq = BootSequence::new();
        let digest = [0xAB_u8; 32];
        seq.begin_stage(BootStage::ResetVector, 0).unwrap();
        seq.complete_stage(BootStage::ResetVector, 10, digest).unwrap();
        assert_eq!(*seq.witness_digest(BootStage::ResetVector), digest);
    }
}
