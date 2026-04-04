//! # RVM Kernel
//!
//! Top-level integration crate for the RVM (RuVix Virtual Machine)
//! coherence-native microhypervisor. This crate wires together all
//! subsystems (HAL, capabilities, witness, proof, partitions, scheduler,
//! memory, coherence, boot, Wasm, and security) into a single API
//! surface.
//!
//! ## Architecture
//!
//! ```text
//!          +---------------------------------------------+
//!          |                  rvm-kernel                  |
//!          |                                             |
//!          |  +----------+  +----------+  +-----------+  |
//!          |  | rvm-boot |  | rvm-sched|  |rvm-memory |  |
//!          |  +----+-----+  +----+-----+  +-----+-----+  |
//!          |       |             |              |         |
//!          |  +----+-------------+--------------+-----+  |
//!          |  |            rvm-partition               |  |
//!          |  +----+--------+----------+---------+----+  |
//!          |       |        |          |         |       |
//!          |  +----+--+ +---+----+ +---+---+ +---+----+  |
//!          |  |rvm-cap| |rvm-wit.| |rvm-prf| |rvm-sec.|  |
//!          |  +----+--+ +---+----+ +---+---+ +---+----+  |
//!          |       |        |          |         |       |
//!          |  +----+--------+----------+---------+----+  |
//!          |  |              rvm-types                |   |
//!          |  +----+----------------------------------+  |
//!          |       |                                     |
//!          |  +----+--+  +----------+                    |
//!          |  |rvm-hal|  |rvm-wasm  | (optional)         |
//!          |  +-------+  +----------+                    |
//!          +---------------------------------------------+
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Re-export all subsystem crates for unified access.
pub use rvm_boot as boot;
/// Capability-based access control.
pub use rvm_cap as cap;
/// Coherence monitoring and Phi computation.
pub use rvm_coherence as coherence;
/// Hardware abstraction layer traits.
pub use rvm_hal as hal;
/// Guest memory management.
pub use rvm_memory as memory;
/// Partition lifecycle management.
pub use rvm_partition as partition;
/// Proof-gated state transitions.
pub use rvm_proof as proof;
/// Coherence-weighted scheduler.
pub use rvm_sched as sched;
/// Security policy enforcement.
pub use rvm_security as security;
/// Core type definitions.
pub use rvm_types as types;
/// WebAssembly guest runtime.
pub use rvm_wasm as wasm;
/// Witness trail management.
pub use rvm_witness as witness;

/// RVM version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// RVM crate count (number of subsystem crates).
pub const CRATE_COUNT: usize = 13;

// ---------------------------------------------------------------------------
// Kernel integration struct
// ---------------------------------------------------------------------------

use rvm_boot::BootTracker;
use rvm_cap::{CapManagerConfig, CapabilityManager};
use rvm_partition::PartitionManager;
use rvm_sched::Scheduler;
use rvm_types::{
    ActionKind, PartitionConfig, PartitionId, RvmConfig, RvmError, RvmResult,
    WitnessRecord,
};
use rvm_witness::WitnessLog;

/// Default maximum CPUs supported by the kernel.
const DEFAULT_MAX_CPUS: usize = 8;

/// Default witness log capacity (number of records).
const DEFAULT_WITNESS_CAPACITY: usize = 256;

/// Default capability table capacity per partition.
const DEFAULT_CAP_CAPACITY: usize = 256;

/// Default partition table capacity.
const DEFAULT_MAX_PARTITIONS: usize = 256;

/// Top-level kernel integrating all RVM subsystems.
///
/// The kernel holds ownership of all core subsystem instances
/// and provides a unified API for partition lifecycle, scheduling,
/// and security enforcement.
pub struct Kernel {
    /// Partition lifecycle manager.
    partitions: PartitionManager,
    /// Coherence-weighted scheduler (8 CPUs, 256 partitions).
    scheduler: Scheduler<DEFAULT_MAX_CPUS, DEFAULT_MAX_PARTITIONS>,
    /// Append-only witness log.
    witness_log: WitnessLog<DEFAULT_WITNESS_CAPACITY>,
    /// Capability manager (P1/P2/P3 verification).
    cap_manager: CapabilityManager<DEFAULT_CAP_CAPACITY>,
    /// Boot progress tracker.
    boot: BootTracker,
    /// Kernel configuration.
    config: RvmConfig,
    /// Whether the kernel has completed booting.
    booted: bool,
}

/// Configuration for constructing a kernel instance.
#[derive(Debug, Clone, Copy)]
pub struct KernelConfig {
    /// Base RVM configuration.
    pub rvm: RvmConfig,
    /// Capability manager configuration.
    pub cap: CapManagerConfig,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            rvm: RvmConfig::default(),
            cap: CapManagerConfig::new(),
        }
    }
}

impl Kernel {
    /// Create a new kernel instance with the given configuration.
    #[must_use]
    pub fn new(config: KernelConfig) -> Self {
        Self {
            partitions: PartitionManager::new(),
            scheduler: Scheduler::new(),
            witness_log: WitnessLog::new(),
            cap_manager: CapabilityManager::new(config.cap),
            boot: BootTracker::new(),
            config: config.rvm,
            booted: false,
        }
    }

    /// Create a kernel with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(KernelConfig::default())
    }

    /// Run the boot sequence through all 7 phases.
    ///
    /// Each phase completion is recorded as a witness entry. After all
    /// phases complete, the kernel is ready to accept partition requests.
    pub fn boot(&mut self) -> RvmResult<()> {
        use rvm_boot::BootPhase;

        let phases = [
            BootPhase::HalInit,
            BootPhase::MemoryInit,
            BootPhase::CapabilityInit,
            BootPhase::WitnessInit,
            BootPhase::SchedulerInit,
            BootPhase::RootPartition,
            BootPhase::Handoff,
        ];

        for phase in &phases {
            self.boot.complete_phase(*phase)?;
            emit_boot_witness(&self.witness_log, *phase);
        }

        self.booted = true;
        Ok(())
    }

    /// Advance the scheduler by one epoch.
    ///
    /// Returns the epoch summary. Requires the kernel to have booted.
    pub fn tick(&mut self) -> RvmResult<rvm_sched::EpochSummary> {
        if !self.booted {
            return Err(RvmError::InvalidPartitionState);
        }

        let summary = self.scheduler.tick_epoch();

        // Emit an epoch witness.
        let mut record = WitnessRecord::zeroed();
        record.action_kind = ActionKind::SchedulerEpoch as u8;
        record.proof_tier = 1;
        let switch_bytes = summary.switch_count.to_le_bytes();
        record.payload[0..2].copy_from_slice(&switch_bytes);
        self.witness_log.append(record);

        Ok(summary)
    }

    /// Create a new partition with the given configuration.
    ///
    /// Emits a `PartitionCreate` witness record on success.
    pub fn create_partition(&mut self, config: &PartitionConfig) -> RvmResult<PartitionId> {
        if !self.booted {
            return Err(RvmError::InvalidPartitionState);
        }

        let epoch = self.scheduler.current_epoch();
        let id = self.partitions.create(
            rvm_partition::PartitionType::Agent,
            config.vcpu_count,
            epoch,
        )?;

        // Emit witness.
        let mut record = WitnessRecord::zeroed();
        record.action_kind = ActionKind::PartitionCreate as u8;
        record.proof_tier = 1;
        record.actor_partition_id = PartitionId::HYPERVISOR.as_u32();
        record.target_object_id = id.as_u32() as u64;
        self.witness_log.append(record);

        Ok(id)
    }

    /// Destroy a partition and reclaim its resources.
    ///
    /// This is a placeholder that emits a `PartitionDestroy` witness.
    /// Full resource reclamation is deferred.
    pub fn destroy_partition(&mut self, id: PartitionId) -> RvmResult<()> {
        if !self.booted {
            return Err(RvmError::InvalidPartitionState);
        }

        // Verify the partition exists.
        if self.partitions.get(id).is_none() {
            return Err(RvmError::PartitionNotFound);
        }

        // Emit witness.
        let mut record = WitnessRecord::zeroed();
        record.action_kind = ActionKind::PartitionDestroy as u8;
        record.proof_tier = 1;
        record.actor_partition_id = PartitionId::HYPERVISOR.as_u32();
        record.target_object_id = id.as_u32() as u64;
        self.witness_log.append(record);

        Ok(())
    }

    /// Return whether the kernel has completed booting.
    #[must_use]
    pub const fn is_booted(&self) -> bool {
        self.booted
    }

    /// Return the current scheduler epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.scheduler.current_epoch()
    }

    /// Return the number of active partitions.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.partitions.count()
    }

    /// Return the total number of witness records emitted.
    pub fn witness_count(&self) -> u64 {
        self.witness_log.total_emitted()
    }

    /// Return a reference to the kernel configuration.
    #[must_use]
    pub const fn config(&self) -> &RvmConfig {
        &self.config
    }

    /// Return a reference to the partition manager.
    #[must_use]
    pub fn partitions(&self) -> &PartitionManager {
        &self.partitions
    }

    /// Return a reference to the capability manager.
    #[must_use]
    pub fn cap_manager(&self) -> &CapabilityManager<DEFAULT_CAP_CAPACITY> {
        &self.cap_manager
    }

    /// Return a mutable reference to the capability manager.
    pub fn cap_manager_mut(&mut self) -> &mut CapabilityManager<DEFAULT_CAP_CAPACITY> {
        &mut self.cap_manager
    }

    /// Return a reference to the witness log.
    #[must_use]
    pub fn witness_log(&self) -> &WitnessLog<DEFAULT_WITNESS_CAPACITY> {
        &self.witness_log
    }

    // -- Feature-gated subsystems --

    /// Access the coherence engine (requires `coherence` feature).
    ///
    /// Returns `Err(Unsupported)` if the coherence feature is not enabled.
    #[cfg(feature = "coherence")]
    pub fn coherence_enabled(&self) -> bool {
        true
    }

    /// Access the coherence engine (stub when feature is disabled).
    #[cfg(not(feature = "coherence"))]
    pub fn coherence_enabled(&self) -> bool {
        false
    }

    /// Check whether WASM support is compiled in.
    #[cfg(feature = "wasm")]
    pub fn wasm_enabled(&self) -> bool {
        true
    }

    /// WASM support is not compiled in.
    #[cfg(not(feature = "wasm"))]
    pub fn wasm_enabled(&self) -> bool {
        false
    }
}

/// Emit a boot phase completion witness.
fn emit_boot_witness(log: &WitnessLog<DEFAULT_WITNESS_CAPACITY>, phase: rvm_boot::BootPhase) {
    let action = match phase {
        rvm_boot::BootPhase::Handoff => ActionKind::BootComplete,
        _ => ActionKind::BootAttestation,
    };
    let mut record = WitnessRecord::zeroed();
    record.action_kind = action as u8;
    record.proof_tier = 1;
    record.actor_partition_id = PartitionId::HYPERVISOR.as_u32();
    record.payload[0] = phase as u8;
    log.append(record);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_creation() {
        let kernel = Kernel::with_defaults();
        assert!(!kernel.is_booted());
        assert_eq!(kernel.partition_count(), 0);
        assert_eq!(kernel.witness_count(), 0);
    }

    #[test]
    fn test_boot_sequence() {
        let mut kernel = Kernel::with_defaults();
        assert!(kernel.boot().is_ok());
        assert!(kernel.is_booted());

        // 7 boot phases = 7 witness records.
        assert_eq!(kernel.witness_count(), 7);
    }

    #[test]
    fn test_double_boot_fails() {
        let mut kernel = Kernel::with_defaults();
        kernel.boot().unwrap();

        // Second boot attempt fails because phases are already complete.
        assert!(kernel.boot().is_err());
    }

    #[test]
    fn test_create_partition() {
        let mut kernel = Kernel::with_defaults();
        kernel.boot().unwrap();

        let config = PartitionConfig::default();
        let id = kernel.create_partition(&config).unwrap();
        assert_eq!(kernel.partition_count(), 1);
        assert!(kernel.partitions().get(id).is_some());

        // Witness for create.
        let pre_boot_witnesses = 7u64;
        assert_eq!(kernel.witness_count(), pre_boot_witnesses + 1);
    }

    #[test]
    fn test_create_partition_before_boot() {
        let mut kernel = Kernel::with_defaults();
        let config = PartitionConfig::default();
        assert_eq!(kernel.create_partition(&config), Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_destroy_partition() {
        let mut kernel = Kernel::with_defaults();
        kernel.boot().unwrap();

        let config = PartitionConfig::default();
        let id = kernel.create_partition(&config).unwrap();
        assert!(kernel.destroy_partition(id).is_ok());
    }

    #[test]
    fn test_destroy_nonexistent_partition() {
        let mut kernel = Kernel::with_defaults();
        kernel.boot().unwrap();

        let bad_id = PartitionId::new(999);
        assert_eq!(kernel.destroy_partition(bad_id), Err(RvmError::PartitionNotFound));
    }

    #[test]
    fn test_tick() {
        let mut kernel = Kernel::with_defaults();
        kernel.boot().unwrap();

        let summary = kernel.tick().unwrap();
        assert_eq!(summary.epoch, 0);
        assert_eq!(kernel.current_epoch(), 1);
    }

    #[test]
    fn test_tick_before_boot() {
        let mut kernel = Kernel::with_defaults();
        assert!(kernel.tick().is_err());
    }

    #[test]
    fn test_feature_gates() {
        let kernel = Kernel::with_defaults();

        // These compile regardless of features, but return false
        // when the features are not enabled.
        let _coherence = kernel.coherence_enabled();
        let _wasm = kernel.wasm_enabled();
    }

    #[test]
    fn test_custom_config() {
        let config = KernelConfig {
            rvm: RvmConfig {
                max_partitions: 64,
                ..RvmConfig::default()
            },
            cap: CapManagerConfig::new().with_max_depth(4),
        };
        let mut kernel = Kernel::new(config);
        assert_eq!(kernel.config().max_partitions, 64);
        kernel.boot().unwrap();
        assert!(kernel.is_booted());
    }

    #[test]
    fn test_multiple_partitions() {
        let mut kernel = Kernel::with_defaults();
        kernel.boot().unwrap();

        let config = PartitionConfig::default();
        let id1 = kernel.create_partition(&config).unwrap();
        let id2 = kernel.create_partition(&config).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(kernel.partition_count(), 2);
    }

    #[test]
    fn test_kernel_version() {
        assert!(!VERSION.is_empty());
        assert_eq!(CRATE_COUNT, 13);
    }
}
