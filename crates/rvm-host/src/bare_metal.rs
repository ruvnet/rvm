//! The bare-metal adapter: the only one that may claim partition isolation.
//!
//! It exists here for two reasons. It is the top rung of the ADR-289 §2
//! ladder, so runtime selection needs something to select. And it is what
//! makes [`crate::IsolationClaim::Partition`] a reachable value at all, which
//! in turn makes the hosted adapters' inability to reach it a property worth
//! testing rather than a vacuous one.
//!
//! Constructing it requires a live partition in a real
//! [`PartitionManager`](rvm_partition::PartitionManager) — see
//! [`crate::PartitionEvidence`]. A desktop process has no partition manager
//! and therefore cannot build this adapter, let alone its claim.

use rvm_partition::{PartitionId, PartitionManager};
use rvm_rvf::CapabilityClass;
use rvm_wasm::MAX_MODULE_SIZE;

use crate::adapter::{AdapterDescriptor, HostAdapter, RuntimeClass};
use crate::isolation::{HostEnvironment, PartitionEvidence};
use crate::mechanism::{IsolationMechanism, MechanismSet, MechanismStatus};

/// Bare-metal RVM: partitions, capability tables, device leases, measured
/// boot, and witnessed security gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BareMetalAdapter {
    evidence: PartitionEvidence,
}

impl BareMetalAdapter {
    /// An adapter for `partition`, which must be live in `manager`.
    ///
    /// Returns `None` when it is not. The check is the whole point: without
    /// it, "bare metal" would be a string an adapter could choose.
    #[must_use]
    pub fn new(manager: &PartitionManager, partition: PartitionId) -> Option<Self> {
        PartitionEvidence::from_manager(manager, partition).map(|evidence| Self { evidence })
    }

    /// The partition this adapter runs agents in.
    #[must_use]
    pub const fn partition(self) -> PartitionId {
        self.evidence.partition()
    }
}

impl HostAdapter for BareMetalAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            name: "bare-metal",
            runtime: RuntimeClass::NativeRvm,
            max_module_bytes: MAX_MODULE_SIZE,
        }
    }

    fn environment(&self) -> HostEnvironment {
        HostEnvironment::bare_metal(self.evidence)
    }

    fn mechanisms(&self) -> MechanismSet {
        MechanismSet::new()
            .with_all(&IsolationMechanism::PORTABLE_CORE, MechanismStatus::Engaged)
            .with_all(
                &IsolationMechanism::BARE_METAL_ONLY,
                MechanismStatus::Engaged,
            )
    }

    fn enforces(&self, class: CapabilityClass) -> bool {
        // Every class RVM can represent has a kernel object behind it here:
        // regions, comm edges, partitions, and device leases. The two classes
        // RVM cannot represent are refused upstream by `rvm-rvf`, so a package
        // declaring one never reaches an adapter.
        class.is_representable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Placement;
    use crate::isolation::IsolationClaim;
    use crate::testkit;
    use crate::witness::{claim_of, event_of, HostEvent};
    use rvm_partition::PartitionType;
    use rvm_witness::WitnessLog;

    fn manager() -> (PartitionManager, PartitionId) {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        (mgr, id)
    }

    #[test]
    fn it_cannot_be_built_without_a_live_partition() {
        let (mgr, _) = manager();
        assert!(BareMetalAdapter::new(&mgr, PartitionId::new(999)).is_none());
    }

    #[test]
    fn it_claims_partition_isolation() {
        let (mgr, id) = manager();
        let adapter = BareMetalAdapter::new(&mgr, id).unwrap();
        assert_eq!(adapter.isolation_claim(), IsolationClaim::Partition);
        assert!(adapter.isolation_claim().is_bare_metal());
        assert_eq!(adapter.partition(), id);
        assert_eq!(adapter.descriptor().runtime, RuntimeClass::NativeRvm);
    }

    #[test]
    fn it_engages_the_hypervisor_class_mechanisms() {
        let (mgr, id) = manager();
        let set = BareMetalAdapter::new(&mgr, id).unwrap().mechanisms();
        for m in IsolationMechanism::BARE_METAL_ONLY {
            assert!(set.is_engaged(m), "{m} was declared but not engaged");
        }
        assert!(set.not_engaged().is_empty());
    }

    #[test]
    fn it_enforces_every_representable_class() {
        let (mgr, id) = manager();
        let adapter = BareMetalAdapter::new(&mgr, id).unwrap();
        let representable = CapabilityClass::ALL
            .into_iter()
            .filter(|c| c.is_representable());
        for class in representable {
            assert!(adapter.enforces(class), "{class} was not enforceable");
        }
    }

    #[test]
    fn a_package_the_wasm_adapter_refuses_prepares_here() {
        let (mgr, id) = manager();
        let adapter = BareMetalAdapter::new(&mgr, id).unwrap();
        let pkg = testkit::package("network,gpu,filesystem");
        let log = WitnessLog::<64>::new();

        let iso = adapter
            .prepare(&pkg, Placement::new(id, 0, 16), &log, 10)
            .unwrap();
        assert_eq!(iso.claim, IsolationClaim::Partition);
        assert!(iso.is_granted(CapabilityClass::Gpu));

        let prepared = (0..log.len())
            .filter_map(|i| log.get(i))
            .find(|r| event_of(r) == Some(HostEvent::IsolationPrepared))
            .unwrap();
        assert_eq!(claim_of(&prepared), Some(IsolationClaim::Partition));
    }
}
