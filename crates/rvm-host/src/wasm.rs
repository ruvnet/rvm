//! The WASM adapter: the boundary every backend has, and nothing else.
//!
//! This is the adapter that works everywhere — browser, embedded interpreter,
//! a desktop build with no operating-system integration wired up — because it
//! composes nothing beneath WASM. It is also the honest floor of the ADR-289
//! ladder: a package that needs a filesystem or a network is refused here
//! rather than started with the declaration treated as advice.

use rvm_rvf::CapabilityClass;
use rvm_wasm::MAX_MODULE_SIZE;

use crate::adapter::{AdapterDescriptor, HostAdapter, RuntimeClass};
use crate::isolation::HostEnvironment;
use crate::mechanism::{IsolationMechanism, MechanismSet, MechanismStatus};

/// The capability classes any RVM backend can hold to their declared bounds
/// without operating-system or device mediation.
///
/// Each of these is enforced by machinery the runtime itself owns: WASM linear
/// memory and quotas for [`Memory`](CapabilityClass::Memory), the read-only
/// mapping of the immutable base for [`Model`](CapabilityClass::Model), the
/// delta chain for [`PersistentState`](CapabilityClass::PersistentState), the
/// host-function boundary for [`Mcp`](CapabilityClass::Mcp) and
/// [`InterAgentMessaging`](CapabilityClass::InterAgentMessaging), and the
/// runtime's own virtual clock for [`Clock`](CapabilityClass::Clock).
///
/// Everything absent from this list needs a boundary outside WASM, which is
/// exactly why the hosted and bare-metal adapters exist.
pub const RUNTIME_ENFORCED_CLASSES: [CapabilityClass; 6] = [
    CapabilityClass::Memory,
    CapabilityClass::Model,
    CapabilityClass::PersistentState,
    CapabilityClass::Mcp,
    CapabilityClass::InterAgentMessaging,
    CapabilityClass::Clock,
];

/// WASM isolation with no operating-system integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmAdapter {
    max_module_bytes: usize,
}

impl WasmAdapter {
    /// An adapter admitting modules up to [`rvm_wasm::MAX_MODULE_SIZE`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_module_bytes: MAX_MODULE_SIZE,
        }
    }

    /// An adapter with a stricter module limit.
    ///
    /// The value is clamped to [`rvm_wasm::MAX_MODULE_SIZE`]: the executor's
    /// own limit is a backstop, and an adapter that raised it would be
    /// promising something the layer beneath will refuse anyway.
    #[must_use]
    pub const fn with_max_module_bytes(bytes: usize) -> Self {
        Self {
            max_module_bytes: if bytes < MAX_MODULE_SIZE {
                bytes
            } else {
                MAX_MODULE_SIZE
            },
        }
    }
}

impl Default for WasmAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl HostAdapter for WasmAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            name: "wasm",
            runtime: RuntimeClass::Wasm,
            max_module_bytes: self.max_module_bytes,
        }
    }

    fn environment(&self) -> HostEnvironment {
        HostEnvironment::portable()
    }

    fn mechanisms(&self) -> MechanismSet {
        MechanismSet::new().with_all(&IsolationMechanism::PORTABLE_CORE, MechanismStatus::Engaged)
    }

    fn enforces(&self, class: CapabilityClass) -> bool {
        RUNTIME_ENFORCED_CLASSES.contains(&class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Placement;
    use crate::isolation::IsolationClaim;
    use crate::testkit;
    use crate::witness::{event_of, HostEvent};
    use crate::HostError;
    use alloc::vec::Vec;
    use rvm_types::PartitionId;
    use rvm_wasm::agent::AgentManager;
    use rvm_witness::WitnessLog;

    const PLACEMENT: Placement = Placement::new(PartitionId::new(1), 0, 16);

    fn events<const N: usize>(log: &WitnessLog<N>) -> Vec<HostEvent> {
        (0..log.len())
            .filter_map(|i| log.get(i))
            .filter_map(|r| event_of(&r))
            .collect()
    }

    #[test]
    fn the_wasm_adapter_claims_wasm_only_and_never_more() {
        let adapter = WasmAdapter::new();
        assert_eq!(adapter.isolation_claim(), IsolationClaim::WasmOnly);
        assert!(!adapter.isolation_claim().is_bare_metal());
        assert_eq!(adapter.descriptor().runtime, RuntimeClass::Wasm);
    }

    #[test]
    fn it_declares_only_the_portable_core_and_engages_all_of_it() {
        let set = WasmAdapter::new().mechanisms();
        assert_eq!(set.len(), IsolationMechanism::PORTABLE_CORE.len());
        assert!(set.not_engaged().is_empty());
        for m in IsolationMechanism::PORTABLE_CORE {
            assert!(set.is_engaged(m));
        }
    }

    #[test]
    fn a_runtime_enforced_package_prepares_and_records_every_class() {
        let adapter = WasmAdapter::new();
        let pkg = testkit::package("memory,clock");
        let log = WitnessLog::<64>::new();

        let iso = adapter.prepare(&pkg, PLACEMENT, &log, 100).unwrap();
        assert_eq!(iso.claim, IsolationClaim::WasmOnly);
        assert_eq!(iso.adapter, "wasm");
        assert!(iso.is_granted(CapabilityClass::Clock));
        assert!(!iso.is_granted(CapabilityClass::Network));

        // Two grants, thirteen denials, one isolation record: every one of the
        // fifteen classes is accounted for in the chain.
        let seen = events(&log);
        assert_eq!(
            seen.iter()
                .filter(|e| **e == HostEvent::CapabilityGranted)
                .count(),
            2
        );
        assert_eq!(
            seen.iter()
                .filter(|e| **e == HostEvent::CapabilityDenied)
                .count(),
            13
        );
        assert_eq!(seen.last(), Some(&HostEvent::IsolationPrepared));
    }

    #[test]
    fn a_class_it_cannot_enforce_is_a_witnessed_refusal_not_a_partial_start() {
        let adapter = WasmAdapter::new();
        let pkg = testkit::package("memory,network");
        let log = WitnessLog::<64>::new();

        assert_eq!(
            adapter.prepare(&pkg, PLACEMENT, &log, 100),
            Err(HostError::CapabilityUnenforceable(CapabilityClass::Network))
        );

        // The refusal is in the chain, and no grant is — the memory class the
        // package also declared was never recorded as issued.
        let seen = events(&log);
        assert_eq!(seen, [HostEvent::CapabilityRefused]);
        assert!(!seen.contains(&HostEvent::CapabilityGranted));
        assert!(!seen.contains(&HostEvent::IsolationPrepared));

        let record = log.get(0).unwrap();
        assert_eq!(record.aux[1], CapabilityClass::Network as u8);
    }

    #[test]
    fn a_module_starts_only_after_isolation_is_prepared() {
        let adapter = WasmAdapter::new();
        let pkg = testkit::package("memory");
        let log = WitnessLog::<64>::new();
        let mut agents = AgentManager::<4>::new();

        let iso = adapter.prepare(&pkg, PLACEMENT, &log, 100).unwrap();
        let id = adapter
            .spawn(&iso, &testkit::MINIMAL_WASM, &mut agents, &log, 200)
            .unwrap();

        assert_eq!(agents.count(), 1);
        assert_eq!(agents.get(id).unwrap().partition_id, PLACEMENT.partition);
        assert!(events(&log).contains(&HostEvent::ModuleAdmitted));
    }

    #[test]
    fn a_malformed_module_is_refused_and_witnessed_before_any_agent_exists() {
        let adapter = WasmAdapter::new();
        let pkg = testkit::package("memory");
        let log = WitnessLog::<64>::new();
        let mut agents = AgentManager::<4>::new();

        let iso = adapter.prepare(&pkg, PLACEMENT, &log, 100).unwrap();
        let result = adapter.spawn(&iso, b"not wasm", &mut agents, &log, 200);

        assert!(matches!(result, Err(HostError::ModuleRejected(_))));
        assert_eq!(agents.count(), 0);
        assert!(events(&log).contains(&HostEvent::ModuleRefused));
        assert!(!events(&log).contains(&HostEvent::ModuleAdmitted));
    }

    #[test]
    fn an_oversize_module_is_refused_against_the_adapters_own_limit() {
        let adapter = WasmAdapter::with_max_module_bytes(4);
        let pkg = testkit::package("memory");
        let log = WitnessLog::<64>::new();
        let mut agents = AgentManager::<4>::new();

        let iso = adapter.prepare(&pkg, PLACEMENT, &log, 100).unwrap();
        assert_eq!(
            adapter.spawn(&iso, &testkit::MINIMAL_WASM, &mut agents, &log, 200),
            Err(HostError::ModuleTooLarge)
        );
        assert_eq!(agents.count(), 0);
    }

    #[test]
    fn an_adapter_cannot_raise_the_executors_module_limit() {
        let adapter = WasmAdapter::with_max_module_bytes(usize::MAX);
        assert_eq!(adapter.descriptor().max_module_bytes, MAX_MODULE_SIZE);
    }

    #[test]
    fn the_classes_rvm_cannot_represent_never_reach_an_adapter() {
        // rvm-rvf refuses clipboard and randomness during mapping, so a
        // VerifiedPackage can never declare them and `enforces` is never asked.
        let adapter = WasmAdapter::new();
        for class in [CapabilityClass::Clipboard, CapabilityClass::Randomness] {
            assert!(!class.is_representable());
            assert!(!adapter.enforces(class));
        }
    }
}
