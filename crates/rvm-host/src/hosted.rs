//! The hosted adapter: a normal desktop process, with whatever the operating
//! system will actually give it.
//!
//! # What this crate can and cannot do
//!
//! `rvm-host` is `no_std` and portable. It cannot call `CreateJobObject`,
//! `sandbox_init`, or `unshare(2)`; those are host-integration work sitting
//! above this layer, in the process that owns the platform SDK. So the OS
//! stack here is *declared* rather than applied: [`HostedAdapter::new`] lists
//! every mechanism ADR-285 §3 assigns to the platform and marks each one
//! [`MechanismStatus::Unimplemented`], and the integration that actually
//! applied one calls [`HostedAdapter::engaging`] to say so.
//!
//! The direction of that default is the point. An adapter that assumed its
//! declared stack took hold would report `os-sandbox+wasm` on a build where
//! nothing was applied — which is the exact overstatement ADR-285 exists to
//! prevent. Assuming nothing engaged means the claim degrades to `wasm-only`
//! and the capability classes that need OS mediation are refused. Wrong in the
//! safe direction, and visibly wrong: [`MechanismSet::not_engaged`] names
//! every mechanism that did not take hold.
//!
//! # Real versus unimplemented
//!
//! | Piece | Status here |
//! |---|---|
//! | Mechanism declaration per OS, and per-mechanism status | real |
//! | Claim derivation from *engaged* mechanisms | real |
//! | Capability enforceability keyed to engaged mechanisms | real |
//! | Module admission and agent spawn | real, via `rvm-wasm` |
//! | Applying a job object, sandbox profile, or namespace | **unimplemented** — needs a platform host |
//! | Notarization and hardened-runtime verification | **unimplemented** — a build and release property, reported not checked |

use rvm_rvf::CapabilityClass;
use rvm_wasm::MAX_MODULE_SIZE;

use crate::adapter::{AdapterDescriptor, HostAdapter, RuntimeClass};
use crate::error::{HostError, HostResult};
use crate::isolation::HostEnvironment;
use crate::mechanism::{HostOs, IsolationMechanism, MechanismSet, MechanismStatus};
use crate::wasm::RUNTIME_ENFORCED_CLASSES;

/// The largest OS stack is Linux, at five mechanisms.
const MAX_STACK: usize = 5;

/// A hosted desktop adapter for one operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedAdapter {
    os: HostOs,
    /// One flag per entry of [`IsolationMechanism::stack_for`], in that order.
    engaged: [bool; MAX_STACK],
    max_module_bytes: usize,
}

impl HostedAdapter {
    /// An adapter for `os` with nothing engaged yet.
    ///
    /// Its claim is [`crate::IsolationClaim::WasmOnly`] until an integration
    /// reports a mechanism through [`Self::engaging`].
    #[must_use]
    pub const fn new(os: HostOs) -> Self {
        Self {
            os,
            engaged: [false; MAX_STACK],
            max_module_bytes: MAX_MODULE_SIZE,
        }
    }

    /// The operating system this adapter runs on.
    #[must_use]
    pub const fn host_os(self) -> HostOs {
        self.os
    }

    /// Record that the host integration applied `mechanism`.
    ///
    /// # Errors
    ///
    /// [`HostError::MechanismNotInStack`] when `mechanism` does not belong to
    /// this adapter's operating system. Engaging seccomp does nothing for a
    /// Windows process, and accepting the claim would let a mislabelled
    /// integration earn an isolation class it has not got.
    pub fn engaging(mut self, mechanism: IsolationMechanism) -> HostResult<Self> {
        let stack = IsolationMechanism::stack_for(self.os);
        let Some(index) = stack.iter().position(|m| *m == mechanism) else {
            return Err(HostError::MechanismNotInStack(mechanism));
        };
        self.engaged[index] = true;
        Ok(self)
    }

    /// Record that the host integration applied every mechanism in `mechanisms`.
    ///
    /// # Errors
    ///
    /// As [`Self::engaging`], for the first mechanism outside this stack.
    pub fn engaging_all(mut self, mechanisms: &[IsolationMechanism]) -> HostResult<Self> {
        for m in mechanisms {
            self = self.engaging(*m)?;
        }
        Ok(self)
    }

    /// Record that the whole declared stack took hold.
    ///
    /// For an integration that applied everything ADR-285 §3 lists for the
    /// platform, and for tests that need the fully-confined case.
    #[must_use]
    pub fn fully_engaged(mut self) -> Self {
        let stack = IsolationMechanism::stack_for(self.os);
        for (i, _) in stack.iter().enumerate() {
            self.engaged[i] = true;
        }
        self
    }

    /// Restrict the module size this adapter admits.
    #[must_use]
    pub const fn with_max_module_bytes(mut self, bytes: usize) -> Self {
        self.max_module_bytes = if bytes < MAX_MODULE_SIZE {
            bytes
        } else {
            MAX_MODULE_SIZE
        };
        self
    }

    /// The mechanisms that actually engaged.
    fn engaged_mechanisms(self) -> impl Iterator<Item = IsolationMechanism> {
        let stack = IsolationMechanism::stack_for(self.os);
        let engaged = self.engaged;
        stack
            .iter()
            .enumerate()
            .filter(move |(i, _)| engaged[*i])
            .map(|(_, m)| *m)
    }

    fn confines_filesystem(self) -> bool {
        self.engaged_mechanisms()
            .any(IsolationMechanism::confines_filesystem)
    }

    fn confines_network(self) -> bool {
        self.engaged_mechanisms()
            .any(IsolationMechanism::confines_network)
    }

    fn confines_process(self) -> bool {
        self.engaged_mechanisms()
            .any(IsolationMechanism::confines_process)
    }
}

impl HostAdapter for HostedAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            name: "hosted",
            runtime: RuntimeClass::OsIsolationWasm,
            max_module_bytes: self.max_module_bytes,
        }
    }

    fn environment(&self) -> HostEnvironment {
        HostEnvironment::hosted(self.os)
    }

    fn mechanisms(&self) -> MechanismSet {
        let stack = IsolationMechanism::stack_for(self.os);
        let mut set = MechanismSet::new().with_all(
            &IsolationMechanism::PORTABLE_CORE,
            MechanismStatus::Engaged,
        );
        for (i, mechanism) in stack.iter().enumerate() {
            let status = if self.engaged[i] {
                MechanismStatus::Engaged
            } else {
                MechanismStatus::Unimplemented
            };
            set = set.with(*mechanism, status);
        }
        set
    }

    fn enforces(&self, class: CapabilityClass) -> bool {
        if RUNTIME_ENFORCED_CLASSES.contains(&class) {
            return true;
        }
        match class {
            CapabilityClass::Filesystem => self.confines_filesystem(),
            CapabilityClass::Network => self.confines_network(),
            CapabilityClass::Process => self.confines_process(),
            // Devices need a lease, and a lease needs a hypervisor. A desktop
            // process can open the camera; it cannot bound what the agent then
            // does with it, so declaring these would be enforcement in name.
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Placement;
    use crate::isolation::IsolationClaim;
    use crate::testkit;
    use crate::witness::{claim_of, event_of, HostEvent};
    use alloc::vec::Vec;
    use rvm_types::PartitionId;
    use rvm_witness::WitnessLog;

    const PLACEMENT: Placement = Placement::new(PartitionId::new(2), 0, 16);

    #[test]
    fn a_freshly_constructed_hosted_adapter_claims_wasm_only() {
        for os in HostOs::ALL {
            let adapter = HostedAdapter::new(os);
            assert_eq!(
                adapter.isolation_claim(),
                IsolationClaim::WasmOnly,
                "{os} overstated a stack it never applied"
            );
        }
    }

    #[test]
    fn an_unapplied_stack_is_reported_as_unimplemented_rather_than_omitted() {
        let adapter = HostedAdapter::new(HostOs::Linux);
        let set = adapter.mechanisms();
        let stack = IsolationMechanism::stack_for(HostOs::Linux);

        for m in stack {
            assert_eq!(set.status_of(*m), Some(MechanismStatus::Unimplemented));
        }
        assert_eq!(set.not_engaged().len(), stack.len());
    }

    #[test]
    fn engaging_one_mechanism_earns_the_os_sandbox_claim() {
        let adapter = HostedAdapter::new(HostOs::Linux)
            .engaging(IsolationMechanism::LinuxSeccomp)
            .unwrap();
        assert_eq!(adapter.isolation_claim(), IsolationClaim::OsSandboxWasm);
        assert!(adapter.mechanisms().is_engaged(IsolationMechanism::LinuxSeccomp));
        assert!(!adapter.mechanisms().is_engaged(IsolationMechanism::LinuxCgroups));
    }

    #[test]
    fn a_mechanism_from_another_platform_is_rejected() {
        assert_eq!(
            HostedAdapter::new(HostOs::Windows).engaging(IsolationMechanism::LinuxSeccomp),
            Err(HostError::MechanismNotInStack(
                IsolationMechanism::LinuxSeccomp
            ))
        );
        assert_eq!(
            HostedAdapter::new(HostOs::MacOs).engaging(IsolationMechanism::WindowsJobObject),
            Err(HostError::MechanismNotInStack(
                IsolationMechanism::WindowsJobObject
            ))
        );
    }

    #[test]
    fn a_bare_metal_mechanism_can_never_be_engaged_by_a_hosted_adapter() {
        for os in HostOs::ALL {
            for m in IsolationMechanism::BARE_METAL_ONLY {
                assert_eq!(
                    HostedAdapter::new(os).engaging(m),
                    Err(HostError::MechanismNotInStack(m))
                );
            }
        }
    }

    #[test]
    fn a_fully_engaged_hosted_adapter_still_never_claims_partition() {
        for os in HostOs::ALL {
            let adapter = HostedAdapter::new(os).fully_engaged();
            let claim = adapter.isolation_claim();
            assert_eq!(claim, IsolationClaim::OsSandboxWasm);
            assert!(!claim.is_bare_metal());
            assert!(adapter.mechanisms().not_engaged().is_empty());
        }
    }

    #[test]
    fn filesystem_is_enforceable_only_once_something_confines_paths() {
        let bare = HostedAdapter::new(HostOs::Linux);
        assert!(!bare.enforces(CapabilityClass::Filesystem));

        // cgroups bound memory and CPU; they say nothing about paths.
        let cgroups = bare.engaging(IsolationMechanism::LinuxCgroups).unwrap();
        assert!(!cgroups.enforces(CapabilityClass::Filesystem));

        let mounts = cgroups
            .engaging(IsolationMechanism::LinuxRestrictedMounts)
            .unwrap();
        assert!(mounts.enforces(CapabilityClass::Filesystem));
    }

    #[test]
    fn network_is_enforceable_only_once_something_confines_destinations() {
        let bare = HostedAdapter::new(HostOs::Windows);
        assert!(!bare.enforces(CapabilityClass::Network));

        let job = bare.engaging(IsolationMechanism::WindowsJobObject).unwrap();
        assert!(!job.enforces(CapabilityClass::Network));

        let netctl = job
            .engaging(IsolationMechanism::WindowsOutboundNetworkControl)
            .unwrap();
        assert!(netctl.enforces(CapabilityClass::Network));
    }

    #[test]
    fn device_classes_are_never_enforceable_from_a_desktop_process() {
        let adapter = HostedAdapter::new(HostOs::MacOs).fully_engaged();
        for class in [
            CapabilityClass::Gpu,
            CapabilityClass::Sensor,
            CapabilityClass::Display,
            CapabilityClass::Audio,
        ] {
            assert!(!adapter.enforces(class), "{class} claimed a device lease");
        }
    }

    #[test]
    fn a_network_package_is_refused_before_confinement_and_accepted_after() {
        let pkg = testkit::package("memory,network");
        let log = WitnessLog::<64>::new();

        let bare = HostedAdapter::new(HostOs::Linux);
        assert_eq!(
            bare.prepare(&pkg, PLACEMENT, &log, 10),
            Err(HostError::CapabilityUnenforceable(CapabilityClass::Network))
        );

        let confined = bare
            .engaging(IsolationMechanism::LinuxNetworkNamespace)
            .unwrap();
        let iso = confined.prepare(&pkg, PLACEMENT, &log, 20).unwrap();
        assert!(iso.is_granted(CapabilityClass::Network));
        assert_eq!(iso.claim, IsolationClaim::OsSandboxWasm);
    }

    #[test]
    fn the_prepared_record_carries_the_claim_the_adapter_actually_obtained() {
        let pkg = testkit::package("memory");

        for (adapter, expected) in [
            (HostedAdapter::new(HostOs::Linux), IsolationClaim::WasmOnly),
            (
                HostedAdapter::new(HostOs::Linux).fully_engaged(),
                IsolationClaim::OsSandboxWasm,
            ),
        ] {
            let log = WitnessLog::<64>::new();
            adapter.prepare(&pkg, PLACEMENT, &log, 10).unwrap();

            let prepared: Vec<_> = (0..log.len())
                .filter_map(|i| log.get(i))
                .filter(|r| event_of(r) == Some(HostEvent::IsolationPrepared))
                .collect();
            assert_eq!(prepared.len(), 1);
            assert_eq!(claim_of(&prepared[0]), Some(expected));
            assert_ne!(claim_of(&prepared[0]), Some(IsolationClaim::Partition));
        }
    }

    #[test]
    fn the_hosted_adapter_sits_on_the_second_rung_of_the_ladder() {
        let d = HostedAdapter::new(HostOs::MacOs).descriptor();
        assert_eq!(d.runtime, RuntimeClass::OsIsolationWasm);
        assert_eq!(d.runtime.rank(), 1);
        assert_eq!(d.name, "hosted");
    }
}
