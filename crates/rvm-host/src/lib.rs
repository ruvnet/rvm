//! # Host adapters for RVM
//!
//! The layer between a verified RVF and a running agent. `rvm-rvf` answers
//! "may this artifact run?"; this crate answers "inside what, and how honestly
//! can we describe it?" It implements the `rvm-host` surface of ADR-289
//! (desktop host adapters) and the isolation-claim discipline of ADR-285
//! (hosted RVM security boundary).
//!
//! ## Three things this crate refuses to do
//!
//! **It will not execute an unverified artifact.** Every entry point that can
//! lead to execution takes a [`VerifiedPackage`], whose only constructor
//! rejects a [`VerificationReport`](rvm_rvf::VerificationReport) with
//! `ok == false`. Verification before allocation (ADR-284 §1.1) is a type, not
//! a convention.
//!
//! **It will not let a hosted process claim bare-metal isolation.**
//! [`IsolationClaim`] is derived from a [`HostEnvironment`] and a
//! [`MechanismSet`], never asserted. The bare-metal environment can only be
//! built from [`PartitionEvidence`], which requires a live partition in a real
//! [`PartitionManager`](rvm_partition::PartitionManager); a desktop process
//! has none, so [`IsolationClaim::derive`] has no branch that returns
//! [`IsolationClaim::Partition`] for it. A hosted adapter that declared an
//! operating-system stack but engaged none of it degrades to
//! [`IsolationClaim::WasmOnly`] rather than assuming its stack took hold.
//!
//! **It will not start with a capability class it cannot enforce.** ADR-286 §3
//! requires refusal rather than degradation, so [`HostAdapter::prepare`]
//! checks the whole declared set before recording any grant, and a package
//! whose declaration outruns the adapter produces a witnessed refusal with no
//! grant records behind it.
//!
//! ## The adapters
//!
//! | Adapter | Environment | Claim | Enforces beyond the runtime core |
//! |---|---|---|---|
//! | [`WasmAdapter`] | portable | `wasm-only` | nothing |
//! | [`HostedAdapter`] | Windows / macOS / Linux desktop | `os-sandbox+wasm`, or `wasm-only` when nothing engaged | filesystem, network, process — each keyed to an engaged mechanism |
//! | [`BareMetalAdapter`] | RVM partition | `partition` | every representable class |
//!
//! ## Using one
//!
//! ```ignore
//! use rvm_host::{HostAdapter, HostedAdapter, HostOs, IsolationMechanism, Placement, VerifiedPackage};
//!
//! let report = rvm_rvf::verify(bytes, &opts)?;
//! rvm_rvf::emit_report(&report, &log, witness_ctx);   // pass or fail, it is recorded
//! let package = VerifiedPackage::from_report(&report)?;  // refuses a failed report
//!
//! let adapter = HostedAdapter::new(HostOs::Linux)
//!     .engaging(IsolationMechanism::LinuxNamespaces)?   // the host integration applied this
//!     .engaging(IsolationMechanism::LinuxSeccomp)?;
//!
//! let isolation = adapter.prepare(&package, Placement::new(partition, epoch, pages), &log, now)?;
//! assert!(!isolation.claim.is_bare_metal());            // it never is, here
//! let agent = adapter.spawn(&isolation, wasm_bytes, &mut agents, &log, now)?;
//! ```
//!
//! ## Allocation
//!
//! `no_std` with `alloc` required, because a capability set and a mechanism
//! set are both variable-length. Nothing on the decision path allocates beyond
//! those two vectors; witness details are typed codes rather than formatted
//! strings.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::doc_markdown)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod adapter;
pub mod bare_metal;
pub mod error;
pub mod hosted;
pub mod isolation;
pub mod mechanism;
pub mod package;
pub mod wasm;
pub mod witness;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use adapter::{
    strongest, AdapterDescriptor, HostAdapter, IsolationContext, Placement, RuntimeClass,
};
pub use bare_metal::BareMetalAdapter;
pub use error::{HostError, HostResult};
pub use hosted::HostedAdapter;
pub use isolation::{HostEnvironment, IsolationClaim, PartitionEvidence};
pub use mechanism::{HostOs, IsolationMechanism, MechanismReport, MechanismSet, MechanismStatus};
pub use package::VerifiedPackage;
pub use wasm::{WasmAdapter, RUNTIME_ENFORCED_CLASSES};
pub use witness::{build_record, claim_of, emit, event_of, HostEvent, HostWitnessContext};

/// The version of the host-adapter contract this crate implements.
///
/// Pairs with [`rvm_rvf::RVF_CONTRACT_VERSION`]: an adapter and a loader are
/// only compatible when both contract versions are ones the other recognizes
/// (ADR-291).
pub const HOST_CONTRACT_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use rvm_partition::{PartitionManager, PartitionType};
    use rvm_rvf::CapabilityClass;
    use rvm_types::PartitionId;
    use rvm_wasm::agent::AgentManager;
    use rvm_witness::WitnessLog;

    #[test]
    fn the_same_package_runs_under_every_adapter_with_a_different_honest_claim() {
        let package = testkit::package("memory,clock");
        let placement = Placement::new(PartitionId::new(1), 0, 16);

        let mut manager = PartitionManager::new();
        let partition = manager.create(PartitionType::Agent, 1, 0).unwrap();

        let wasm = WasmAdapter::new();
        let hosted = HostedAdapter::new(HostOs::Linux).fully_engaged();
        let bare = BareMetalAdapter::new(&manager, partition).unwrap();

        let log = WitnessLog::<256>::new();
        let claims = [
            wasm.prepare(&package, placement, &log, 1).unwrap().claim,
            hosted.prepare(&package, placement, &log, 2).unwrap().claim,
            bare.prepare(&package, Placement::new(partition, 0, 16), &log, 3)
                .unwrap()
                .claim,
        ];

        assert_eq!(
            claims,
            [
                IsolationClaim::WasmOnly,
                IsolationClaim::OsSandboxWasm,
                IsolationClaim::Partition,
            ]
        );
        // Only the bare-metal one claims a hypervisor boundary.
        assert_eq!(claims.iter().filter(|c| c.is_bare_metal()).count(), 1);
    }

    #[test]
    fn no_hosted_adapter_in_any_configuration_reports_bare_metal() {
        let package = testkit::package("memory");
        let placement = Placement::new(PartitionId::new(1), 0, 16);

        for os in HostOs::ALL {
            for adapter in [
                HostedAdapter::new(os),
                HostedAdapter::new(os).fully_engaged(),
            ] {
                let log = WitnessLog::<64>::new();
                let iso = adapter.prepare(&package, placement, &log, 1).unwrap();
                assert!(!iso.claim.is_bare_metal(), "{os} claimed bare metal");

                // And the record agrees with the context, so an auditor
                // reading only the chain reaches the same conclusion.
                let claims: Vec<_> = (0..log.len())
                    .filter_map(|i| log.get(i))
                    .filter_map(|r| claim_of(&r))
                    .collect();
                assert!(!claims.is_empty());
                assert!(!claims.contains(&IsolationClaim::Partition));
            }
        }
    }

    #[test]
    fn nothing_executes_before_verification_succeeds() {
        // The failed report yields no package, and every path to `spawn`
        // requires one, so there is no arrangement of these calls that starts
        // a module from an artifact that did not verify.
        let data = testkit::container_with_wasm("memory");
        let report = rvm_rvf::verify(&data, &rvm_rvf::VerifyOptions::default()).unwrap();
        assert!(!report.is_ok());
        assert_eq!(
            VerifiedPackage::from_report(&report),
            Err(HostError::Unverified)
        );
    }

    #[test]
    fn selection_prefers_bare_metal_then_hosted_then_wasm() {
        let mut manager = PartitionManager::new();
        let partition = manager.create(PartitionType::Agent, 1, 0).unwrap();

        let descriptors = [
            WasmAdapter::new().descriptor(),
            HostedAdapter::new(HostOs::Linux).descriptor(),
            BareMetalAdapter::new(&manager, partition)
                .unwrap()
                .descriptor(),
        ];
        assert_eq!(strongest(&descriptors).unwrap().name, "bare-metal");
        assert_eq!(strongest(&descriptors[..2]).unwrap().name, "hosted");
        assert_eq!(strongest(&descriptors[..1]).unwrap().name, "wasm");
    }

    #[test]
    fn a_full_start_leaves_a_verifiable_witness_chain() {
        let package = testkit::package("memory,clock");
        let adapter = WasmAdapter::new();
        let log = WitnessLog::<256>::new();
        let mut agents = AgentManager::<4>::new();

        let iso = adapter
            .prepare(
                &package,
                Placement::new(PartitionId::new(1), 0, 16),
                &log,
                1,
            )
            .unwrap();
        adapter
            .spawn(&iso, &testkit::MINIMAL_WASM, &mut agents, &log, 2)
            .unwrap();

        let records: Vec<_> = (0..log.len()).filter_map(|i| log.get(i)).collect();
        assert!(rvm_witness::verify_chain(&records).is_ok());

        // Every one of the fifteen classes is decided in the chain exactly once.
        let decided: Vec<u8> = records
            .iter()
            .filter(|r| {
                matches!(
                    event_of(r),
                    Some(HostEvent::CapabilityGranted | HostEvent::CapabilityDenied)
                )
            })
            .map(|r| r.aux[1])
            .collect();
        assert_eq!(decided.len(), CapabilityClass::ALL.len());
    }

    #[test]
    fn no_adapter_admits_a_module_larger_than_the_executor_backstop() {
        let mut manager = PartitionManager::new();
        let partition = manager.create(PartitionType::Agent, 1, 0).unwrap();

        for descriptor in [
            WasmAdapter::new().descriptor(),
            HostedAdapter::new(HostOs::MacOs).descriptor(),
            BareMetalAdapter::new(&manager, partition)
                .unwrap()
                .descriptor(),
        ] {
            assert!(
                descriptor.max_module_bytes <= rvm_wasm::MAX_MODULE_SIZE,
                "{} would admit more than the executor accepts",
                descriptor.name
            );
        }
    }
}
