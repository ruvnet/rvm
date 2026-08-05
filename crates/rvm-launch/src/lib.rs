//! # Instance lifecycle for RVM
//!
//! The layer above `rvm-host`. `rvm-rvf` decides whether an artifact may run,
//! `rvm-host` decides what it runs inside, and this crate drives one execution
//! through create, start, suspend, resume, checkpoint, and terminate. It
//! implements the `rvm-launch` surface of ADR-289 and the lineage binding of
//! ADR-288 §4.
//!
//! ## The library is the contract
//!
//! ADR-289 §3 lists these as CLI verbs, and a binary is a thin shell over what
//! is here. Keeping the surface a library first is what stops the CLI, the
//! Tauri reader through `rvm-ffi`, and Forge through `rvm-node` from enforcing
//! three different things — the failure mode ADR-289 rejects in its
//! alternatives.
//!
//! | ADR-289 verb | Here |
//! |---|---|
//! | `rvm inspect` | [`inspect`] |
//! | `rvm verify` | [`verify`] |
//! | `rvm run` | [`Instance::create`] then [`Instance::start`] |
//! | `rvm suspend` | [`Instance::suspend`] |
//! | `rvm resume` | [`Instance::resume`] |
//! | `rvm checkpoint` | [`Instance::checkpoint`] |
//! | `rvm witness` | [`Instance::witness`] |
//! | `rvm terminate` | [`Instance::terminate`] |
//!
//! ## Four invariants
//!
//! **Nothing executes before verification succeeds.** [`Instance::create`]
//! takes a [`VerifiedPackage`](rvm_host::VerifiedPackage), whose only
//! constructor rejects a failed report.
//!
//! **Inspection is not execution.** [`inspect`] and [`verify`] read headers,
//! hash payloads, and check signatures. Neither maps a segment, resolves an
//! entry point, or interprets a payload, so a scanner can handle an untrusted
//! artifact without becoming an execution surface for it.
//!
//! **Illegal transitions are errors, not no-ops.** The state machine in
//! [`state`] permits nothing outside its table, and each refusal is witnessed
//! before it is returned.
//!
//! **State binds to its lineage.** A [`Checkpoint`] carries the base RVF
//! identity it was produced under (ADR-288 §4), and [`Instance::restore`]
//! refuses one from a different base before it touches the state machine or a
//! runtime. Instance identity is recorded as provenance but is deliberately
//! *not* a gate — ADR-289 criterion 7 requires suspending under one host
//! adapter and resuming under another, so the instance on the far side is a
//! new one by construction.
//!
//! ## Using it
//!
//! ```ignore
//! use rvm_launch::{inspect, verify, Instance, InstanceId};
//! use rvm_host::{Placement, VerifiedPackage, WasmAdapter};
//!
//! let report = verify(bytes, &opts, &log, witness_ctx)?;   // witnessed either way
//! let package = VerifiedPackage::from_report(&report)?;    // refuses a failed report
//!
//! let mut instance = Instance::create(
//!     InstanceId::new(1), WasmAdapter::new(), package, placement, &log, now,
//! )?;
//! instance.start(wasm_bytes, &mut agents, &log, now)?;
//! instance.suspend(&mut agents, &log, now)?;
//! let checkpoint = instance.checkpoint(&log, now)?;        // bound to the base identity
//! instance.terminate(&mut agents, &log, now)?;
//!
//! let chain = instance.witness(&log);
//! ```
//!
//! ## Allocation
//!
//! `no_std` with `alloc` required: the capability set inherited from
//! `rvm-host` and the witness spans an instance accumulates are both
//! variable-length. Each lifecycle operation costs at most one span.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::doc_markdown)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod checkpoint;
pub mod error;
pub mod inspect;
pub mod instance;
pub mod state;
pub mod witness;

pub use checkpoint::Checkpoint;
pub use error::{LaunchError, LaunchResult};
pub use inspect::{inspect, verify, Inspection, SegmentSummary};
pub use instance::Instance;
pub use state::{is_legal, InstanceId, InstanceState, LifecycleOp};
pub use witness::{build_record, emit, emit_illegal, event_of, LaunchEvent, LaunchWitnessContext};

/// The version of the lifecycle contract this crate implements.
///
/// Pairs with [`rvm_host::HOST_CONTRACT_VERSION`] and
/// [`rvm_rvf::RVF_CONTRACT_VERSION`] in the ADR-291 compatibility matrix.
pub const LAUNCH_CONTRACT_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use rvm_host::{
        testkit, HostAdapter, HostError, HostOs, HostedAdapter, IsolationClaim, IsolationMechanism,
        Placement, VerifiedPackage, WasmAdapter,
    };
    use rvm_rvf::{CapabilityClass, VerifyOptions, WitnessContext};
    use rvm_types::PartitionId;
    use rvm_wasm::agent::AgentManager;
    use rvm_witness::WitnessLog;

    const PLACEMENT: Placement = Placement::new(PartitionId::new(1), 0, 16);

    #[test]
    fn inspect_and_verify_never_reach_an_instance_on_their_own() {
        // The whole path from bytes to execution, with the gate in the middle.
        let data = testkit::container_with_wasm("memory,clock");
        let log = WitnessLog::<256>::new();

        // Inspection tells you what the artifact claims. It grants nothing.
        let inspected = inspect(&data).unwrap();
        assert_eq!(
            inspected.declared_classes,
            [CapabilityClass::Memory, CapabilityClass::Clock]
        );

        // Under the strict posture this artifact does not verify, and there is
        // no way from that report to a running instance.
        let strict = verify(
            &data,
            &VerifyOptions::default(),
            &log,
            WitnessContext::new(1, 1),
        )
        .unwrap();
        assert!(!strict.ok);
        assert_eq!(
            VerifiedPackage::from_report(&strict),
            Err(HostError::Unverified)
        );

        // Under the development posture it does, and only then does an
        // instance exist.
        let permitted = verify(
            &data,
            &testkit::lenient_options(),
            &log,
            WitnessContext::new(1, 2),
        )
        .unwrap();
        let package = VerifiedPackage::from_report(&permitted).unwrap();
        let instance = Instance::create(
            InstanceId::new(1),
            WasmAdapter::new(),
            package,
            PLACEMENT,
            &log,
            3,
        )
        .unwrap();
        assert_eq!(instance.state(), InstanceState::Created);
    }

    #[test]
    fn an_undeclared_capability_is_unavailable_to_a_running_instance() {
        let log = WitnessLog::<256>::new();
        let mut agents = AgentManager::<4>::new();
        let mut instance = Instance::create(
            InstanceId::new(1),
            WasmAdapter::new(),
            testkit::package("memory"),
            PLACEMENT,
            &log,
            1,
        )
        .unwrap();
        instance
            .start(&testkit::MINIMAL_WASM, &mut agents, &log, 2)
            .unwrap();

        // Fourteen of the fifteen classes stay closed, and each closure is in
        // the chain rather than merely implied by its absence.
        for class in CapabilityClass::ALL {
            let expected = class == CapabilityClass::Memory;
            assert_eq!(instance.isolation().is_granted(class), expected, "{class}");
        }
        let denied: Vec<_> = instance
            .witness(&log)
            .iter()
            .filter(|r| rvm_host::event_of(r) == Some(rvm_host::HostEvent::CapabilityDenied))
            .map(|r| r.aux[1])
            .collect();
        assert_eq!(denied.len(), 14);
    }

    #[test]
    fn an_unsupported_capability_class_is_a_witnessed_refusal_not_a_partial_start() {
        let log = WitnessLog::<256>::new();
        let result = Instance::create(
            InstanceId::new(1),
            WasmAdapter::new(),
            testkit::package("memory,filesystem"),
            PLACEMENT,
            &log,
            1,
        );

        assert!(matches!(
            result,
            Err(LaunchError::Host(HostError::CapabilityUnenforceable(
                CapabilityClass::Filesystem
            )))
        ));
        assert_eq!(log.total_emitted(), 1);
        let record = log.get(0).unwrap();
        assert_eq!(
            rvm_host::event_of(&record),
            Some(rvm_host::HostEvent::CapabilityRefused)
        );
    }

    #[test]
    fn the_adapter_that_can_enforce_the_class_starts_the_same_package() {
        let log = WitnessLog::<256>::new();
        let mut agents = AgentManager::<4>::new();
        let adapter = HostedAdapter::new(HostOs::Linux)
            .engaging(IsolationMechanism::LinuxRestrictedMounts)
            .unwrap();

        let mut instance = Instance::create(
            InstanceId::new(1),
            adapter,
            testkit::package("memory,filesystem"),
            PLACEMENT,
            &log,
            1,
        )
        .unwrap();
        instance
            .start(&testkit::MINIMAL_WASM, &mut agents, &log, 2)
            .unwrap();

        assert_eq!(instance.state(), InstanceState::Running);
        assert!(instance.isolation().is_granted(CapabilityClass::Filesystem));
        assert_eq!(instance.isolation().claim, IsolationClaim::OsSandboxWasm);
        assert!(instance.adapter().enforces(CapabilityClass::Filesystem));
    }

    #[test]
    fn a_hosted_instance_never_reports_bare_metal_isolation() {
        let log = WitnessLog::<512>::new();
        for os in HostOs::ALL {
            for adapter in [
                HostedAdapter::new(os),
                HostedAdapter::new(os).fully_engaged(),
            ] {
                let instance = Instance::create(
                    InstanceId::new(1),
                    adapter,
                    testkit::package("memory"),
                    PLACEMENT,
                    &log,
                    1,
                )
                .unwrap();
                assert!(!instance.isolation().claim.is_bare_metal(), "{os}");

                let claimed: Vec<_> = instance
                    .witness(&log)
                    .iter()
                    .filter_map(rvm_host::claim_of)
                    .collect();
                assert!(!claimed.is_empty());
                assert!(!claimed.contains(&IsolationClaim::Partition));
            }
        }
    }

    #[test]
    fn the_three_contract_versions_agree() {
        assert_eq!(LAUNCH_CONTRACT_VERSION, 1);
        assert_eq!(rvm_host::HOST_CONTRACT_VERSION, 1);
        assert_eq!(rvm_rvf::RVF_CONTRACT_VERSION, 1);
    }
}
