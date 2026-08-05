//! Lifecycle tests: the happy path, every illegal transition, checkpoint
//! lineage, and what the witness chain shows for each.

use super::*;
use crate::witness::{event_of, LaunchEvent};
use rvm_host::{HostError, HostOs, HostedAdapter, IsolationClaim, WasmAdapter};
use rvm_rvf::CapabilityClass;
use rvm_types::PartitionId;

const PLACEMENT: Placement = Placement::new(PartitionId::new(1), 0, 16);
const SUBSTITUTE_WASM: [u8; 11] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];
type Log = WitnessLog<512>;
type Agents = AgentManager<8>;

pub(super) fn instance(log: &Log) -> Instance<WasmAdapter> {
    Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        rvm_host::testkit::package("memory,clock"),
        PLACEMENT,
        log,
        1,
    )
    .expect("the wasm adapter enforces both declared classes")
}

pub(super) fn started(log: &Log, agents: &mut Agents) -> Instance<WasmAdapter> {
    let mut inst = instance(log);
    inst.start(&rvm_host::testkit::MINIMAL_WASM, agents, log, 2)
        .unwrap();
    inst
}

pub(super) fn events(inst: &Instance<WasmAdapter>, log: &Log) -> Vec<LaunchEvent> {
    inst.witness(log).iter().filter_map(event_of).collect()
}

// ---------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------

#[test]
fn creation_prepares_isolation_and_runs_nothing() {
    let log = Log::new();
    let inst = instance(&log);

    assert_eq!(inst.state(), InstanceState::Created);
    assert_eq!(inst.agent(), None);
    assert_eq!(inst.checkpoint_count(), 0);
    assert_eq!(inst.isolation().claim, IsolationClaim::WasmOnly);
    assert!(inst.isolation().is_granted(CapabilityClass::Clock));
    assert_eq!(
        events(&inst, &log).last(),
        Some(&LaunchEvent::InstanceCreated)
    );
}

#[test]
fn creation_is_refused_when_the_adapter_cannot_enforce_a_declared_class() {
    let log = Log::new();
    let result = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        rvm_host::testkit::package("memory,network"),
        PLACEMENT,
        &log,
        1,
    );

    assert!(matches!(
        result,
        Err(LaunchError::Host(HostError::CapabilityUnenforceable(
            CapabilityClass::Network
        )))
    ));
    // The refusal is in the chain and no instance was created.
    assert_eq!(log.total_emitted(), 1);
    assert!(result.is_err());
}

#[test]
fn the_same_package_creates_under_a_hosted_adapter_with_a_different_claim() {
    let log = Log::new();
    let inst = Instance::create(
        InstanceId::new(2),
        HostedAdapter::new(HostOs::Linux).fully_engaged(),
        rvm_host::testkit::package("memory,clock"),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();

    assert_eq!(inst.isolation().claim, IsolationClaim::OsSandboxWasm);
    assert!(!inst.isolation().claim.is_bare_metal());
}

// ---------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------

#[test]
fn the_full_lifecycle_runs_end_to_end() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = instance(&log);

    inst.start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, &log, 2)
        .unwrap();
    assert_eq!(inst.state(), InstanceState::Running);
    assert!(inst.agent().is_some());
    assert_eq!(agents.count(), 1);

    inst.suspend(&mut agents, &log, 3).unwrap();
    assert_eq!(inst.state(), InstanceState::Suspended);

    let checkpoint = inst.checkpoint(&log, 4).unwrap();
    assert_eq!(
        inst.state(),
        InstanceState::Suspended,
        "a checkpoint observes"
    );
    assert_eq!(inst.checkpoint_count(), 1);

    inst.resume(&mut agents, &log, 5).unwrap();
    assert_eq!(inst.state(), InstanceState::Running);

    inst.terminate(&mut agents, &log, 6).unwrap();
    assert_eq!(inst.state(), InstanceState::Terminated);
    assert_eq!(agents.count(), 0);

    assert_eq!(
        events(&inst, &log),
        [
            LaunchEvent::InstanceCreated,
            LaunchEvent::InstanceStarted,
            LaunchEvent::InstanceSuspended,
            LaunchEvent::CheckpointTaken,
            LaunchEvent::InstanceResumed,
            LaunchEvent::InstanceTerminated,
        ]
    );
    assert!(checkpoint.belongs_to(inst.package().identity()));
}

#[test]
fn a_module_that_fails_admission_leaves_the_instance_created() {
    let log = Log::new();
    let mut agents = Agents::new();
    let malformed = b"not wasm";
    let data = rvm_host::testkit::container_with_module("memory,clock", malformed);
    let report = rvm_rvf::verify(&data, &rvm_host::testkit::lenient_options()).unwrap();
    let package = VerifiedPackage::from_report(&report).unwrap();
    let mut inst = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        package,
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();

    assert!(matches!(
        inst.start(malformed, &mut agents, &log, 2),
        Err(LaunchError::Host(HostError::ModuleRejected(_)))
    ));
    assert_eq!(inst.state(), InstanceState::Created);
    assert_eq!(inst.agent(), None);
    assert_eq!(agents.count(), 0);

    // Verification established byte identity, not WASM validity; runtime
    // admission remains a distinct gate and the refusal is non-mutating.
    assert_eq!(inst.state(), InstanceState::Created);
}

#[test]
fn a_valid_but_unverified_module_is_refused_before_admission() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = instance(&log);

    assert_eq!(
        inst.start(&SUBSTITUTE_WASM, &mut agents, &log, 2),
        Err(LaunchError::ExecutableMismatch)
    );
    assert_eq!(inst.state(), InstanceState::Created);
    assert_eq!(inst.agent(), None);
    assert_eq!(agents.count(), 0);
    assert_eq!(
        events(&inst, &log).last(),
        Some(&LaunchEvent::ExecutableRejected)
    );
}

// ---------------------------------------------------------------------
// Illegal transitions
// ---------------------------------------------------------------------

#[test]
fn a_running_instance_cannot_be_started_again() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);

    assert_eq!(
        inst.start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, &log, 3),
        Err(LaunchError::IllegalTransition {
            from: InstanceState::Running,
            op: LifecycleOp::Start,
        })
    );
    assert_eq!(agents.count(), 1, "no second agent was spawned");
}

#[test]
fn an_instance_that_was_never_suspended_cannot_resume() {
    let log = Log::new();
    let mut agents = Agents::new();

    let mut fresh = instance(&log);
    assert_eq!(
        fresh.resume(&mut agents, &log, 2),
        Err(LaunchError::IllegalTransition {
            from: InstanceState::Created,
            op: LifecycleOp::Resume,
        })
    );

    let mut running = started(&log, &mut agents);
    assert_eq!(
        running.resume(&mut agents, &log, 3),
        Err(LaunchError::IllegalTransition {
            from: InstanceState::Running,
            op: LifecycleOp::Resume,
        })
    );
}

#[test]
fn an_instance_that_is_not_running_cannot_be_suspended() {
    let log = Log::new();
    let mut agents = Agents::new();

    let mut fresh = instance(&log);
    assert_eq!(
        fresh.suspend(&mut agents, &log, 2),
        Err(LaunchError::IllegalTransition {
            from: InstanceState::Created,
            op: LifecycleOp::Suspend,
        })
    );

    let mut inst = started(&log, &mut agents);
    inst.suspend(&mut agents, &log, 3).unwrap();
    assert_eq!(
        inst.suspend(&mut agents, &log, 4),
        Err(LaunchError::IllegalTransition {
            from: InstanceState::Suspended,
            op: LifecycleOp::Suspend,
        })
    );
}

#[test]
fn a_created_instance_has_nothing_to_checkpoint() {
    let log = Log::new();
    let mut inst = instance(&log);
    assert_eq!(
        inst.checkpoint(&log, 2),
        Err(LaunchError::IllegalTransition {
            from: InstanceState::Created,
            op: LifecycleOp::Checkpoint,
        })
    );
    assert_eq!(inst.checkpoint_count(), 0);
}

#[test]
fn a_terminated_instance_refuses_every_operation() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);
    inst.terminate(&mut agents, &log, 3).unwrap();

    let expect = |op| LaunchError::IllegalTransition {
        from: InstanceState::Terminated,
        op,
    };
    assert_eq!(
        inst.start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, &log, 4),
        Err(expect(LifecycleOp::Start))
    );
    assert_eq!(
        inst.suspend(&mut agents, &log, 5),
        Err(expect(LifecycleOp::Suspend))
    );
    assert_eq!(
        inst.resume(&mut agents, &log, 6),
        Err(expect(LifecycleOp::Resume))
    );
    assert_eq!(
        inst.checkpoint(&log, 7),
        Err(expect(LifecycleOp::Checkpoint))
    );
    assert_eq!(
        inst.terminate(&mut agents, &log, 8),
        Err(expect(LifecycleOp::Terminate))
    );
    assert_eq!(inst.state(), InstanceState::Terminated);
}

#[test]
fn every_illegal_transition_is_witnessed_before_it_is_returned() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = instance(&log);

    let before = log.total_emitted();
    assert!(inst.resume(&mut agents, &log, 2).is_err());
    assert_eq!(log.total_emitted(), before + 1);

    let record = log.get(usize::try_from(before).unwrap() % 512).unwrap();
    assert_eq!(event_of(&record), Some(LaunchEvent::IllegalTransition));
    assert_eq!(record.aux[1], InstanceState::Created as u8);
    assert_eq!(
        u32::from_le_bytes(record.aux[4..8].try_into().unwrap()),
        u32::from(LifecycleOp::Resume as u8)
    );
}
