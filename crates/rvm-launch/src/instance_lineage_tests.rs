//! Checkpoint lineage and witness-chain tests for [`super::Instance`].
//!
//! Split from `instance_tests.rs` only for file size; the shared fixtures live
//! there and are re-imported here.

use super::tests::{events, instance, started};
use super::*;
use crate::witness::{event_of, LaunchEvent};
use rvm_host::{HostOs, HostedAdapter, IsolationClaim, WasmAdapter};
use rvm_rvf::CapabilityClass;
use rvm_types::PartitionId;

const PLACEMENT: Placement = Placement::new(PartitionId::new(1), 0, 16);
type Log = WitnessLog<512>;
type Agents = AgentManager<8>;
const SUBSTITUTE_WASM: [u8; 11] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];

// ---------------------------------------------------------------------
// Checkpoint lineage
// ---------------------------------------------------------------------

#[test]
fn a_checkpoint_binds_to_the_base_rvf_identity() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);

    let checkpoint = inst.checkpoint(&log, 3).unwrap();
    assert_eq!(checkpoint.base_identity(), inst.package().identity());
    assert_eq!(checkpoint.origin(), inst.id());
    assert_eq!(checkpoint.captured_state(), InstanceState::Running);
}

#[test]
fn state_from_a_different_lineage_is_rejected_rather_than_replayed() {
    let log = Log::new();
    let mut agents = Agents::new();

    // Two different artifacts. The second declares a different class set, so
    // it hashes differently — a genuinely separate lineage.
    let mut donor = Instance::create(
        InstanceId::new(7),
        WasmAdapter::new(),
        rvm_host::testkit::package("memory,model"),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    donor
        .start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, &log, 2)
        .unwrap();
    let foreign = donor.checkpoint(&log, 3).unwrap();

    let mut target = instance(&log);
    assert_ne!(foreign.base_identity(), target.package().identity());

    let before = log.total_emitted();
    assert_eq!(
        target.restore(
            &foreign,
            &rvm_host::testkit::MINIMAL_WASM,
            &mut agents,
            &log,
            4
        ),
        Err(LaunchError::LineageMismatch)
    );

    // Refused, witnessed, and no execution began with partial foreign state.
    assert_eq!(target.state(), InstanceState::Created);
    assert_eq!(target.agent(), None);
    let record = log.get(usize::try_from(before).unwrap() % 512).unwrap();
    assert_eq!(event_of(&record), Some(LaunchEvent::CheckpointRejected));
    assert_eq!(
        u32::from_le_bytes(record.aux[4..8].try_into().unwrap()),
        foreign.lineage_tag()
    );
}

#[test]
fn the_lineage_check_runs_before_the_state_machine() {
    // A foreign checkpoint offered to a terminated instance is a lineage
    // rejection, not an illegal transition: the identity mismatch is the more
    // serious finding and must not be masked by the state check.
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);
    inst.terminate(&mut agents, &log, 3).unwrap();

    let foreign = Checkpoint::new(
        [0xAAu8; 32],
        InstanceId::new(99),
        0,
        InstanceState::Suspended,
        16,
        0,
    );
    assert_eq!(
        inst.restore(
            &foreign,
            &rvm_host::testkit::MINIMAL_WASM,
            &mut agents,
            &log,
            4
        ),
        Err(LaunchError::LineageMismatch)
    );
}

#[test]
fn a_suspended_instance_restores_from_its_own_checkpoint() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);

    let checkpoint = inst.checkpoint(&log, 3).unwrap();
    inst.suspend(&mut agents, &log, 4).unwrap();

    inst.restore(
        &checkpoint,
        &rvm_host::testkit::MINIMAL_WASM,
        &mut agents,
        &log,
        5,
    )
    .unwrap();
    assert_eq!(inst.state(), InstanceState::Running);
    assert!(events(&inst, &log).contains(&LaunchEvent::CheckpointRestored));
}

#[test]
fn a_checkpoint_resumes_into_a_new_instance_of_the_same_lineage() {
    // ADR-289 criterion 7: suspend under one adapter, checkpoint, resume under
    // another. The far-side instance is new by construction, so the origin
    // instance identifier must not gate the restore — only the base identity.
    let log = Log::new();
    let mut agents = Agents::new();

    let mut first = started(&log, &mut agents);
    first.suspend(&mut agents, &log, 3).unwrap();
    let checkpoint = first.checkpoint(&log, 4).unwrap();
    first.terminate(&mut agents, &log, 5).unwrap();

    let mut second = Instance::create(
        InstanceId::new(2),
        HostedAdapter::new(HostOs::Linux).fully_engaged(),
        rvm_host::testkit::package("memory,clock"),
        PLACEMENT,
        &log,
        6,
    )
    .unwrap();
    assert_ne!(second.id(), checkpoint.origin());
    assert!(checkpoint.belongs_to(second.package().identity()));

    second
        .restore(
            &checkpoint,
            &rvm_host::testkit::MINIMAL_WASM,
            &mut agents,
            &log,
            7,
        )
        .unwrap();
    assert_eq!(second.state(), InstanceState::Running);
    assert!(second.agent().is_some());
    // The two runs obtained different, honestly reported boundaries.
    assert_eq!(second.isolation().claim, IsolationClaim::OsSandboxWasm);
}

#[test]
fn a_created_restore_refuses_module_bytes_not_bound_to_the_package() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = instance(&log);
    let checkpoint = Checkpoint::new(
        *inst.package().identity(),
        InstanceId::new(99),
        0,
        InstanceState::Suspended,
        16,
        0,
    );

    assert_eq!(
        inst.restore(&checkpoint, &SUBSTITUTE_WASM, &mut agents, &log, 2),
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

#[test]
fn checkpoint_sequence_numbers_advance() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);

    let first = inst.checkpoint(&log, 3).unwrap();
    let second = inst.checkpoint(&log, 4).unwrap();
    assert_eq!(first.sequence(), 0);
    assert_eq!(second.sequence(), 1);
    assert_eq!(inst.checkpoint_count(), 2);
    assert!(second.witness_sequence() > first.witness_sequence());
}

// ---------------------------------------------------------------------
// The witness chain
// ---------------------------------------------------------------------

#[test]
fn the_instance_chain_verifies_and_covers_every_capability_decision() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);
    inst.terminate(&mut agents, &log, 3).unwrap();

    let chain = inst.witness(&log);
    // A dedicated log makes the instance's spans the whole log, so the
    // exported chain is complete and hash-linked end to end.
    assert_eq!(chain.len() as u64, log.total_emitted());
    assert!(rvm_witness::verify_chain(&chain).is_ok());
    assert!(chain
        .iter()
        .all(|r| inst.binds_to_package(r)
            || rvm_host::event_of(r).is_none() && event_of(r).is_none()));

    // Every one of the fifteen classes was decided exactly once at the host
    // boundary, and both grants and denials are present.
    let decisions: Vec<_> = chain
        .iter()
        .filter_map(rvm_host::event_of)
        .filter(|e| {
            matches!(
                e,
                rvm_host::HostEvent::CapabilityGranted | rvm_host::HostEvent::CapabilityDenied
            )
        })
        .collect();
    assert_eq!(decisions.len(), CapabilityClass::ALL.len());
    assert!(decisions.contains(&rvm_host::HostEvent::CapabilityGranted));
    assert!(decisions.contains(&rvm_host::HostEvent::CapabilityDenied));
}

#[test]
fn the_chain_is_returned_in_sequence_order() {
    let log = Log::new();
    let mut agents = Agents::new();
    let mut inst = started(&log, &mut agents);
    inst.suspend(&mut agents, &log, 3).unwrap();
    inst.resume(&mut agents, &log, 4).unwrap();

    let chain = inst.witness(&log);
    assert!(chain.windows(2).all(|w| w[0].sequence < w[1].sequence));
    assert!(!chain.is_empty());
}

#[test]
fn instances_of_different_artifacts_sharing_a_log_get_disjoint_chains() {
    let log = Log::new();
    let mut agents = Agents::new();

    let mut a = instance(&log);
    let mut b = Instance::create(
        InstanceId::new(2),
        WasmAdapter::new(),
        rvm_host::testkit::package("memory,model"),
        PLACEMENT,
        &log,
        2,
    )
    .unwrap();

    a.start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, &log, 3)
        .unwrap();
    b.start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, &log, 4)
        .unwrap();

    let a_chain = a.witness(&log);
    let b_chain = b.witness(&log);
    assert!(!a_chain.is_empty());
    assert!(!b_chain.is_empty());
    for record in &a_chain {
        assert!(
            !b_chain.iter().any(|r| r.sequence == record.sequence),
            "chains overlapped at sequence {}",
            record.sequence
        );
    }
}

#[test]
fn a_refused_creation_contributes_no_grant_to_the_chain() {
    let log = Log::new();
    let refused = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        rvm_host::testkit::package("gpu"),
        PLACEMENT,
        &log,
        1,
    );
    assert!(refused.is_err());

    let granted = (0..log.len())
        .filter_map(|i| log.get(i))
        .filter(|r| rvm_host::event_of(r) == Some(rvm_host::HostEvent::CapabilityGranted))
        .count();
    assert_eq!(granted, 0);
}
