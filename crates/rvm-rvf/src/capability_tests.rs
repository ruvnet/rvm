//! Tests for [`crate::capability`], split out so neither file grows past
//! the workspace's 500-line ceiling.

use super::*;
use crate::container::walk;
use crate::testkit;

fn map(names: &str) -> RvfResult<CapabilityMapping> {
    let data = testkit::minimal_container(names);
    let segs = walk(&data).unwrap();
    map_declared(&declared_classes(&data, &segs))
}

#[test]
fn wire_names_round_trip_for_every_class() {
    for class in CapabilityClass::ALL {
        assert_eq!(CapabilityClass::from_wire(class.as_str()), Some(class));
    }
    assert_eq!(CapabilityClass::from_wire("teleportation"), None);
    assert_eq!(
        CapabilityClass::PersistentState.as_str(),
        "persistent-state"
    );
}

#[test]
fn an_absent_declaration_denies_all_fifteen_classes() {
    let mapping = map_declared(&[]).unwrap();
    assert!(mapping.granted().is_empty());
    assert_eq!(mapping.denied().len(), 15);
    for class in CapabilityClass::ALL {
        assert!(!mapping.is_granted(class), "{class} should be denied");
        assert_eq!(mapping.rights_for(class), CapRights::empty());
    }
}

#[test]
fn declared_classes_are_read_from_meta() {
    let mapping = map("network, filesystem,clock").unwrap();
    assert!(mapping.is_granted(CapabilityClass::Network));
    assert!(mapping.is_granted(CapabilityClass::Filesystem));
    assert!(mapping.is_granted(CapabilityClass::Clock));
    assert!(!mapping.is_granted(CapabilityClass::Gpu));
    assert_eq!(mapping.denied().len(), 12);
}

#[test]
fn unknown_class_names_are_skipped_not_granted() {
    let mapping = map("network,teleportation").unwrap();
    assert!(mapping.is_granted(CapabilityClass::Network));
    assert_eq!(mapping.granted().len(), 1);
}

#[test]
fn encrypted_metadata_contributes_no_declaration() {
    let mut data = testkit::minimal_container("network");
    // Set ENCRYPTED on the META segment's flags at header offset 0x06.
    data[0x06..0x08].copy_from_slice(&crate::format::FLAG_ENCRYPTED.to_le_bytes());
    // The content hash still covers the payload, so the walk succeeds.
    let segs = walk(&data).unwrap();
    assert!(declared_classes(&data, &segs).is_empty());
}

#[test]
fn an_unrepresentable_class_is_refused_rather_than_dropped() {
    assert_eq!(
        map("network,clipboard"),
        Err(RvfError::UnsupportedCapability(CapabilityClass::Clipboard))
    );
    assert_eq!(
        map("randomness"),
        Err(RvfError::UnsupportedCapability(CapabilityClass::Randomness))
    );
}

#[test]
fn thirteen_of_fifteen_classes_are_representable() {
    let unrepresentable: Vec<_> = CapabilityClass::ALL
        .into_iter()
        .filter(|c| !c.is_representable())
        .collect();
    assert_eq!(
        unrepresentable,
        [CapabilityClass::Randomness, CapabilityClass::Clipboard]
            .into_iter()
            .collect::<Vec<_>>()
    );
}

#[test]
fn model_maps_read_only_because_the_base_rvf_is_immutable() {
    let binding = CapabilityClass::Model.rvm_binding().unwrap();
    assert_eq!(binding.cap_type, CapType::Region);
    assert_eq!(binding.rights, CapRights::READ);
    assert!(!binding.rights.contains(CapRights::WRITE));
}

#[test]
fn no_binding_ever_grants_the_delegation_rights() {
    // A capability derived from a declaration must not be re-grantable on
    // the strength of the declaration alone.
    for class in CapabilityClass::ALL {
        let Some(binding) = class.rvm_binding() else {
            continue;
        };
        assert!(!binding.rights.contains(CapRights::GRANT), "{class}");
        assert!(!binding.rights.contains(CapRights::GRANT_ONCE), "{class}");
        assert!(!binding.rights.contains(CapRights::REVOKE), "{class}");
    }
}

#[test]
fn granted_bindings_install_into_a_capability_table() {
    let mapping = map("network,filesystem,clock").unwrap();
    let mut table = CapabilityTable::<16>::new();
    let owner = PartitionId::new(1);

    let n = mapping.install(&mut table, owner, 0, 100).unwrap();
    assert_eq!(n, 3);
    assert_eq!(table.len(), 3);

    let badges: Vec<u64> = table.iter().map(|(_, slot)| slot.badge).collect();
    assert!(badges.contains(&(CapabilityClass::Network as u64)));
    assert!(badges.contains(&(CapabilityClass::Filesystem as u64)));
}

#[test]
fn installing_into_a_full_table_reports_the_table_full() {
    let mapping = map("network,filesystem,clock").unwrap();
    let mut table = CapabilityTable::<2>::new();
    assert_eq!(
        mapping.install(&mut table, PartitionId::new(1), 0, 1),
        Err(RvfError::CapabilityTableFull)
    );
}

#[test]
fn a_denied_class_installs_nothing() {
    let mapping = map_declared(&[]).unwrap();
    let mut table = CapabilityTable::<16>::new();
    assert_eq!(
        mapping
            .install(&mut table, PartitionId::new(1), 0, 1)
            .unwrap(),
        0
    );
    assert!(table.is_empty());
}
