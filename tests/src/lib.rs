//! # RVM Integration Tests
//!
//! Cross-crate integration tests for the RVM microhypervisor.

#[cfg(test)]
mod tests {
    use rvm_types::{
        CapRights, CapToken, CapType, CoherenceScore, GuestPhysAddr,
        PartitionId, PhysAddr, WitnessHash, WitnessRecord, ActionKind,
    };

    #[test]
    fn partition_id_round_trip() {
        let id = PartitionId::new(42);
        assert_eq!(id.as_u32(), 42);
    }

    #[test]
    fn partition_id_vmid() {
        let id = PartitionId::new(0x1FF);
        assert_eq!(id.vmid(), 0xFF);
    }

    #[test]
    fn coherence_score_clamping() {
        let score = CoherenceScore::from_basis_points(15_000);
        assert_eq!(score.as_basis_points(), 10_000);
    }

    #[test]
    fn coherence_threshold() {
        let high = CoherenceScore::from_basis_points(5000);
        let low = CoherenceScore::from_basis_points(1000);
        assert!(high.is_coherent());
        assert!(!low.is_coherent());
    }

    #[test]
    fn witness_hash_zero() {
        assert!(WitnessHash::ZERO.is_zero());
        let non_zero = WitnessHash::from_bytes([1u8; 32]);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn witness_record_size() {
        assert_eq!(core::mem::size_of::<WitnessRecord>(), 64);
    }

    #[test]
    fn capability_rights_check() {
        let token = CapToken::new(
            1,
            CapType::Partition,
            CapRights::READ,
            0,
        );
        assert!(token.has_rights(CapRights::READ));
        assert!(!token.has_rights(CapRights::WRITE));
    }

    #[test]
    fn capability_combined_rights() {
        let token = CapToken::new(
            1,
            CapType::Partition,
            CapRights::READ | CapRights::WRITE | CapRights::GRANT,
            0,
        );
        assert!(token.has_rights(CapRights::READ | CapRights::WRITE));
        assert!(!token.has_rights(CapRights::EXECUTE));
    }

    #[test]
    fn memory_region_alignment() {
        let aligned = GuestPhysAddr::new(0x1000);
        let unaligned = GuestPhysAddr::new(0x1001);
        assert!(aligned.is_page_aligned());
        assert!(!unaligned.is_page_aligned());
    }

    #[test]
    fn phys_addr_page_align_down() {
        let addr = PhysAddr::new(0x1234);
        assert_eq!(addr.page_align_down().as_u64(), 0x1000);
    }

    #[test]
    fn boot_phase_sequence() {
        let mut tracker = rvm_boot::BootTracker::new();
        assert!(!tracker.is_complete());

        tracker.complete_phase(rvm_boot::BootPhase::HalInit).unwrap();
        tracker.complete_phase(rvm_boot::BootPhase::MemoryInit).unwrap();
        tracker.complete_phase(rvm_boot::BootPhase::CapabilityInit).unwrap();
        tracker.complete_phase(rvm_boot::BootPhase::WitnessInit).unwrap();
        tracker.complete_phase(rvm_boot::BootPhase::SchedulerInit).unwrap();
        tracker.complete_phase(rvm_boot::BootPhase::RootPartition).unwrap();
        tracker.complete_phase(rvm_boot::BootPhase::Handoff).unwrap();

        assert!(tracker.is_complete());
    }

    #[test]
    fn boot_phase_out_of_order() {
        let mut tracker = rvm_boot::BootTracker::new();
        assert!(tracker.complete_phase(rvm_boot::BootPhase::MemoryInit).is_err());
    }

    #[test]
    fn wasm_header_validation() {
        let valid = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert!(rvm_wasm::validate_header(&valid).is_ok());

        let bad_magic = [0xFF; 8];
        assert!(rvm_wasm::validate_header(&bad_magic).is_err());

        let short = [0x00, 0x61];
        assert!(rvm_wasm::validate_header(&short).is_err());
    }

    #[test]
    fn security_gate_enforcement() {
        let token = CapToken::new(
            1,
            CapType::Partition,
            CapRights::READ | CapRights::WRITE,
            0,
        );

        let request = rvm_security::GateRequest {
            token: &token,
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: None,
        };
        assert!(rvm_security::enforce(&request).is_ok());

        // Wrong type should fail.
        let bad_request = rvm_security::GateRequest {
            token: &token,
            required_type: CapType::Region,
            required_rights: CapRights::READ,
            proof_commitment: None,
        };
        assert!(rvm_security::enforce(&bad_request).is_err());
    }

    #[test]
    fn witness_log_append() {
        let mut log = rvm_witness::WitnessLog::<16>::new();
        assert!(log.is_empty());

        let record = WitnessRecord::zeroed();
        log.append(record);
        assert_eq!(log.len(), 1);

        log.append(record);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn witness_emitter_builds_records() {
        let log = rvm_witness::WitnessLog::<16>::new();
        let emitter = rvm_witness::WitnessEmitter::new(&log);
        let seq = emitter.emit_partition_create(
            1,         // actor_partition_id
            100,       // new_partition_id
            0xABCD,    // cap_hash
            1_000_000, // timestamp_ns
        );
        assert_eq!(seq, 0);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn coherence_ema_filter() {
        let mut filter = rvm_coherence::EmaFilter::new(5000); // 50% alpha
        let score = filter.update(8000);
        assert_eq!(score.as_basis_points(), 8000);

        let score2 = filter.update(4000);
        assert_eq!(score2.as_basis_points(), 6000);
    }

    #[test]
    fn partition_manager_basic() {
        let mut mgr = rvm_partition::PartitionManager::new();
        assert_eq!(mgr.count(), 0);

        let id = mgr.create(
            rvm_partition::PartitionType::Agent,
            2,
            1,
        ).unwrap();
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get(id).is_some());
    }

    #[test]
    fn kernel_version() {
        assert!(!rvm_kernel::VERSION.is_empty());
        assert_eq!(rvm_kernel::CRATE_COUNT, 13);
    }

    #[test]
    fn action_kind_subsystem() {
        assert_eq!(ActionKind::PartitionCreate.subsystem(), 0);
        assert_eq!(ActionKind::CapabilityGrant.subsystem(), 1);
        assert_eq!(ActionKind::RegionCreate.subsystem(), 2);
    }

    #[test]
    fn fnv1a_hash() {
        let hash = rvm_witness::fnv1a_64(b"hello");
        assert_ne!(hash, 0);
        // Deterministic.
        assert_eq!(hash, rvm_witness::fnv1a_64(b"hello"));
    }
}
