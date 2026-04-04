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

        let request = rvm_security::PolicyRequest {
            token: &token,
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: None,
        };
        assert!(rvm_security::enforce(&request).is_ok());

        // Wrong type should fail.
        let bad_request = rvm_security::PolicyRequest {
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

    // ===============================================================
    // Cross-crate integration scenarios
    // ===============================================================

    // ---------------------------------------------------------------
    // Scenario 1: Create partition -> grant capability -> verify P1
    //             -> emit witness -> check chain
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_partition_cap_proof_witness_chain() {
        use rvm_cap::{CapabilityManager, CapManagerConfig};
        use rvm_types::{CapType, CapRights, ProofTier, ProofToken};
        use rvm_proof::context::ProofContextBuilder;
        use rvm_proof::engine::ProofEngine;

        // Step 1: Create a partition via the partition manager.
        let mut part_mgr = rvm_partition::PartitionManager::new();
        let pid = part_mgr
            .create(rvm_partition::PartitionType::Agent, 2, 0)
            .unwrap();

        // Step 2: Grant a capability to this partition via the cap manager.
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let all_rights = CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
            .union(CapRights::GRANT)
            .union(CapRights::REVOKE)
            .union(CapRights::PROVE);

        let (root_idx, root_gen) = cap_mgr
            .create_root_capability(CapType::Partition, all_rights, 0, pid)
            .unwrap();

        // Step 3: Verify P1 on the capability.
        assert!(cap_mgr.verify_p1(root_idx, root_gen, CapRights::PROVE).is_ok());

        // Step 4: Run the full proof engine pipeline (P1 + P2 + witness).
        let witness_log = rvm_witness::WitnessLog::<32>::new();
        let token = ProofToken {
            tier: ProofTier::P2,
            epoch: 0,
            hash: 0x1234,
        };
        let context = ProofContextBuilder::new(pid)
            .target_object(42)
            .capability_handle(root_idx)
            .capability_generation(root_gen)
            .current_epoch(0)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(1)
            .build();

        let mut engine = ProofEngine::<64>::new();
        engine
            .verify_and_witness(&token, &context, &cap_mgr, &witness_log)
            .unwrap();

        // Step 5: Verify witness chain integrity.
        assert_eq!(witness_log.total_emitted(), 1);
        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofVerifiedP2 as u8);
        assert_eq!(record.actor_partition_id, pid.as_u32());
        assert_eq!(record.target_object_id, 42);
        assert_eq!(record.capability_hash, 0x1234);
    }

    // ---------------------------------------------------------------
    // Scenario 2: Security gate end-to-end with valid/invalid caps
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_security_gate_valid_request() {
        use rvm_security::{SecurityGate, GateRequest};
        use rvm_types::WitnessHash;

        let log = rvm_witness::WitnessLog::<32>::new();
        let gate = SecurityGate::new(&log);

        // Valid request: correct type, sufficient rights, valid proof.
        let token = CapToken::new(
            1,
            CapType::Region,
            CapRights::READ | CapRights::WRITE,
            0,
        );
        let commitment = WitnessHash::from_bytes([0xAB; 32]);
        let request = GateRequest {
            token,
            required_type: CapType::Region,
            required_rights: CapRights::WRITE,
            proof_commitment: Some(commitment),
            action: ActionKind::RegionCreate,
            target_object_id: 100,
            timestamp_ns: 5000,
        };

        let response = gate.check_and_execute(&request).unwrap();
        assert_eq!(response.proof_tier, 2); // P2 because proof commitment provided.
        assert_eq!(response.witness_sequence, 0);
        assert_eq!(log.total_emitted(), 1);

        // Check the witness record.
        let record = log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::RegionCreate as u8);
    }

    #[test]
    fn cross_crate_security_gate_wrong_type() {
        use rvm_security::{SecurityGate, SecurityError, GateRequest};

        let log = rvm_witness::WitnessLog::<32>::new();
        let gate = SecurityGate::new(&log);

        let token = CapToken::new(1, CapType::Region, CapRights::READ, 0);
        let request = GateRequest {
            token,
            required_type: CapType::Partition, // Wrong type.
            required_rights: CapRights::READ,
            proof_commitment: None,
            action: ActionKind::PartitionCreate,
            target_object_id: 1,
            timestamp_ns: 1000,
        };

        let err = gate.check_and_execute(&request).unwrap_err();
        assert_eq!(err, SecurityError::CapabilityTypeMismatch);

        // Rejection witness emitted.
        let record = log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofRejected as u8);
    }

    #[test]
    fn cross_crate_security_gate_insufficient_rights() {
        use rvm_security::{SecurityGate, SecurityError, GateRequest};

        let log = rvm_witness::WitnessLog::<32>::new();
        let gate = SecurityGate::new(&log);

        let token = CapToken::new(
            1,
            CapType::Partition,
            CapRights::READ, // Only READ, but WRITE required.
            0,
        );
        let request = GateRequest {
            token,
            required_type: CapType::Partition,
            required_rights: CapRights::WRITE,
            proof_commitment: None,
            action: ActionKind::PartitionCreate,
            target_object_id: 1,
            timestamp_ns: 1000,
        };

        let err = gate.check_and_execute(&request).unwrap_err();
        assert_eq!(err, SecurityError::InsufficientRights);
    }

    #[test]
    fn cross_crate_security_gate_zero_proof_commitment() {
        use rvm_security::{SecurityGate, SecurityError, GateRequest};
        use rvm_types::WitnessHash;

        let log = rvm_witness::WitnessLog::<32>::new();
        let gate = SecurityGate::new(&log);

        let token = CapToken::new(
            1,
            CapType::Partition,
            CapRights::READ | CapRights::WRITE,
            0,
        );
        let request = GateRequest {
            token,
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: Some(WitnessHash::ZERO), // Zero = invalid.
            action: ActionKind::PartitionCreate,
            target_object_id: 1,
            timestamp_ns: 1000,
        };

        let err = gate.check_and_execute(&request).unwrap_err();
        assert_eq!(err, SecurityError::PolicyViolation);
    }

    // ---------------------------------------------------------------
    // Scenario 3: Coherence scoring -> scheduler priority computation
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_coherence_score_to_scheduler_priority() {
        use rvm_types::CutPressure;

        // Simulate: partition has coherence 8000bp, gets a cut pressure signal.
        let coherence = CoherenceScore::from_basis_points(8000);
        assert!(coherence.is_coherent());

        // Convert coherence into a cut pressure value (higher coherence = lower pressure).
        // Pressure is typically derived from the graph, but we simulate:
        let pressure = CutPressure::from_fixed(0x0003_0000); // boost = 3
        let deadline_urgency: u16 = 100;

        let priority = rvm_sched::compute_priority(deadline_urgency, pressure);
        assert_eq!(priority, 103); // 100 + 3

        // Now test with zero pressure (degraded mode / DC-1).
        let priority_degraded = rvm_sched::compute_priority(deadline_urgency, CutPressure::ZERO);
        assert_eq!(priority_degraded, 100); // deadline only
    }

    #[test]
    fn cross_crate_coherence_driven_partition_split_decision() {
        use rvm_types::CutPressure;

        // Partition with high cut pressure should trigger split.
        let pressure = CutPressure::from_fixed(9000);
        assert!(pressure.exceeds_threshold(CutPressure::DEFAULT_SPLIT_THRESHOLD));

        // Low pressure should not trigger split.
        let low_pressure = CutPressure::from_fixed(5000);
        assert!(!low_pressure.exceeds_threshold(CutPressure::DEFAULT_SPLIT_THRESHOLD));
    }

    // ---------------------------------------------------------------
    // Scenario 4: Full kernel lifecycle: boot, create, tick, witness check
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_kernel_full_lifecycle() {
        use rvm_kernel::{Kernel, KernelConfig};
        use rvm_types::PartitionConfig;

        let mut kernel = Kernel::new(KernelConfig::default());
        kernel.boot().unwrap();
        assert!(kernel.is_booted());

        let config = PartitionConfig::default();
        let id1 = kernel.create_partition(&config).unwrap();
        let id2 = kernel.create_partition(&config).unwrap();
        assert_eq!(kernel.partition_count(), 2);
        assert_ne!(id1, id2);

        // Tick a few times.
        for _ in 0..3 {
            kernel.tick().unwrap();
        }
        assert_eq!(kernel.current_epoch(), 3);

        // Destroy one partition.
        kernel.destroy_partition(id1).unwrap();

        // Total witnesses: 7 boot + 2 create + 3 tick + 1 destroy = 13.
        assert_eq!(kernel.witness_count(), 13);
    }

    // ---------------------------------------------------------------
    // Scenario 5: Memory region management + tier placement
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_memory_region_and_tier() {
        use rvm_memory::{RegionManager, RegionConfig, TierManager, Tier, BuddyAllocator, MemoryPermissions};
        use rvm_types::{OwnedRegionId, PhysAddr};

        // Set up a buddy allocator.
        let mut alloc = BuddyAllocator::<16, 2>::new(PhysAddr::new(0x1000_0000)).unwrap();
        let addr = alloc.alloc_pages(0).unwrap();
        assert!(addr.is_page_aligned());

        // Set up a region manager and create a region.
        let mut region_mgr = RegionManager::<16>::new();
        let rid = region_mgr
            .create(RegionConfig {
                id: OwnedRegionId::new(1),
                owner: PartitionId::new(1),
                guest_base: GuestPhysAddr::new(0x0),
                host_base: PhysAddr::new(addr.as_u64()),
                page_count: 1,
                tier: Tier::Warm,
                permissions: MemoryPermissions::READ_WRITE,
            })
            .unwrap();

        // Register in the tier manager.
        let mut tier_mgr = TierManager::<8>::new();
        tier_mgr.register(rid, Tier::Warm).unwrap();

        let state = tier_mgr.get(rid).unwrap();
        assert_eq!(state.tier, Tier::Warm);
    }

    // ---------------------------------------------------------------
    // Scenario 6: Witness log integrity verification
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_witness_log_chain_integrity() {
        let log = rvm_witness::WitnessLog::<32>::new();

        // Emit several records.
        for i in 0..5u8 {
            let mut record = WitnessRecord::zeroed();
            record.action_kind = i;
            record.proof_tier = 1;
            record.actor_partition_id = 1;
            log.append(record);
        }

        assert_eq!(log.total_emitted(), 5);

        // Collect records and verify chain.
        let mut records = [WitnessRecord::zeroed(); 5];
        for i in 0..5 {
            records[i] = log.get(i).unwrap();
        }

        let result = rvm_witness::verify_chain(&records);
        assert!(result.is_ok());
    }

    // ---------------------------------------------------------------
    // Scenario 7: EMA filter feeds coherence score
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_ema_coherence_scoring() {
        // Use EMA filter to smooth coherence signal, then check threshold.
        let mut filter = rvm_coherence::EmaFilter::new(5000); // 50% alpha
        let s1 = filter.update(9000); // First update: takes raw value.
        assert_eq!(s1.as_basis_points(), 9000);
        assert!(s1.is_coherent());

        let s2 = filter.update(2000); // Smoothed: (9000 + 2000) / 2 = 5500.
        assert_eq!(s2.as_basis_points(), 5500);
        assert!(s2.is_coherent()); // 5500 >= 3000 threshold

        let s3 = filter.update(1000); // (5500 + 1000) / 2 = 3250.
        assert_eq!(s3.as_basis_points(), 3250);
        assert!(s3.is_coherent()); // 3250 >= 3000

        let s4 = filter.update(1000); // (3250 + 1000) / 2 = 2125.
        assert_eq!(s4.as_basis_points(), 2125);
        assert!(!s4.is_coherent()); // 2125 < 3000
    }

    // ---------------------------------------------------------------
    // Scenario 8: Partition split scoring
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_partition_split_scoring() {
        let region_coherence = CoherenceScore::from_basis_points(6000);
        let left = CoherenceScore::from_basis_points(5500);
        let right = CoherenceScore::from_basis_points(8000);

        let score = rvm_partition::scored_region_assignment(region_coherence, left, right);
        // |6000-5500| = 500, |6000-8000| = 2000 -> closer to left.
        assert_eq!(score, 7500);
    }

    // ---------------------------------------------------------------
    // Scenario 9: Merge preconditions with coherence scores
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_partition_merge_preconditions() {
        let high = CoherenceScore::from_basis_points(8000);
        let low = CoherenceScore::from_basis_points(5000);

        // Both high -> merge allowed.
        assert!(rvm_partition::merge_preconditions_met(high, high).is_ok());

        // One low -> merge denied.
        assert!(rvm_partition::merge_preconditions_met(high, low).is_err());
    }

    // ---------------------------------------------------------------
    // Scenario 10: Proof verification with insufficient cap then retry
    // ---------------------------------------------------------------
    #[test]
    fn cross_crate_proof_retry_after_cap_grant() {
        use rvm_cap::CapabilityManager;
        use rvm_types::{CapType, CapRights, ProofTier, ProofToken};
        use rvm_proof::context::ProofContextBuilder;
        use rvm_proof::engine::ProofEngine;

        let witness_log = rvm_witness::WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        // Create capability with READ only (no PROVE).
        let (idx, gen) = cap_mgr
            .create_root_capability(CapType::Region, CapRights::READ, 0, owner)
            .unwrap();

        let token = ProofToken {
            tier: ProofTier::P1,
            epoch: 0,
            hash: 0,
        };

        let context = ProofContextBuilder::new(owner)
            .capability_handle(idx)
            .capability_generation(gen)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(1)
            .build();

        let mut engine = ProofEngine::<64>::new();

        // First attempt: should fail (no PROVE right).
        assert!(engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log).is_err());
        assert_eq!(witness_log.total_emitted(), 1); // Rejection emitted.

        // Create a new capability with PROVE rights.
        let all_rights = CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::PROVE);
        let (idx2, gen2) = cap_mgr
            .create_root_capability(CapType::Region, all_rights, 0, owner)
            .unwrap();

        let context2 = ProofContextBuilder::new(owner)
            .capability_handle(idx2)
            .capability_generation(gen2)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(2) // Different nonce.
            .build();

        // Second attempt with proper cap: should succeed.
        assert!(engine.verify_and_witness(&token, &context2, &cap_mgr, &witness_log).is_ok());
        assert_eq!(witness_log.total_emitted(), 2);
    }
}
