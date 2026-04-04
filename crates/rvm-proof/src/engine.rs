//! Unified proof engine.
//!
//! Wraps the capability verifier (from rvm-cap) and witness emitter
//! (from rvm-witness) into a single `ProofEngine` that implements
//! the P1 -> P2 -> witness pipeline.

use rvm_cap::{CapabilityManager, ProofError};
use rvm_types::{ActionKind, CapRights, ProofToken, RvmError, RvmResult, WitnessRecord};
use rvm_witness::WitnessLog;

use crate::context::ProofContext;
use crate::policy::PolicyEvaluator;

/// Unified proof engine combining capability verification, policy
/// evaluation, and witness emission.
///
/// The const parameter `N` is the capability table capacity.
pub struct ProofEngine<const N: usize> {
    /// P2 policy evaluator with nonce tracking.
    policy: PolicyEvaluator,
}

impl<const N: usize> Default for ProofEngine<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ProofEngine<N> {
    /// Create a new proof engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy: PolicyEvaluator::new(),
        }
    }

    /// Execute the full proof pipeline: P1 check -> P2 validate -> emit witness.
    ///
    /// On success, a witness record is appended to the log and `Ok(())`
    /// is returned. On failure, a proof-rejected witness is emitted and
    /// the appropriate error is returned.
    ///
    /// # Errors
    ///
    /// Returns an [`RvmError`] if P1 capability check or P2 policy validation fails.
    pub fn verify_and_witness<const W: usize>(
        &mut self,
        proof_token: &ProofToken,
        context: &ProofContext,
        cap_manager: &CapabilityManager<N>,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<()> {
        // Stage 1: P1 capability check.
        let p1_result = cap_manager.verify_p1(
            context.capability_handle,
            context.capability_generation,
            CapRights::PROVE,
        );

        if let Err(e) = p1_result {
            emit_proof_rejected(witness_log, context, proof_token);
            return Err(proof_error_to_rvm(e));
        }

        // Stage 2: P2 policy validation.
        if let Err(e) = self.policy.evaluate_all_rules(context) {
            emit_proof_rejected(witness_log, context, proof_token);
            return Err(e);
        }

        // Stage 3: Emit success witness.
        let action = match proof_token.tier {
            rvm_types::ProofTier::P1 => ActionKind::ProofVerifiedP1,
            rvm_types::ProofTier::P2 => ActionKind::ProofVerifiedP2,
            rvm_types::ProofTier::P3 => ActionKind::ProofVerifiedP3,
        };

        emit_proof_witness(witness_log, action, context, proof_token);
        Ok(())
    }

    /// P3 stub: returns `Unsupported` (deferred to post-v1).
    ///
    /// # Errors
    ///
    /// Always returns [`RvmError::Unsupported`].
    pub fn verify_p3<const W: usize>(
        &self,
        context: &ProofContext,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<()> {
        let token = ProofToken {
            tier: rvm_types::ProofTier::P3,
            epoch: context.current_epoch,
            hash: 0,
        };
        emit_proof_rejected(witness_log, context, &token);
        Err(RvmError::Unsupported)
    }
}

/// Emit a witness record for a successful proof verification.
fn emit_proof_witness<const W: usize>(
    log: &WitnessLog<W>,
    action: ActionKind,
    context: &ProofContext,
    token: &ProofToken,
) {
    let mut record = WitnessRecord::zeroed();
    record.action_kind = action as u8;
    record.proof_tier = token.tier as u8;
    record.actor_partition_id = context.partition_id.as_u32();
    record.target_object_id = context.target_object;
    record.capability_hash = token.hash;
    log.append(record);
}

/// Emit a witness record for a rejected proof.
fn emit_proof_rejected<const W: usize>(
    log: &WitnessLog<W>,
    context: &ProofContext,
    token: &ProofToken,
) {
    let mut record = WitnessRecord::zeroed();
    record.action_kind = ActionKind::ProofRejected as u8;
    record.proof_tier = token.tier as u8;
    record.actor_partition_id = context.partition_id.as_u32();
    record.target_object_id = context.target_object;
    record.capability_hash = token.hash;
    log.append(record);
}

/// Convert a `ProofError` (from rvm-cap) into an `RvmError`.
fn proof_error_to_rvm(e: ProofError) -> RvmError {
    RvmError::from(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ProofContextBuilder;
    use rvm_cap::CapabilityManager;
    use rvm_types::{CapType, PartitionId, ProofTier};

    fn all_rights() -> CapRights {
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
            .union(CapRights::GRANT)
            .union(CapRights::REVOKE)
            .union(CapRights::PROVE)
    }

    #[test]
    fn test_full_pipeline_success() {
        let witness_log = WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        // Create a capability with PROVE rights.
        let (idx, gen) = cap_mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let token = ProofToken {
            tier: ProofTier::P2,
            epoch: 0,
            hash: 0xABCD,
        };

        let context = ProofContextBuilder::new(owner)
            .target_object(42)
            .capability_handle(idx)
            .capability_generation(gen)
            .current_epoch(0)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(1)
            .build();

        let mut engine = ProofEngine::<64>::new();
        let result = engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log);
        assert!(result.is_ok());

        // Witness should have been emitted.
        assert!(witness_log.total_emitted() > 0);
        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofVerifiedP2 as u8);
    }

    #[test]
    fn test_p1_failure_emits_rejected_witness() {
        let witness_log = WitnessLog::<32>::new();
        let cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let token = ProofToken {
            tier: ProofTier::P1,
            epoch: 0,
            hash: 0,
        };

        let context = ProofContextBuilder::new(owner)
            .capability_handle(999) // Invalid handle.
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(1)
            .build();

        let mut engine = ProofEngine::<64>::new();
        let result = engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log);
        assert!(result.is_err());

        // Should have emitted a rejection witness.
        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofRejected as u8);
    }

    #[test]
    fn test_p3_not_implemented() {
        let witness_log = WitnessLog::<32>::new();
        let engine = ProofEngine::<64>::new();
        let context = ProofContextBuilder::new(PartitionId::new(1)).build();

        let result = engine.verify_p3(&context, &witness_log);
        assert_eq!(result, Err(RvmError::Unsupported));
    }

    #[test]
    fn test_p2_nonce_replay_fails() {
        let witness_log = WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let (idx, gen) = cap_mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let token = ProofToken {
            tier: ProofTier::P2,
            epoch: 0,
            hash: 0,
        };

        let context = ProofContextBuilder::new(owner)
            .capability_handle(idx)
            .capability_generation(gen)
            .current_epoch(0)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(55)
            .build();

        let mut engine = ProofEngine::<64>::new();

        // First call succeeds.
        assert!(engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log).is_ok());

        // Second call with same nonce fails.
        let result = engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log);
        assert!(result.is_err());
    }

    #[test]
    fn test_p1_insufficient_rights_emits_rejected() {
        let witness_log = WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        // Create with READ only, no PROVE.
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
        let result = engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log);
        assert!(result.is_err());

        // Rejected witness emitted.
        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofRejected as u8);
    }

    #[test]
    fn test_p2_policy_failure_emits_rejected() {
        let witness_log = WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let (idx, gen) = cap_mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let token = ProofToken {
            tier: ProofTier::P2,
            epoch: 0,
            hash: 0xABCD,
        };

        // Region bounds are inverted -> P2 failure.
        let context = ProofContextBuilder::new(owner)
            .capability_handle(idx)
            .capability_generation(gen)
            .region_bounds(0x2000, 0x1000) // inverted
            .time_window(500, 1000)
            .nonce(1)
            .build();

        let mut engine = ProofEngine::<64>::new();
        let result = engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log);
        assert!(result.is_err());

        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofRejected as u8);
    }

    #[test]
    fn test_p1_tier_success_witness() {
        let witness_log = WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let (idx, gen) = cap_mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let token = ProofToken {
            tier: ProofTier::P1,
            epoch: 0,
            hash: 0x1234,
        };

        let context = ProofContextBuilder::new(owner)
            .target_object(99)
            .capability_handle(idx)
            .capability_generation(gen)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(10)
            .build();

        let mut engine = ProofEngine::<64>::new();
        assert!(engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log).is_ok());

        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofVerifiedP1 as u8);
        assert_eq!(record.target_object_id, 99);
        assert_eq!(record.capability_hash, 0x1234);
    }

    #[test]
    fn test_multiple_verify_increments_witness_count() {
        let witness_log = WitnessLog::<32>::new();
        let mut cap_mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let (idx, gen) = cap_mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let mut engine = ProofEngine::<64>::new();

        for nonce in 1..=5u64 {
            let token = ProofToken {
                tier: ProofTier::P2,
                epoch: 0,
                hash: 0,
            };
            let context = ProofContextBuilder::new(owner)
                .capability_handle(idx)
                .capability_generation(gen)
                .region_bounds(0x1000, 0x2000)
                .time_window(500, 1000)
                .nonce(nonce)
                .build();
            assert!(engine.verify_and_witness(&token, &context, &cap_mgr, &witness_log).is_ok());
        }
        assert_eq!(witness_log.total_emitted(), 5);
    }

    #[test]
    fn test_p3_emits_rejection_witness() {
        let witness_log = WitnessLog::<32>::new();
        let engine = ProofEngine::<64>::new();
        let context = ProofContextBuilder::new(PartitionId::new(1))
            .target_object(42)
            .build();

        let _ = engine.verify_p3(&context, &witness_log);
        let record = witness_log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofRejected as u8);
        assert_eq!(record.proof_tier, ProofTier::P3 as u8);
    }
}
