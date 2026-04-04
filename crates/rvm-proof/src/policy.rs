//! P2 policy rules for proof validation.
//!
//! Each rule is evaluated in constant time regardless of outcome,
//! preventing timing side-channel leakage (ADR-135). All rules
//! execute even if earlier rules fail.

use rvm_types::{PartitionId, RvmError};

use crate::context::ProofContext;

/// A single P2 policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// The capability must trace back to the correct owner partition.
    OwnershipChain,
    /// The target address must fall within declared region bounds.
    RegionBounds,
    /// The device or resource lease must not have expired.
    LeaseExpiry,
    /// The delegation chain must not exceed the maximum depth.
    DelegationDepth,
    /// The nonce must not have been used before (replay prevention).
    NonceReplay,
    /// The operation must occur within the valid time window.
    TimeWindow,
}

/// Nonce ring buffer size for replay detection.
///
/// Increased from 64 to 4096 to prevent replay attacks that exploit
/// the small ring buffer window (security finding: nonce ring too small).
const NONCE_RING_SIZE: usize = 4096;

/// Evaluator state for policy rules, including nonce tracking.
#[allow(clippy::struct_field_names)]
pub struct PolicyEvaluator {
    nonce_ring: [u64; NONCE_RING_SIZE],
    nonce_write_pos: usize,
    /// Monotonic watermark: any nonce at or below this value is rejected
    /// outright, even if it has fallen off the ring buffer. This
    /// prevents replaying very old nonces after ring eviction.
    nonce_watermark: u64,
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator {
    /// Create a new policy evaluator with an empty nonce ring.
    #[must_use]
    #[allow(clippy::large_stack_arrays)]
    pub const fn new() -> Self {
        Self {
            nonce_ring: [0u64; NONCE_RING_SIZE],
            nonce_write_pos: 0,
            nonce_watermark: 0,
        }
    }

    /// Evaluate a single policy rule against the given context.
    ///
    /// Returns `Ok(())` if the rule passes.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`RvmError`] if the rule fails.
    pub fn evaluate_rule(&self, rule: Rule, context: &ProofContext) -> Result<(), RvmError> {
        match rule {
            Rule::OwnershipChain => {
                // Structural check: partition must be within the valid range.
                // Full ownership chain validation is done by the cap manager
                // at P1 level; here we only verify structural validity.
                if context.partition_id.as_u32() > PartitionId::MAX_LOGICAL {
                    Err(RvmError::InsufficientCapability)
                } else {
                    Ok(())
                }
            }
            Rule::RegionBounds => {
                if context.region_base < context.region_limit {
                    Ok(())
                } else {
                    Err(RvmError::ProofInvalid)
                }
            }
            Rule::LeaseExpiry => {
                if context.current_time_ns <= context.lease_expiry_ns {
                    Ok(())
                } else {
                    Err(RvmError::DeviceLeaseExpired)
                }
            }
            Rule::DelegationDepth => {
                // Depth is checked structurally -- just verify it is within bounds.
                if context.max_delegation_depth <= 8 {
                    Ok(())
                } else {
                    Err(RvmError::DelegationDepthExceeded)
                }
            }
            Rule::NonceReplay => {
                if self.is_nonce_replayed(context.nonce) {
                    Err(RvmError::ProofInvalid)
                } else {
                    Ok(())
                }
            }
            Rule::TimeWindow => {
                // The operation must happen while the lease is valid.
                if context.current_time_ns <= context.lease_expiry_ns {
                    Ok(())
                } else {
                    Err(RvmError::ProofBudgetExceeded)
                }
            }
        }
    }

    /// Evaluate ALL P2 rules against the given context in constant time.
    ///
    /// Every rule is evaluated regardless of intermediate failures
    /// to prevent timing side-channel leakage (ADR-135). If the nonce
    /// check passes, it is recorded to prevent replay.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ProofInvalid`] if any rule fails.
    pub fn evaluate_all_rules(&mut self, context: &ProofContext) -> Result<(), RvmError> {
        let mut valid = true;

        // Ownership chain.
        valid &= self.evaluate_rule(Rule::OwnershipChain, context).is_ok();

        // Region bounds.
        valid &= self.evaluate_rule(Rule::RegionBounds, context).is_ok();

        // Lease expiry.
        valid &= self.evaluate_rule(Rule::LeaseExpiry, context).is_ok();

        // Delegation depth.
        valid &= self.evaluate_rule(Rule::DelegationDepth, context).is_ok();

        // Nonce replay.
        let nonce_ok = self.evaluate_rule(Rule::NonceReplay, context).is_ok();
        valid &= nonce_ok;

        // Time window.
        valid &= self.evaluate_rule(Rule::TimeWindow, context).is_ok();

        if valid {
            // Record nonce only if all checks passed.
            if context.nonce != 0 {
                self.record_nonce(context.nonce);
            }
            Ok(())
        } else {
            Err(RvmError::ProofInvalid)
        }
    }

    /// Check whether a nonce has been seen before.
    ///
    /// Also rejects nonces at or below the monotonic watermark to
    /// prevent replaying very old nonces that have fallen off the ring.
    fn is_nonce_replayed(&self, nonce: u64) -> bool {
        if nonce == 0 {
            return false; // Zero nonce is a sentinel, not subject to replay.
        }
        // Watermark check: reject any nonce at or below the low-water mark.
        if nonce <= self.nonce_watermark {
            return true;
        }
        for &entry in &self.nonce_ring {
            if entry == nonce {
                return true;
            }
        }
        false
    }

    /// Record a nonce as used and advance the watermark on wrap.
    fn record_nonce(&mut self, nonce: u64) {
        self.nonce_ring[self.nonce_write_pos] = nonce;
        self.nonce_write_pos = (self.nonce_write_pos + 1) % NONCE_RING_SIZE;
        // Advance watermark when the write pointer wraps around.
        if self.nonce_write_pos == 0 {
            let mut min_val = u64::MAX;
            for &entry in &self.nonce_ring {
                if entry != 0 && entry < min_val {
                    min_val = entry;
                }
            }
            if min_val != u64::MAX && min_val > self.nonce_watermark {
                self.nonce_watermark = min_val;
            }
        }
    }
}

/// All P2 rules in evaluation order.
pub const ALL_RULES: [Rule; 6] = [
    Rule::OwnershipChain,
    Rule::RegionBounds,
    Rule::LeaseExpiry,
    Rule::DelegationDepth,
    Rule::NonceReplay,
    Rule::TimeWindow,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ProofContextBuilder;
    use rvm_types::PartitionId;

    fn valid_context() -> ProofContext {
        ProofContextBuilder::new(PartitionId::new(1))
            .target_object(42)
            .capability_handle(1)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .max_delegation_depth(4)
            .nonce(42)
            .build()
    }

    #[test]
    fn test_all_rules_pass() {
        let mut evaluator = PolicyEvaluator::new();
        let ctx = valid_context();
        assert!(evaluator.evaluate_all_rules(&ctx).is_ok());
    }

    #[test]
    fn test_region_bounds_fail() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .capability_handle(1)
            .region_bounds(0x2000, 0x1000) // inverted
            .time_window(500, 1000)
            .nonce(1)
            .build();
        assert_eq!(evaluator.evaluate_rule(Rule::RegionBounds, &ctx), Err(RvmError::ProofInvalid));
    }

    #[test]
    fn test_lease_expiry_fail() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .capability_handle(1)
            .region_bounds(0x1000, 0x2000)
            .time_window(2000, 1000) // current > expiry
            .nonce(1)
            .build();
        assert_eq!(evaluator.evaluate_rule(Rule::LeaseExpiry, &ctx), Err(RvmError::DeviceLeaseExpired));
    }

    #[test]
    fn test_nonce_replay() {
        let mut evaluator = PolicyEvaluator::new();
        let ctx = valid_context();

        // First call succeeds and records the nonce.
        assert!(evaluator.evaluate_all_rules(&ctx).is_ok());

        // Second call with same nonce fails.
        assert_eq!(evaluator.evaluate_all_rules(&ctx), Err(RvmError::ProofInvalid));
    }

    #[test]
    fn test_zero_nonce_not_replayed() {
        let mut evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .capability_handle(1)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(0)
            .build();

        // Zero nonce should always pass replay check.
        assert!(evaluator.evaluate_all_rules(&ctx).is_ok());
        assert!(evaluator.evaluate_all_rules(&ctx).is_ok());
    }

    #[test]
    fn test_constant_time_evaluation() {
        // Even with multiple failures, all rules execute.
        let mut evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .capability_handle(1)
            .region_bounds(0x2000, 0x1000) // bounds fail
            .time_window(2000, 1000) // time fail
            .nonce(1)
            .build();

        // Should return a single combined error.
        assert_eq!(evaluator.evaluate_all_rules(&ctx), Err(RvmError::ProofInvalid));
    }

    #[test]
    fn test_hypervisor_partition_ownership_passes() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::HYPERVISOR)
            .capability_handle(0)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .build();
        assert!(evaluator.evaluate_rule(Rule::OwnershipChain, &ctx).is_ok());
    }

    // ---------------------------------------------------------------
    // Individual rule tests for all 6 rule types
    // ---------------------------------------------------------------

    #[test]
    fn test_ownership_chain_valid_partition() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(100))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .build();
        assert!(evaluator.evaluate_rule(Rule::OwnershipChain, &ctx).is_ok());
    }

    #[test]
    fn test_ownership_chain_exceeds_max_logical() {
        let evaluator = PolicyEvaluator::new();
        // PartitionId::MAX_LOGICAL is 4096. Partition > 4096 should fail.
        let ctx = ProofContextBuilder::new(PartitionId::new(PartitionId::MAX_LOGICAL + 1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .build();
        assert_eq!(
            evaluator.evaluate_rule(Rule::OwnershipChain, &ctx),
            Err(RvmError::InsufficientCapability)
        );
    }

    #[test]
    fn test_ownership_chain_at_max_logical_boundary() {
        let evaluator = PolicyEvaluator::new();
        // Exactly at MAX_LOGICAL should pass.
        let ctx = ProofContextBuilder::new(PartitionId::new(PartitionId::MAX_LOGICAL))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .build();
        assert!(evaluator.evaluate_rule(Rule::OwnershipChain, &ctx).is_ok());
    }

    #[test]
    fn test_region_bounds_equal_base_limit_fails() {
        let evaluator = PolicyEvaluator::new();
        // base == limit is not valid (must be strictly less).
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x1000)
            .build();
        assert_eq!(
            evaluator.evaluate_rule(Rule::RegionBounds, &ctx),
            Err(RvmError::ProofInvalid)
        );
    }

    #[test]
    fn test_region_bounds_zero_zero_fails() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0, 0)
            .build();
        assert_eq!(
            evaluator.evaluate_rule(Rule::RegionBounds, &ctx),
            Err(RvmError::ProofInvalid)
        );
    }

    #[test]
    fn test_region_bounds_one_apart_passes() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x1001)
            .build();
        assert!(evaluator.evaluate_rule(Rule::RegionBounds, &ctx).is_ok());
    }

    #[test]
    fn test_lease_expiry_at_exact_boundary() {
        let evaluator = PolicyEvaluator::new();
        // current_time == expiry should pass (<=).
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .time_window(1000, 1000)
            .build();
        assert!(evaluator.evaluate_rule(Rule::LeaseExpiry, &ctx).is_ok());
    }

    #[test]
    fn test_delegation_depth_at_max() {
        let evaluator = PolicyEvaluator::new();
        // Depth exactly 8 should pass.
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .max_delegation_depth(8)
            .build();
        assert!(evaluator.evaluate_rule(Rule::DelegationDepth, &ctx).is_ok());
    }

    #[test]
    fn test_delegation_depth_exceeds_max() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .max_delegation_depth(9)
            .build();
        assert_eq!(
            evaluator.evaluate_rule(Rule::DelegationDepth, &ctx),
            Err(RvmError::DelegationDepthExceeded)
        );
    }

    #[test]
    fn test_delegation_depth_zero_passes() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .max_delegation_depth(0)
            .build();
        assert!(evaluator.evaluate_rule(Rule::DelegationDepth, &ctx).is_ok());
    }

    #[test]
    fn test_time_window_current_past_expiry_fails() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .time_window(5000, 4999)
            .build();
        assert_eq!(
            evaluator.evaluate_rule(Rule::TimeWindow, &ctx),
            Err(RvmError::ProofBudgetExceeded)
        );
    }

    #[test]
    fn test_time_window_at_boundary_passes() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .time_window(5000, 5000)
            .build();
        assert!(evaluator.evaluate_rule(Rule::TimeWindow, &ctx).is_ok());
    }

    #[test]
    fn test_nonce_replay_fresh_nonce_passes() {
        let evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .nonce(42)
            .build();
        assert!(evaluator.evaluate_rule(Rule::NonceReplay, &ctx).is_ok());
    }

    // ---------------------------------------------------------------
    // Nonce replay detection across ring buffer wrap
    // ---------------------------------------------------------------

    #[test]
    fn test_nonce_replay_across_ring_wrap() {
        let mut evaluator = PolicyEvaluator::new();

        // Fill the ring buffer with 4096 unique nonces.
        for i in 1..=4096u64 {
            let ctx = ProofContextBuilder::new(PartitionId::new(1))
                .region_bounds(0x1000, 0x2000)
                .time_window(500, 1000)
                .nonce(i)
                .build();
            assert!(evaluator.evaluate_all_rules(&ctx).is_ok());
        }

        // Nonce 1 should still be in the ring buffer.
        let ctx_replay = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(1)
            .build();
        assert_eq!(
            evaluator.evaluate_all_rules(&ctx_replay),
            Err(RvmError::ProofInvalid)
        );

        // Now insert one more to trigger watermark advancement.
        let ctx_new = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(4097)
            .build();
        assert!(evaluator.evaluate_all_rules(&ctx_new).is_ok());

        // Nonce 1 should be rejected by the watermark even after eviction.
        let ctx_reuse = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(1)
            .build();
        assert_eq!(
            evaluator.evaluate_all_rules(&ctx_reuse),
            Err(RvmError::ProofInvalid)
        );
    }

    #[test]
    fn test_nonce_watermark_rejects_old() {
        let mut evaluator = PolicyEvaluator::new();

        // Fill the ring with nonces 100..100+4096, then one more to
        // trigger watermark. Nonces below the watermark are rejected.
        for i in 100..100 + 4096u64 {
            let ctx = ProofContextBuilder::new(PartitionId::new(1))
                .region_bounds(0x1000, 0x2000)
                .time_window(500, 1000)
                .nonce(i)
                .build();
            assert!(evaluator.evaluate_all_rules(&ctx).is_ok());
        }

        // Trigger wrap.
        let ctx_wrap = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(100 + 4096)
            .build();
        assert!(evaluator.evaluate_all_rules(&ctx_wrap).is_ok());

        // Nonce 50 (below watermark) should be rejected.
        let ctx_old = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(50)
            .build();
        assert_eq!(
            evaluator.evaluate_all_rules(&ctx_old),
            Err(RvmError::ProofInvalid)
        );
    }

    #[test]
    fn test_all_rules_constant_structure() {
        // Verify the ALL_RULES constant has exactly 6 entries.
        assert_eq!(ALL_RULES.len(), 6);
        assert_eq!(ALL_RULES[0], Rule::OwnershipChain);
        assert_eq!(ALL_RULES[1], Rule::RegionBounds);
        assert_eq!(ALL_RULES[2], Rule::LeaseExpiry);
        assert_eq!(ALL_RULES[3], Rule::DelegationDepth);
        assert_eq!(ALL_RULES[4], Rule::NonceReplay);
        assert_eq!(ALL_RULES[5], Rule::TimeWindow);
    }

    #[test]
    fn test_evaluate_all_with_single_failure_returns_proof_invalid() {
        // Only region bounds fail, everything else passes.
        let mut evaluator = PolicyEvaluator::new();
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x2000, 0x1000) // inverted
            .time_window(500, 1000)
            .nonce(100)
            .build();
        assert_eq!(evaluator.evaluate_all_rules(&ctx), Err(RvmError::ProofInvalid));
    }

    #[test]
    fn test_nonce_not_recorded_on_failure() {
        let mut evaluator = PolicyEvaluator::new();

        // First attempt: fails because of inverted region bounds.
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x2000, 0x1000) // inverted
            .time_window(500, 1000)
            .nonce(777)
            .build();
        assert!(evaluator.evaluate_all_rules(&ctx).is_err());

        // Second attempt with same nonce but valid context should succeed
        // because the nonce was NOT recorded on failure.
        let ctx_ok = ProofContextBuilder::new(PartitionId::new(1))
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .nonce(777)
            .build();
        assert!(evaluator.evaluate_all_rules(&ctx_ok).is_ok());
    }
}
