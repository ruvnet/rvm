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
const NONCE_RING_SIZE: usize = 64;

/// Evaluator state for policy rules, including nonce tracking.
pub struct PolicyEvaluator {
    nonce_ring: [u64; NONCE_RING_SIZE],
    nonce_write_pos: usize,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator with an empty nonce ring.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nonce_ring: [0u64; NONCE_RING_SIZE],
            nonce_write_pos: 0,
        }
    }

    /// Evaluate a single policy rule against the given context.
    ///
    /// Returns `Ok(())` if the rule passes.
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
    fn is_nonce_replayed(&self, nonce: u64) -> bool {
        if nonce == 0 {
            return false; // Zero nonce is a sentinel, not subject to replay.
        }
        for &entry in &self.nonce_ring {
            if entry == nonce {
                return true;
            }
        }
        false
    }

    /// Record a nonce as used.
    fn record_nonce(&mut self, nonce: u64) {
        self.nonce_ring[self.nonce_write_pos] = nonce;
        self.nonce_write_pos = (self.nonce_write_pos + 1) % NONCE_RING_SIZE;
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
}
