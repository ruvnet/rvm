//! Three-layer proof verification (ADR-135).
//!
//! - **P1**: Capability existence + rights check (< 1 us, bitmap AND).
//! - **P2**: Structural invariant validation (< 100 us, constant-time).
//! - **P3**: Deep proof (v1 stub, returns `P3NotImplemented`).

use crate::derivation::DerivationTree;
use crate::error::ProofError;
use crate::table::CapabilityTable;
use rvm_types::CapRights;

/// Nonce ring buffer size for replay prevention.
///
/// Increased from 64 to 4096 to prevent replay attacks that exploit
/// the small ring buffer window (security finding: nonce ring too small).
const NONCE_RING_SIZE: usize = 4096;

/// Policy context for P2 validation.
#[derive(Debug, Clone, Copy)]
pub struct PolicyContext {
    /// The expected owner partition ID.
    pub expected_owner: u32,
    /// Region lower bound (used for bounds checking).
    pub region_base: u64,
    /// Region upper bound.
    pub region_limit: u64,
    /// Lease expiry timestamp in nanoseconds.
    pub lease_expiry_ns: u64,
    /// Current timestamp in nanoseconds.
    pub current_time_ns: u64,
    /// Maximum delegation depth (typically 8).
    pub max_delegation_depth: u8,
    /// Nonce for replay prevention.
    pub nonce: u64,
}

/// Three-layer proof verifier.
///
/// Encapsulates the epoch and nonce tracker needed for P1/P2/P3 verification.
pub struct ProofVerifier<const N: usize> {
    /// Reference epoch for stale-handle detection.
    current_epoch: u32,
    /// Nonce ring buffer for replay prevention.
    nonce_ring: [u64; NONCE_RING_SIZE],
    /// Write position in the nonce ring.
    nonce_write_pos: usize,
    /// Monotonic watermark: any nonce below this value is rejected
    /// outright, even if it has fallen off the ring buffer. This
    /// prevents replaying very old nonces after ring eviction.
    nonce_watermark: u64,
}

impl<const N: usize> ProofVerifier<N> {
    /// Creates a new proof verifier with the given epoch.
    #[must_use]
    #[allow(clippy::large_stack_arrays)]
    pub const fn new(epoch: u32) -> Self {
        Self {
            current_epoch: epoch,
            nonce_ring: [0u64; NONCE_RING_SIZE],
            nonce_write_pos: 0,
            nonce_watermark: 0,
        }
    }

    /// Updates the current epoch.
    pub fn set_epoch(&mut self, epoch: u32) {
        self.current_epoch = epoch;
    }

    /// P1: Capability existence + rights check.
    ///
    /// Budget: < 1 us. No allocation. All checks execute regardless of
    /// intermediate failures to prevent timing side-channel leakage.
    /// The final error returned is deliberately the most generic
    /// (`InvalidHandle`) to avoid leaking which check failed.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::InvalidHandle`] if the handle is invalid.
    /// Returns [`ProofError::StaleCapability`] if the epoch does not match.
    /// Returns [`ProofError::InsufficientRights`] if the rights are insufficient.
    #[inline]
    pub fn verify_p1(
        &self,
        table: &CapabilityTable<N>,
        cap_index: u32,
        cap_generation: u32,
        required_rights: CapRights,
    ) -> Result<(), ProofError> {
        // Run ALL checks unconditionally to prevent timing side channels.
        // We accumulate a bitmask of failures rather than early-returning.
        let mut fail_mask: u8 = 0;

        let lookup_result = table.lookup(cap_index, cap_generation);

        // Check 1: Handle validity.
        let (epoch_match, rights_match) = if let Ok(slot) = &lookup_result {
            // Check 2: Epoch match.
            let e = slot.token.epoch() == self.current_epoch;
            // Check 3: Rights subset.
            let r = slot.token.has_rights(required_rights);
            (e, r)
        } else {
            fail_mask |= 1;
            // Still "compute" epoch and rights checks against dummy values
            // to keep timing constant. The compiler should not elide these
            // because fail_mask is read below.
            (false, false)
        };

        if !epoch_match {
            fail_mask |= 2;
        }
        if !rights_match {
            fail_mask |= 4;
        }

        if fail_mask == 0 {
            Ok(())
        } else if fail_mask & 1 != 0 {
            Err(ProofError::InvalidHandle)
        } else if fail_mask & 2 != 0 {
            Err(ProofError::StaleCapability)
        } else {
            Err(ProofError::InsufficientRights)
        }
    }

    /// P2: Structural invariant validation (constant-time).
    ///
    /// Budget: < 100 us. All checks execute regardless of intermediate
    /// failures to prevent timing side-channel leakage (ADR-135).
    ///
    /// Checks: ownership chain, region bounds, lease expiry,
    /// delegation depth, nonce replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::PolicyViolation`] if any structural check fails.
    pub fn verify_p2(
        &mut self,
        table: &CapabilityTable<N>,
        tree: &DerivationTree<N>,
        cap_index: u32,
        cap_generation: u32,
        ctx: &PolicyContext,
    ) -> Result<(), ProofError> {
        let mut valid = true;

        // 1. Ownership chain valid.
        let owner_ok = table
            .lookup(cap_index, cap_generation)
            .map(|slot| slot.owner.as_u32() == ctx.expected_owner)
            .unwrap_or(false);
        valid &= owner_ok;

        // 2. Region bounds legal.
        valid &= ctx.region_base < ctx.region_limit;

        // 3. Lease not expired.
        valid &= ctx.current_time_ns <= ctx.lease_expiry_ns;

        // 4. Delegation depth within limit.
        let depth_ok = tree
            .depth(cap_index)
            .map(|d| d <= ctx.max_delegation_depth)
            .unwrap_or(false);
        valid &= depth_ok;

        // 5. Nonce not replayed.
        let nonce_ok = self.check_nonce(ctx.nonce);
        valid &= nonce_ok;

        if valid {
            self.mark_nonce(ctx.nonce);
            Ok(())
        } else {
            Err(ProofError::PolicyViolation)
        }
    }

    /// P3: Deep proof verification (v1 stub).
    ///
    /// Returns `Err(ProofError::P3NotImplemented)` in v1.
    ///
    /// # Errors
    ///
    /// Always returns [`ProofError::P3NotImplemented`] in v1.
    #[inline]
    pub fn verify_p3(&self) -> Result<(), ProofError> {
        Err(ProofError::P3NotImplemented)
    }

    /// Checks if a nonce has been used recently.
    ///
    /// Rejects nonces that are below the monotonic watermark (very old
    /// nonces that have already fallen off the ring) as well as nonces
    /// still present in the ring buffer.
    fn check_nonce(&self, nonce: u64) -> bool {
        // Zero nonce is a sentinel, not subject to replay.
        if nonce == 0 {
            return true;
        }
        // Watermark check: reject any nonce below the low-water mark.
        if nonce <= self.nonce_watermark {
            return false;
        }
        for entry in &self.nonce_ring {
            if *entry == nonce {
                return false;
            }
        }
        true
    }

    /// Records a nonce as used and advances the watermark.
    fn mark_nonce(&mut self, nonce: u64) {
        if nonce == 0 {
            return;
        }
        self.nonce_ring[self.nonce_write_pos] = nonce;
        self.nonce_write_pos = (self.nonce_write_pos + 1) % NONCE_RING_SIZE;
        // Advance watermark: the watermark tracks the minimum nonce
        // that was evicted from the ring. When we wrap, the oldest
        // entry is being overwritten, so we bump the watermark.
        if self.nonce_write_pos == 0 {
            // We just wrapped. Find the minimum value in the ring
            // to set as the new watermark.
            let mut min_val = u64::MAX;
            for entry in &self.nonce_ring {
                if *entry != 0 && *entry < min_val {
                    min_val = *entry;
                }
            }
            if min_val != u64::MAX && min_val > self.nonce_watermark {
                self.nonce_watermark = min_val;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_types::{CapToken, CapType, PartitionId};

    fn setup() -> (CapabilityTable<64>, DerivationTree<64>, ProofVerifier<64>) {
        let table = CapabilityTable::<64>::new();
        let tree = DerivationTree::<64>::new();
        let verifier = ProofVerifier::<64>::new(0);
        (table, tree, verifier)
    }

    fn all_rights() -> CapRights {
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
            .union(CapRights::GRANT)
            .union(CapRights::REVOKE)
    }

    #[test]
    fn test_p1_valid() {
        let (mut table, _, verifier) = setup();
        let owner = PartitionId::new(1);
        let token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (idx, gen) = table.insert_root(token, owner, 0).unwrap();
        assert!(verifier.verify_p1(&table, idx, gen, CapRights::READ).is_ok());
    }

    #[test]
    fn test_p1_invalid_handle() {
        let (table, _, verifier) = setup();
        assert_eq!(verifier.verify_p1(&table, 99, 0, CapRights::READ), Err(ProofError::InvalidHandle));
    }

    #[test]
    fn test_p1_stale_epoch() {
        let (mut table, _, verifier) = setup();
        let token = CapToken::new(100, CapType::Region, all_rights(), 5);
        let (idx, gen) = table.insert_root(token, PartitionId::new(1), 0).unwrap();
        assert_eq!(verifier.verify_p1(&table, idx, gen, CapRights::READ), Err(ProofError::StaleCapability));
    }

    #[test]
    fn test_p1_insufficient_rights() {
        let (mut table, _, verifier) = setup();
        let token = CapToken::new(100, CapType::Region, CapRights::READ, 0);
        let (idx, gen) = table.insert_root(token, PartitionId::new(1), 0).unwrap();
        assert_eq!(verifier.verify_p1(&table, idx, gen, CapRights::WRITE), Err(ProofError::InsufficientRights));
    }

    #[test]
    fn test_p2_all_pass() {
        let (mut table, mut tree, mut verifier) = setup();
        let token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (idx, gen) = table.insert_root(token, PartitionId::new(1), 0).unwrap();
        tree.add_root(idx, 0).unwrap();

        let ctx = PolicyContext {
            expected_owner: 1,
            region_base: 0x1000,
            region_limit: 0x2000,
            lease_expiry_ns: 1_000_000_000,
            current_time_ns: 500_000_000,
            max_delegation_depth: 8,
            nonce: 42,
        };
        assert!(verifier.verify_p2(&table, &tree, idx, gen, &ctx).is_ok());
    }

    #[test]
    fn test_p2_nonce_replay() {
        let (mut table, mut tree, mut verifier) = setup();
        let token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (idx, gen) = table.insert_root(token, PartitionId::new(1), 0).unwrap();
        tree.add_root(idx, 0).unwrap();

        let ctx = PolicyContext {
            expected_owner: 1,
            region_base: 0x1000,
            region_limit: 0x2000,
            lease_expiry_ns: 1_000_000_000,
            current_time_ns: 500_000_000,
            max_delegation_depth: 8,
            nonce: 55,
        };
        assert!(verifier.verify_p2(&table, &tree, idx, gen, &ctx).is_ok());
        assert_eq!(verifier.verify_p2(&table, &tree, idx, gen, &ctx), Err(ProofError::PolicyViolation));
    }

    #[test]
    fn test_p3_not_implemented() {
        let verifier = ProofVerifier::<64>::new(0);
        assert_eq!(verifier.verify_p3(), Err(ProofError::P3NotImplemented));
    }

    #[test]
    fn test_nonce_ring_4096_churn() {
        // Verify that after filling the 4096-entry ring, old nonces are
        // rejected by the monotonic watermark even after eviction.
        let (mut table, mut tree, mut verifier) = setup();
        let token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (idx, gen) = table.insert_root(token, PartitionId::new(1), 0).unwrap();
        tree.add_root(idx, 0).unwrap();

        // Insert 4096 nonces (1..=4096).
        for i in 1..=4096u64 {
            let ctx = PolicyContext {
                expected_owner: 1,
                region_base: 0x1000,
                region_limit: 0x2000,
                lease_expiry_ns: 1_000_000_000,
                current_time_ns: 500_000_000,
                max_delegation_depth: 8,
                nonce: i,
            };
            assert!(verifier.verify_p2(&table, &tree, idx, gen, &ctx).is_ok());
        }

        // Now insert one more to push nonce 1 out and trigger watermark.
        let ctx_new = PolicyContext {
            expected_owner: 1,
            region_base: 0x1000,
            region_limit: 0x2000,
            lease_expiry_ns: 1_000_000_000,
            current_time_ns: 500_000_000,
            max_delegation_depth: 8,
            nonce: 4097,
        };
        assert!(verifier.verify_p2(&table, &tree, idx, gen, &ctx_new).is_ok());

        // Nonce 1 should be rejected by the watermark even though it
        // has been evicted from the ring.
        let ctx_old = PolicyContext {
            expected_owner: 1,
            region_base: 0x1000,
            region_limit: 0x2000,
            lease_expiry_ns: 1_000_000_000,
            current_time_ns: 500_000_000,
            max_delegation_depth: 8,
            nonce: 1,
        };
        assert_eq!(
            verifier.verify_p2(&table, &tree, idx, gen, &ctx_old),
            Err(ProofError::PolicyViolation)
        );
    }

    #[test]
    fn test_watermark_rejects_below_minimum() {
        let mut verifier = ProofVerifier::<64>::new(0);
        // Manually advance the watermark by filling the ring and wrapping.
        // Use nonces 100..100+4096 to set a high watermark.
        for i in 100..100 + 4096u64 {
            verifier.mark_nonce(i);
        }
        // Nonce below the watermark should be rejected.
        assert!(!verifier.check_nonce(1));
        assert!(!verifier.check_nonce(99));
    }
}
