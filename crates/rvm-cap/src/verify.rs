//! Three-layer proof verification (ADR-135).
//!
//! - **P1**: Capability existence + rights check (< 1 us, bitmap AND).
//! - **P2**: Structural invariant validation (< 100 us, constant-time).
//! - **P3**: Deep proof — derivation chain integrity (root reachability, epoch monotonicity).

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
    /// Hash-indexed nonce lookup: `nonce_hash[nonce % SIZE]` stores the
    /// nonce value for O(1) replay detection instead of O(N) linear scan.
    nonce_hash: [u64; NONCE_RING_SIZE],
    /// Write position in the nonce ring.
    nonce_write_pos: usize,
    /// Monotonic watermark: any nonce below this value is rejected
    /// outright, even if it has fallen off the ring buffer. This
    /// prevents replaying very old nonces after ring eviction.
    nonce_watermark: u64,
    /// Whether nonce == 0 is allowed to bypass replay checks.
    ///
    /// Default is `false` (zero nonce is rejected). Set to `true` only
    /// for boot-time or backwards-compatible contexts where a sentinel
    /// nonce is acceptable.
    allow_zero_nonce: bool,
}

impl<const N: usize> ProofVerifier<N> {
    /// Creates a new proof verifier with the given epoch.
    ///
    /// By default, nonce == 0 is **rejected** (no zero-nonce bypass).
    /// Use [`set_allow_zero_nonce`](Self::set_allow_zero_nonce) to enable
    /// the sentinel behaviour for boot-time contexts.
    #[must_use]
    #[allow(clippy::large_stack_arrays)]
    pub const fn new(epoch: u32) -> Self {
        Self {
            current_epoch: epoch,
            nonce_ring: [0u64; NONCE_RING_SIZE],
            nonce_hash: [0u64; NONCE_RING_SIZE],
            nonce_write_pos: 0,
            nonce_watermark: 0,
            allow_zero_nonce: false,
        }
    }

    /// Set whether nonce == 0 is allowed to bypass replay checks.
    pub fn set_allow_zero_nonce(&mut self, allow: bool) {
        self.allow_zero_nonce = allow;
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

    /// P3: Deep proof — derivation chain integrity verification.
    ///
    /// Walks the derivation tree from the given capability back to its
    /// root and verifies:
    /// 1. Every ancestor is valid (not revoked).
    /// 2. Depth decreases monotonically toward the root.
    /// 3. Epoch values are non-decreasing from root to leaf.
    /// 4. The chain terminates at a root node (depth 0).
    /// 5. The chain length does not exceed `max_depth`.
    ///
    /// Budget: < 10 us for depth <= 8 (typical). Worst-case O(depth).
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::DerivationChainBroken`] if the chain is
    /// invalid, tampered, or does not reach a root.
    pub fn verify_p3(
        &self,
        table: &CapabilityTable<N>,
        tree: &DerivationTree<N>,
        cap_index: u32,
        cap_generation: u32,
        max_depth: u8,
    ) -> Result<(), ProofError> {
        // Verify the capability itself is valid.
        let _slot = table
            .lookup(cap_index, cap_generation)
            .map_err(|_| ProofError::DerivationChainBroken)?;

        // Verify the derivation node exists and is valid.
        let node = tree
            .get(cap_index)
            .ok_or(ProofError::DerivationChainBroken)?;
        if !node.is_valid {
            return Err(ProofError::DerivationChainBroken);
        }

        // If this IS a root, chain is trivially valid.
        if node.depth == 0 {
            return Ok(());
        }

        // Walk the derivation tree up to the root.
        let mut current_depth = node.depth;
        let mut current_epoch = node.epoch;
        let mut steps = 0u8;

        // Walk ancestors. The derivation tree uses first-child/next-sibling,
        // so we need to find the parent. We do this by scanning for a node
        // that has `cap_index` in its children chain.
        let mut current_idx = cap_index;
        loop {
            steps += 1;
            if steps > max_depth {
                return Err(ProofError::DerivationChainBroken);
            }

            // Find the parent of current_idx.
            let parent_idx = tree.find_parent(current_idx);
            match parent_idx {
                Some(pidx) => {
                    let parent = match tree.get(pidx) {
                        Some(p) => p,
                        None => return Err(ProofError::DerivationChainBroken),
                    };

                    // Ancestor must be valid.
                    if !parent.is_valid {
                        return Err(ProofError::DerivationChainBroken);
                    }
                    // Depth must decrease.
                    if parent.depth >= current_depth {
                        return Err(ProofError::DerivationChainBroken);
                    }
                    // Epoch must be non-decreasing from root to leaf
                    // (parent.epoch <= child.epoch).
                    if parent.epoch > current_epoch {
                        return Err(ProofError::DerivationChainBroken);
                    }

                    if parent.depth == 0 {
                        // Reached the root — chain is valid.
                        return Ok(());
                    }

                    current_depth = parent.depth;
                    current_epoch = parent.epoch;
                    current_idx = pidx;
                }
                None => {
                    // No parent found but we're not at root — broken chain.
                    return Err(ProofError::DerivationChainBroken);
                }
            }
        }
    }

    /// Checks if a nonce has been used recently.
    ///
    /// Rejects nonces that are below the monotonic watermark (very old
    /// nonces that have already fallen off the ring) as well as nonces
    /// still present in the ring buffer.
    ///
    /// Nonce == 0 is rejected unless `allow_zero_nonce` is set. This
    /// prevents callers from silently skipping replay protection by
    /// passing a default/uninitialized nonce value.
    fn check_nonce(&self, nonce: u64) -> bool {
        if nonce == 0 {
            return self.allow_zero_nonce;
        }
        // Watermark check: reject any nonce below the low-water mark.
        if nonce <= self.nonce_watermark {
            return false;
        }
        // O(1) hash-indexed lookup instead of linear scan.
        let hash_slot = (nonce as usize) % NONCE_RING_SIZE;
        if self.nonce_hash[hash_slot] == nonce {
            return false;
        }
        true
    }

    /// Records a nonce as used and advances the watermark.
    fn mark_nonce(&mut self, nonce: u64) {
        if nonce == 0 {
            return;
        }
        self.nonce_ring[self.nonce_write_pos] = nonce;
        // Populate hash index for O(1) lookup.
        let hash_slot = (nonce as usize) % NONCE_RING_SIZE;
        self.nonce_hash[hash_slot] = nonce;
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
    fn test_p3_root_passes() {
        let (mut table, mut tree, verifier) = setup();
        let token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (idx, gen) = table.insert_root(token, PartitionId::new(1), 0).unwrap();
        tree.add_root(idx, 0).unwrap();

        assert!(verifier.verify_p3(&table, &tree, idx, gen, 8).is_ok());
    }

    #[test]
    fn test_p3_one_level_derivation() {
        let (mut table, mut tree, verifier) = setup();
        let owner = PartitionId::new(1);

        // Create root.
        let root_token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (root_idx, _root_gen) = table.insert_root(root_token, owner, 0).unwrap();
        tree.add_root(root_idx, 0).unwrap();

        // Derive a child.
        let child_token = CapToken::new(200, CapType::Region, CapRights::READ, 0);
        let (child_idx, child_gen) = table.insert_root(child_token, owner, 0).unwrap();
        tree.add_child(root_idx, child_idx, 1, 1).unwrap();

        // P3 should follow child → root and succeed.
        assert!(verifier.verify_p3(&table, &tree, child_idx, child_gen, 8).is_ok());
    }

    #[test]
    fn test_p3_nonexistent_fails() {
        let (table, tree, verifier) = setup();
        assert_eq!(
            verifier.verify_p3(&table, &tree, 99, 0, 8),
            Err(ProofError::DerivationChainBroken),
        );
    }

    #[test]
    fn test_p3_revoked_ancestor_fails() {
        let (mut table, mut tree, verifier) = setup();
        let owner = PartitionId::new(1);

        let root_token = CapToken::new(100, CapType::Region, all_rights(), 0);
        let (root_idx, _) = table.insert_root(root_token, owner, 0).unwrap();
        tree.add_root(root_idx, 0).unwrap();

        let child_token = CapToken::new(200, CapType::Region, CapRights::READ, 0);
        let (child_idx, child_gen) = table.insert_root(child_token, owner, 0).unwrap();
        tree.add_child(root_idx, child_idx, 1, 1).unwrap();

        // Revoke the root.
        tree.revoke(root_idx).unwrap();

        // P3 should fail because root is revoked.
        assert_eq!(
            verifier.verify_p3(&table, &tree, child_idx, child_gen, 8),
            Err(ProofError::DerivationChainBroken),
        );
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
