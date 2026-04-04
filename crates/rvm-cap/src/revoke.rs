//! Epoch-based capability revocation.
//!
//! Revocation propagates through the derivation tree, invalidating
//! all descendants of the revoked capability.

use crate::derivation::DerivationTree;
use crate::error::{CapError, CapResult};
use crate::table::CapabilityTable;

/// Result of a revocation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeResult {
    /// Number of capabilities revoked (including the target).
    pub revoked_count: usize,
}

impl RevokeResult {
    /// Creates a new revoke result.
    #[must_use]
    pub const fn new(revoked_count: usize) -> Self {
        Self { revoked_count }
    }
}

/// Revokes a capability and propagates through the derivation tree.
///
/// Both the derivation tree and the capability table are updated:
/// the tree marks nodes as invalid, and the table invalidates ALL
/// corresponding slots (bumping generation counters) including
/// every descendant in the derivation subtree.
///
/// # Security
///
/// It is critical that table invalidation covers ALL descendants,
/// not just the root. Without this, a revoked child capability's
/// table slot remains `is_valid: true` and would pass P1 verification.
pub fn revoke_capability<const N: usize>(
    table: &mut CapabilityTable<N>,
    tree: &mut DerivationTree<N>,
    index: u32,
    generation: u32,
) -> CapResult<RevokeResult> {
    // Validate that the handle is still valid.
    let _ = table.lookup(index, generation)?;

    // Collect the set of indices that will be revoked by the tree walk.
    // We must invalidate ALL of them in the table, not just the root.
    let revoked_indices = tree.collect_subtree(index);

    // Revoke in the derivation tree (marks descendants invalid).
    let revoked = tree.revoke(index).map_err(|_| CapError::Revoked)?;

    // Synchronize: invalidate ALL revoked slots in the table,
    // including the root and every descendant.
    for &idx in &revoked_indices {
        table.force_invalidate(idx);
    }

    Ok(RevokeResult::new(revoked))
}

/// Revokes a single capability without propagation.
///
/// # Errors
///
/// Returns [`CapError::InvalidHandle`] if the handle is invalid.
/// Returns [`CapError::StaleHandle`] if the generation does not match.
pub fn revoke_single<const N: usize>(
    table: &mut CapabilityTable<N>,
    index: u32,
    generation: u32,
) -> CapResult<()> {
    table.remove(index, generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_types::{CapRights, CapToken, CapType, PartitionId};

    fn all_rights() -> CapRights {
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
            .union(CapRights::GRANT)
            .union(CapRights::REVOKE)
    }

    #[test]
    fn test_revoke_propagation() {
        let mut table = CapabilityTable::<64>::new();
        let mut tree = DerivationTree::<64>::new();
        let owner = PartitionId::new(1);
        let token = CapToken::new(1, CapType::Region, all_rights(), 0);

        let (r_idx, r_gen) = table.insert_root(token, owner, 0).unwrap();
        tree.add_root(r_idx, 0).unwrap();

        let (c1_idx, _) = table.insert_derived(token, owner, 1, r_idx, 0).unwrap();
        tree.add_child(r_idx, c1_idx, 1, 0).unwrap();

        let (c2_idx, _) = table.insert_derived(token, owner, 1, r_idx, 0).unwrap();
        tree.add_child(r_idx, c2_idx, 1, 0).unwrap();

        let (gc_idx, _) = table.insert_derived(token, owner, 2, c1_idx, 0).unwrap();
        tree.add_child(c1_idx, gc_idx, 2, 0).unwrap();

        let result = revoke_capability(&mut table, &mut tree, r_idx, r_gen).unwrap();
        assert_eq!(result.revoked_count, 4);

        assert!(!tree.is_valid(r_idx));
        assert!(!tree.is_valid(c1_idx));
        assert!(!tree.is_valid(c2_idx));
        assert!(!tree.is_valid(gc_idx));
    }

    #[test]
    fn test_revoke_single() {
        let mut table = CapabilityTable::<64>::new();
        let owner = PartitionId::new(1);
        let token = CapToken::new(1, CapType::Region, all_rights(), 0);

        let (idx, gen) = table.insert_root(token, owner, 0).unwrap();
        revoke_single(&mut table, idx, gen).unwrap();
        assert!(table.lookup(idx, gen).is_err());
    }

    #[test]
    fn test_revoke_invalid_handle() {
        let mut table = CapabilityTable::<64>::new();
        let mut tree = DerivationTree::<64>::new();
        let result = revoke_capability(&mut table, &mut tree, 99, 0);
        assert!(result.is_err());
    }
}
