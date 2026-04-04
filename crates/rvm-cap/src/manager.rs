//! Main capability manager tying together table, derivation tree, and verifier.
//!
//! The `CapabilityManager` is the single integration point for all
//! capability operations: create, grant, revoke, verify.

use crate::derivation::DerivationTree;
use crate::error::{CapError, CapResult, ProofError};
use crate::grant::{validate_grant, GrantPolicy};
use crate::revoke::{revoke_capability, RevokeResult};
use crate::table::CapabilityTable;
use crate::verify::{PolicyContext, ProofVerifier};
use crate::DEFAULT_CAP_TABLE_CAPACITY;
use rvm_types::{CapRights, CapToken, CapType, PartitionId};

/// Configuration for the capability manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapManagerConfig {
    /// Maximum delegation depth (default: 8).
    pub max_delegation_depth: u8,
    /// Whether to track derivation chains (for revocation propagation).
    pub track_derivation: bool,
    /// Initial epoch value.
    pub initial_epoch: u32,
}

impl CapManagerConfig {
    /// Creates a new configuration with default values.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_delegation_depth: crate::DEFAULT_MAX_DELEGATION_DEPTH,
            track_derivation: true,
            initial_epoch: 0,
        }
    }

    /// Sets a custom maximum delegation depth.
    #[inline]
    #[must_use]
    pub const fn with_max_depth(mut self, depth: u8) -> Self {
        self.max_delegation_depth = depth;
        self
    }
}

impl Default for CapManagerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about capability manager operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagerStats {
    /// Total capabilities created.
    pub caps_created: u64,
    /// Total capabilities granted (derived).
    pub caps_granted: u64,
    /// Total capabilities revoked.
    pub caps_revoked: u64,
    /// Total revoke operations.
    pub revoke_operations: u64,
    /// Maximum derivation depth reached.
    pub max_depth_reached: u8,
}

/// The main capability manager.
///
/// Coordinates capability table, derivation tree, and proof verifier
/// to provide complete capability lifecycle management.
pub struct CapabilityManager<const N: usize = DEFAULT_CAP_TABLE_CAPACITY> {
    table: CapabilityTable<N>,
    derivation: DerivationTree<N>,
    verifier: ProofVerifier<N>,
    config: CapManagerConfig,
    grant_policy: GrantPolicy,
    epoch: u32,
    next_id: u64,
    stats: ManagerStats,
}

impl<const N: usize> CapabilityManager<N> {
    /// Creates a new capability manager with the given configuration.
    #[must_use]
    pub const fn new(config: CapManagerConfig) -> Self {
        Self {
            table: CapabilityTable::new(),
            derivation: DerivationTree::new(),
            verifier: ProofVerifier::new(config.initial_epoch),
            grant_policy: GrantPolicy {
                max_depth: config.max_delegation_depth,
                allow_grant_once: true,
            },
            epoch: config.initial_epoch,
            next_id: 1,
            config,
            stats: ManagerStats {
                caps_created: 0,
                caps_granted: 0,
                caps_revoked: 0,
                revoke_operations: 0,
                max_depth_reached: 0,
            },
        }
    }

    /// Creates a new capability manager with default configuration.
    #[must_use]
    pub const fn with_defaults() -> Self {
        Self::new(CapManagerConfig::new())
    }

    /// Returns the current configuration.
    #[inline]
    #[must_use]
    pub const fn config(&self) -> &CapManagerConfig {
        &self.config
    }

    /// Returns the current statistics.
    #[inline]
    #[must_use]
    pub const fn stats(&self) -> &ManagerStats {
        &self.stats
    }

    /// Returns the current epoch.
    #[inline]
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Returns the number of active capabilities.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns true if there are no active capabilities.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Increments the global epoch, invalidating stale handles.
    pub fn increment_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.verifier.set_epoch(self.epoch);
    }

    /// Creates a root capability for a new kernel object.
    ///
    /// # Errors
    ///
    /// Returns a [`CapError`] if the table is full or the derivation tree cannot be updated.
    pub fn create_root_capability(
        &mut self,
        cap_type: CapType,
        rights: CapRights,
        badge: u64,
        owner: PartitionId,
    ) -> CapResult<(u32, u32)> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(CapError::TableFull)?;

        let token = CapToken::new(id, cap_type, rights, self.epoch);
        let (index, generation) = self.table.insert_root(token, owner, badge)?;

        if self.config.track_derivation {
            self.derivation.add_root(index, u64::from(self.epoch))?;
        }

        self.stats.caps_created += 1;
        Ok((index, generation))
    }

    /// Grants a derived capability to another partition.
    ///
    /// # Errors
    ///
    /// Returns a [`CapError`] if the source is invalid, rights escalation is attempted,
    /// or the delegation depth limit is exceeded.
    pub fn grant(
        &mut self,
        source_index: u32,
        source_generation: u32,
        requested_rights: CapRights,
        badge: u64,
        target_owner: PartitionId,
    ) -> CapResult<(u32, u32)> {
        let source_slot = self.table.lookup(source_index, source_generation)?;
        let source_copy = *source_slot;

        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(CapError::TableFull)?;

        let (derived_token, depth) = validate_grant(
            &source_copy,
            requested_rights,
            id,
            badge,
            self.epoch,
            self.grant_policy,
        )?;

        let (child_index, child_generation) = self.table.insert_derived(
            derived_token,
            target_owner,
            depth,
            source_index,
            badge,
        )?;

        if self.config.track_derivation {
            self.derivation.add_child(
                source_index,
                child_index,
                depth,
                u64::from(self.epoch),
            )?;
        }

        self.stats.caps_granted += 1;
        if depth > self.stats.max_depth_reached {
            self.stats.max_depth_reached = depth;
        }

        Ok((child_index, child_generation))
    }

    /// Revokes a capability and all its descendants.
    ///
    /// # Errors
    ///
    /// Returns a [`CapError`] if the handle is invalid or already revoked.
    pub fn revoke(&mut self, index: u32, generation: u32) -> CapResult<RevokeResult> {
        let result = revoke_capability(
            &mut self.table,
            &mut self.derivation,
            index,
            generation,
        )?;

        self.stats.caps_revoked += result.revoked_count as u64;
        self.stats.revoke_operations += 1;

        Ok(result)
    }

    /// P1 verification: capability existence + rights check (< 1 us).
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] if the handle is invalid, stale, or lacks the required rights.
    pub fn verify_p1(
        &self,
        cap_index: u32,
        cap_generation: u32,
        required_rights: CapRights,
    ) -> Result<(), ProofError> {
        self.verifier.verify_p1(&self.table, cap_index, cap_generation, required_rights)
    }

    /// P2 verification: structural invariant validation (< 100 us).
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::PolicyViolation`] if any structural check fails.
    pub fn verify_p2(
        &mut self,
        cap_index: u32,
        cap_generation: u32,
        ctx: &PolicyContext,
    ) -> Result<(), ProofError> {
        self.verifier.verify_p2(&self.table, &self.derivation, cap_index, cap_generation, ctx)
    }

    /// P3 verification stub (returns `P3NotImplemented` in v1).
    ///
    /// # Errors
    ///
    /// Always returns [`ProofError::P3NotImplemented`] in v1.
    pub fn verify_p3(&self) -> Result<(), ProofError> {
        self.verifier.verify_p3()
    }

    /// Returns a reference to the underlying table.
    #[must_use]
    pub fn table(&self) -> &CapabilityTable<N> {
        &self.table
    }
}

impl<const N: usize> Default for CapabilityManager<N> {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CapError;

    fn all_rights() -> CapRights {
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
            .union(CapRights::GRANT)
            .union(CapRights::REVOKE)
    }

    #[test]
    fn test_create_root_capability() {
        let mut mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let (idx, gen) = mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        assert_eq!(mgr.len(), 1);
        assert!(mgr.table().lookup(idx, gen).is_ok());
        assert_eq!(mgr.stats().caps_created, 1);
    }

    #[test]
    fn test_grant_and_verify() {
        let mut mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);
        let target = PartitionId::new(2);

        let (root_idx, root_gen) = mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let (child_idx, child_gen) = mgr
            .grant(root_idx, root_gen, CapRights::READ, 42, target)
            .unwrap();

        assert_eq!(mgr.len(), 2);
        let child = mgr.table().lookup(child_idx, child_gen).unwrap();
        assert_eq!(child.token.rights(), CapRights::READ);
        assert_eq!(child.depth, 1);
    }

    #[test]
    fn test_revoke_propagation() {
        let mut mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);
        let target = PartitionId::new(2);

        let (root_idx, root_gen) = mgr
            .create_root_capability(CapType::Region, all_rights(), 0, owner)
            .unwrap();

        let (c1_idx, c1_gen) = mgr
            .grant(root_idx, root_gen, CapRights::READ.union(CapRights::GRANT), 1, target)
            .unwrap();

        let _ = mgr.grant(c1_idx, c1_gen, CapRights::READ, 2, target).unwrap();

        assert_eq!(mgr.len(), 3);
        let result = mgr.revoke(root_idx, root_gen).unwrap();
        assert_eq!(result.revoked_count, 3);
    }

    #[test]
    fn test_delegation_depth_limit() {
        let config = CapManagerConfig::new().with_max_depth(2);
        let mut mgr = CapabilityManager::<64>::new(config);
        let owner = PartitionId::new(1);

        let (i0, g0) = mgr.create_root_capability(CapType::Region, all_rights(), 0, owner).unwrap();
        let (i1, g1) = mgr.grant(i0, g0, all_rights(), 1, owner).unwrap();
        let (i2, g2) = mgr.grant(i1, g1, all_rights(), 2, owner).unwrap();

        let result = mgr.grant(i2, g2, CapRights::READ, 3, owner);
        assert_eq!(result, Err(CapError::DelegationDepthExceeded));
    }

    #[test]
    fn test_epoch_invalidation() {
        let mut mgr = CapabilityManager::<64>::with_defaults();
        let owner = PartitionId::new(1);

        let (idx, gen) = mgr.create_root_capability(CapType::Region, all_rights(), 0, owner).unwrap();
        assert!(mgr.verify_p1(idx, gen, CapRights::READ).is_ok());

        mgr.increment_epoch();
        assert_eq!(mgr.verify_p1(idx, gen, CapRights::READ), Err(ProofError::StaleCapability));
    }

    #[test]
    fn test_p3_not_implemented() {
        let mgr = CapabilityManager::<64>::with_defaults();
        assert_eq!(mgr.verify_p3(), Err(ProofError::P3NotImplemented));
    }
}
