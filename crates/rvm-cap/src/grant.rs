//! Capability granting with monotonic attenuation.
//!
//! Implements the grant semantics from ADR-135:
//! - Source must hold GRANT right
//! - Derived rights must be a subset of source rights
//! - Delegation depth is enforced (max 8)

use crate::error::{CapError, CapResult};
use crate::table::CapSlot;
use crate::DEFAULT_MAX_DELEGATION_DEPTH;
use rvm_types::{CapRights, CapToken};

/// Policy configuration for capability grants.
#[derive(Debug, Clone, Copy)]
pub struct GrantPolicy {
    /// Maximum delegation depth allowed.
    pub max_depth: u8,
    /// Whether `GRANT_ONCE` capabilities are allowed.
    pub allow_grant_once: bool,
}

impl GrantPolicy {
    /// Creates a grant policy with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DELEGATION_DEPTH,
            allow_grant_once: true,
        }
    }

    /// Creates a grant policy with a custom depth limit.
    #[must_use]
    pub const fn with_max_depth(max_depth: u8) -> Self {
        Self {
            max_depth,
            allow_grant_once: true,
        }
    }
}

impl Default for GrantPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates a grant request and produces the derived token.
///
/// Returns `(derived_token, depth)` on success.
pub fn validate_grant(
    source: &CapSlot,
    requested_rights: CapRights,
    new_id: u64,
    badge: u64,
    epoch: u32,
    policy: GrantPolicy,
) -> CapResult<(CapToken, u8)> {
    let source_rights = source.token.rights();

    // Source must hold GRANT right to delegate.
    if !source_rights.contains(CapRights::GRANT) {
        return Err(CapError::GrantNotPermitted);
    }

    // Monotonic attenuation: requested must be a subset of source.
    if !source_rights.contains(requested_rights) {
        return Err(CapError::RightsEscalation);
    }

    // Delegation depth check.
    let new_depth = source.depth + 1;
    if new_depth > policy.max_depth {
        return Err(CapError::DelegationDepthExceeded);
    }

    let _ = badge; // Badge is carried by the slot, not the token.

    let derived_token = CapToken::new(
        new_id,
        source.token.cap_type(),
        requested_rights,
        epoch,
    );

    Ok((derived_token, new_depth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_types::{CapType, PartitionId};

    fn make_source(rights: CapRights, depth: u8) -> CapSlot {
        CapSlot {
            token: CapToken::new(1, CapType::Region, rights, 0),
            generation: 0,
            is_valid: true,
            owner: PartitionId::new(1),
            depth,
            parent_index: u32::MAX,
            badge: 0,
        }
    }

    fn all_rights() -> CapRights {
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
            .union(CapRights::GRANT)
            .union(CapRights::REVOKE)
    }

    #[test]
    fn test_valid_grant() {
        let source = make_source(all_rights(), 0);
        let policy = GrantPolicy::new();
        let (token, depth) = validate_grant(&source, CapRights::READ, 10, 42, 0, policy).unwrap();
        assert_eq!(token.rights(), CapRights::READ);
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_grant_without_grant_right() {
        let source = make_source(CapRights::READ, 0);
        let policy = GrantPolicy::new();
        let result = validate_grant(&source, CapRights::READ, 10, 0, 0, policy);
        assert_eq!(result, Err(CapError::GrantNotPermitted));
    }

    #[test]
    fn test_rights_escalation() {
        let source = make_source(CapRights::READ.union(CapRights::GRANT), 0);
        let policy = GrantPolicy::new();
        let result = validate_grant(&source, CapRights::WRITE, 10, 0, 0, policy);
        assert_eq!(result, Err(CapError::RightsEscalation));
    }

    #[test]
    fn test_depth_limit() {
        let source = make_source(all_rights(), 8);
        let policy = GrantPolicy::new();
        let result = validate_grant(&source, CapRights::READ, 10, 0, 0, policy);
        assert_eq!(result, Err(CapError::DelegationDepthExceeded));
    }

    #[test]
    fn test_grant_preserves_type() {
        let source = CapSlot {
            token: CapToken::new(1, CapType::CommEdge, all_rights(), 5),
            generation: 0,
            is_valid: true,
            owner: PartitionId::new(1),
            depth: 0,
            parent_index: u32::MAX,
            badge: 0,
        };
        let policy = GrantPolicy::new();
        let (token, _) = validate_grant(&source, CapRights::READ, 10, 0, 5, policy).unwrap();
        assert_eq!(token.cap_type(), CapType::CommEdge);
        assert_eq!(token.epoch(), 5);
    }

    #[test]
    fn test_grant_at_max_minus_one() {
        let source = make_source(all_rights(), 7);
        let policy = GrantPolicy::new();
        let (_, depth) = validate_grant(&source, CapRights::READ, 10, 0, 0, policy).unwrap();
        assert_eq!(depth, 8);
    }
}
