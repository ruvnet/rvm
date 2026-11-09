//! Strict cross-substrate authority continuity verification.
//!
//! This module binds decision-relevant security context across component
//! transitions without creating or widening execution authority. It is the first,
//! deliberately strict implementation of ADR-163: every authoritative field must
//! remain identical across the transition. A future, separately authenticated
//! release mechanism may relax individual fields, but no bypass is accepted here.
//!
//! The returned receipt is evidence only. Remote or durable use should seal it
//! through the existing RVM/RVF witness path.

/// Fixed-size digest used to bind an external security-context value.
pub type SecurityDigest = [u8; 32];

/// Security fields that strict continuity requires to remain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityField {
    /// Authenticated principal identity.
    Principal,
    /// Frozen task or operation scope.
    TaskScope,
    /// Root of provenance evidence relevant to the operation.
    ProvenanceRoot,
    /// Capability or delegated-rights scope.
    CapabilityScope,
    /// Active policy-state identity.
    PolicyState,
    /// Canonical semantic action identity.
    CanonicalAction,
    /// Boundary at which the external effect may occur.
    EffectBoundary,
    /// Capability revocation epoch.
    CapabilityEpoch,
}

/// Authoritative context that must survive a strict component transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityContext {
    /// Digest of the authenticated principal.
    pub principal: SecurityDigest,
    /// Digest of the frozen task scope.
    pub task_scope: SecurityDigest,
    /// Digest of the provenance root.
    pub provenance_root: SecurityDigest,
    /// Digest of the capability scope.
    pub capability_scope: SecurityDigest,
    /// Digest of the active policy state.
    pub policy_state: SecurityDigest,
    /// Digest of the canonical action.
    pub canonical_action: SecurityDigest,
    /// Digest of the permitted effect boundary.
    pub effect_boundary: SecurityDigest,
    /// Revocation epoch bound to the capability state.
    pub capability_epoch: u64,
}

/// Planner-visible context bound to a transition receipt.
///
/// These digests may legitimately differ because ordinary execution changes model
/// and workspace state. They are recorded for provenance but do not authorize a
/// change to [`SecurityContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionObservation {
    /// Digest of the planner-visible input context before the transition.
    pub input_context: SecurityDigest,
    /// Digest of the planner-visible output context after the transition.
    pub output_context: SecurityDigest,
}

/// Marker proving that this receipt carries no execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptAuthority {
    /// Evidence only. The receipt cannot grant or widen capability authority.
    None,
}

/// Evidence produced after a strict security-context continuity check passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictContinuityReceipt {
    /// Receipt format version.
    pub version: u8,
    /// Explicit authority marker. Always [`ReceiptAuthority::None`].
    pub authority: ReceiptAuthority,
    /// Authoritative context before the component transition.
    pub before: SecurityContext,
    /// Authoritative context after the component transition.
    pub after: SecurityContext,
    /// Planner-visible context evidence associated with the transition.
    pub observation: TransitionObservation,
}

/// Reason a strict continuity check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuityError {
    /// First authoritative field whose value changed.
    pub field: ContinuityField,
}

/// Verify that decision-relevant authority state remained exactly continuous.
///
/// This function does not consult a capability table and does not authorize the
/// external effect. Callers must separately validate the underlying RVM
/// capability or permit before mutation. Any change to an authoritative field
/// fails closed; there is intentionally no caller-controlled release bit.
///
/// # Errors
///
/// Returns [`ContinuityError`] naming the first authoritative field whose value
/// differs between `before` and `after`.
pub fn verify_strict_continuity(
    before: SecurityContext,
    after: SecurityContext,
    observation: TransitionObservation,
) -> Result<StrictContinuityReceipt, ContinuityError> {
    check_digest(
        before.principal,
        after.principal,
        ContinuityField::Principal,
    )?;
    check_digest(
        before.task_scope,
        after.task_scope,
        ContinuityField::TaskScope,
    )?;
    check_digest(
        before.provenance_root,
        after.provenance_root,
        ContinuityField::ProvenanceRoot,
    )?;
    check_digest(
        before.capability_scope,
        after.capability_scope,
        ContinuityField::CapabilityScope,
    )?;
    check_digest(
        before.policy_state,
        after.policy_state,
        ContinuityField::PolicyState,
    )?;
    check_digest(
        before.canonical_action,
        after.canonical_action,
        ContinuityField::CanonicalAction,
    )?;
    check_digest(
        before.effect_boundary,
        after.effect_boundary,
        ContinuityField::EffectBoundary,
    )?;
    if before.capability_epoch != after.capability_epoch {
        return Err(ContinuityError {
            field: ContinuityField::CapabilityEpoch,
        });
    }

    Ok(StrictContinuityReceipt {
        version: 1,
        authority: ReceiptAuthority::None,
        before,
        after,
        observation,
    })
}

fn check_digest(
    before: SecurityDigest,
    after: SecurityDigest,
    field: ContinuityField,
) -> Result<(), ContinuityError> {
    if before == after {
        Ok(())
    } else {
        Err(ContinuityError { field })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        verify_strict_continuity, ContinuityField, ReceiptAuthority, SecurityContext,
        TransitionObservation,
    };

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn context() -> SecurityContext {
        SecurityContext {
            principal: digest(1),
            task_scope: digest(2),
            provenance_root: digest(3),
            capability_scope: digest(4),
            policy_state: digest(5),
            canonical_action: digest(6),
            effect_boundary: digest(7),
            capability_epoch: 11,
        }
    }

    fn observation() -> TransitionObservation {
        TransitionObservation {
            input_context: digest(8),
            output_context: digest(9),
        }
    }

    #[test]
    fn unchanged_security_context_passes() {
        let receipt = verify_strict_continuity(context(), context(), observation())
            .expect("identical authoritative context should pass");
        assert_eq!(receipt.version, 1);
        assert_eq!(receipt.authority, ReceiptAuthority::None);
        assert_ne!(
            receipt.observation.input_context,
            receipt.observation.output_context
        );
    }

    #[test]
    fn principal_substitution_fails_closed() {
        let before = context();
        let mut after = before;
        after.principal = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("principal substitution must fail");
        assert_eq!(error.field, ContinuityField::Principal);
    }

    #[test]
    fn task_rebinding_fails_closed() {
        let before = context();
        let mut after = before;
        after.task_scope = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("task rebinding must fail");
        assert_eq!(error.field, ContinuityField::TaskScope);
    }

    #[test]
    fn provenance_discontinuity_fails_closed() {
        let before = context();
        let mut after = before;
        after.provenance_root = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("provenance discontinuity must fail");
        assert_eq!(error.field, ContinuityField::ProvenanceRoot);
    }

    #[test]
    fn capability_scope_change_fails_closed() {
        let before = context();
        let mut after = before;
        after.capability_scope = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("capability scope change must fail");
        assert_eq!(error.field, ContinuityField::CapabilityScope);
    }

    #[test]
    fn policy_downgrade_fails_closed() {
        let before = context();
        let mut after = before;
        after.policy_state = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("policy state change must fail");
        assert_eq!(error.field, ContinuityField::PolicyState);
    }

    #[test]
    fn canonical_action_reinterpretation_fails_closed() {
        let before = context();
        let mut after = before;
        after.canonical_action = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("canonical action change must fail");
        assert_eq!(error.field, ContinuityField::CanonicalAction);
    }

    #[test]
    fn effect_boundary_change_fails_closed() {
        let before = context();
        let mut after = before;
        after.effect_boundary = digest(42);
        let error = verify_strict_continuity(before, after, observation())
            .expect_err("effect boundary change must fail");
        assert_eq!(error.field, ContinuityField::EffectBoundary);
    }

    #[test]
    fn stale_or_new_epoch_fails_closed() {
        let before = context();
        for epoch in [before.capability_epoch - 1, before.capability_epoch + 1] {
            let mut after = before;
            after.capability_epoch = epoch;
            let error = verify_strict_continuity(before, after, observation())
                .expect_err("epoch changes require separate authenticated handling");
            assert_eq!(error.field, ContinuityField::CapabilityEpoch);
        }
    }
}
