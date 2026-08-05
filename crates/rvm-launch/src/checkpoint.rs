//! Checkpoints, and the lineage binding that makes them refusable.
//!
//! ADR-288 §4 states the rule this module exists to enforce: *every delta and
//! every checkpoint carries the base RVF identity it belongs to*, and on open
//! the runtime compares that against the base it actually loaded. A mismatch
//! is a **lineage rejection** — the state is refused, execution does not begin
//! with partial state, and the rejection goes into the witness chain.
//!
//! The cases that motivate it are not exotic. State copied between two agents,
//! state carried across an unrelated RVF that happens to share an application
//! name, and state that survives a base-artifact substitution all look like
//! ordinary state until the identity is checked.
//!
//! # Instance identity is provenance, not a gate
//!
//! A checkpoint also records the instance that produced it, but restoring into
//! a *different* instance is allowed. ADR-289 acceptance criterion 7 requires
//! exactly that: suspend under one host adapter, checkpoint, resume under
//! another. The instance on the far side is a new one by construction, so
//! gating on instance identity would forbid the behaviour the ADR requires.
//! The origin travels in the restore record instead, where an auditor can see
//! the handoff.

use crate::state::{InstanceId, InstanceState};
use rvm_types::fnv1a_32;

/// A resumable snapshot, bound to the base RVF it was produced under.
///
/// This is the `CompressedCheckpoint` role of ADR-288 §3 at the lifecycle
/// layer: the metadata that decides whether a snapshot may be applied at all.
/// Serializing the guest's linear memory and quota cursors is `rvm-state`
/// work; what lives here is the binding, because that is what the lifecycle
/// layer has to check before it hands anything to a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    base_identity: [u8; 32],
    origin: InstanceId,
    sequence: u32,
    captured_state: InstanceState,
    memory_pages: u32,
    witness_sequence: u64,
}

impl Checkpoint {
    /// Capture a checkpoint for `origin` running `base_identity`.
    #[must_use]
    pub const fn new(
        base_identity: [u8; 32],
        origin: InstanceId,
        sequence: u32,
        captured_state: InstanceState,
        memory_pages: u32,
        witness_sequence: u64,
    ) -> Self {
        Self {
            base_identity,
            origin,
            sequence,
            captured_state,
            memory_pages,
            witness_sequence,
        }
    }

    /// The base RVF identity this state belongs to.
    #[must_use]
    pub const fn base_identity(&self) -> &[u8; 32] {
        &self.base_identity
    }

    /// The instance that produced it.
    #[must_use]
    pub const fn origin(&self) -> InstanceId {
        self.origin
    }

    /// Which checkpoint this is for that instance, counting from zero.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// The state the instance was in when it was captured.
    #[must_use]
    pub const fn captured_state(&self) -> InstanceState {
        self.captured_state
    }

    /// The memory-page quota in force at capture.
    #[must_use]
    pub const fn memory_pages(&self) -> u32 {
        self.memory_pages
    }

    /// The witness sequence the log had reached at capture, which is where
    /// reconstruction replays deltas from.
    #[must_use]
    pub const fn witness_sequence(&self) -> u64 {
        self.witness_sequence
    }

    /// Whether this checkpoint belongs to the RVF identified by `identity`.
    #[must_use]
    pub fn belongs_to(&self, identity: &[u8; 32]) -> bool {
        &self.base_identity == identity
    }

    /// A short, stable tag for the lineage, for witness detail words.
    #[must_use]
    pub fn lineage_tag(&self) -> u32 {
        fnv1a_32(&self.base_identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(identity: [u8; 32]) -> Checkpoint {
        Checkpoint::new(
            identity,
            InstanceId::new(1),
            0,
            InstanceState::Suspended,
            16,
            42,
        )
    }

    #[test]
    fn a_checkpoint_belongs_only_to_the_identity_it_was_captured_under() {
        let cp = checkpoint([1u8; 32]);
        assert!(cp.belongs_to(&[1u8; 32]));
        assert!(!cp.belongs_to(&[2u8; 32]));
    }

    #[test]
    fn a_single_flipped_bit_in_the_identity_breaks_the_binding() {
        let cp = checkpoint([0u8; 32]);
        let mut near_miss = [0u8; 32];
        near_miss[31] = 1;
        assert!(!cp.belongs_to(&near_miss));
    }

    #[test]
    fn different_lineages_have_different_tags() {
        assert_ne!(
            checkpoint([1u8; 32]).lineage_tag(),
            checkpoint([2u8; 32]).lineage_tag()
        );
        assert_eq!(
            checkpoint([1u8; 32]).lineage_tag(),
            checkpoint([1u8; 32]).lineage_tag()
        );
    }

    #[test]
    fn a_checkpoint_records_where_it_came_from() {
        let cp = checkpoint([5u8; 32]);
        assert_eq!(cp.origin(), InstanceId::new(1));
        assert_eq!(cp.sequence(), 0);
        assert_eq!(cp.captured_state(), InstanceState::Suspended);
        assert_eq!(cp.memory_pages(), 16);
        assert_eq!(cp.witness_sequence(), 42);
    }

    #[test]
    fn two_checkpoints_of_the_same_lineage_differ_only_by_sequence() {
        let first = checkpoint([7u8; 32]);
        let second = Checkpoint::new(
            [7u8; 32],
            InstanceId::new(1),
            1,
            InstanceState::Suspended,
            16,
            43,
        );
        assert_ne!(first, second);
        assert_eq!(first.base_identity(), second.base_identity());
        assert_eq!(second.sequence(), first.sequence() + 1);
    }
}
