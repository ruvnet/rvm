//! Monotonic data-flow labels and explicit egress budgets for governed context.
//!
//! This module protects a boundary that action-scoped capability checks alone
//! cannot express: whether data derived from sensitive runtime context may be
//! disclosed to a particular sink. Labels are evidence about data lineage, not
//! execution authority. An [`EgressBudget`] is likewise a policy input and does
//! not mint, widen, or replace an RVM capability.
//!
//! Version 1 intentionally has no declassification API. Transformations may
//! preserve or add sensitivity through [`FlowLabel::join`], but ordinary model,
//! tool, memory, summary, or delegation paths cannot remove a class.

use sha2::{Digest, Sha256};

/// Maximum number of parents accepted by one flow join.
pub const MAX_FLOW_PARENTS: usize = 64;

/// Maximum byte length of a source or transformation tag.
pub const MAX_FLOW_TAG_BYTES: usize = 4096;

const FLOW_SOURCE_DOMAIN: &[u8] = b"rvm-context-flow-source-v1";
const FLOW_DERIVE_DOMAIN: &[u8] = b"rvm-context-flow-derive-v1";
const FLOW_JOIN_DOMAIN: &[u8] = b"rvm-context-flow-join-v1";

/// Data classes propagated through model-facing context transformations.
///
/// The representation is deliberately compact so it can cross WASM, embedded,
/// and bare-metal boundaries without allocation. Unknown bits are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowClasses(u16);

impl FlowClasses {
    /// Public data that may be disclosed when the sink policy permits it.
    pub const PUBLIC: Self = Self(1 << 0);
    /// User or task input scoped to the current task.
    pub const TASK_INPUT: Self = Self(1 << 1);
    /// Ephemeral runtime context such as conversation or execution state.
    pub const RUNTIME_CONTEXT: Self = Self(1 << 2);
    /// Persistent memory or knowledge retrieved across task boundaries.
    pub const PERSISTENT_MEMORY: Self = Self(1 << 3);
    /// Tool names, descriptions, schemas, or other tool metadata.
    pub const TOOL_METADATA: Self = Self(1 << 4);
    /// Explicit secrets, credentials, or similarly restricted material.
    pub const SECRET: Self = Self(1 << 5);
    /// Every class understood by this contract version.
    pub const ALL: Self = Self(
        Self::PUBLIC.0
            | Self::TASK_INPUT.0
            | Self::RUNTIME_CONTEXT.0
            | Self::PERSISTENT_MEMORY.0
            | Self::TOOL_METADATA.0
            | Self::SECRET.0,
    );
    /// No data classes. Useful for a deny-all egress budget.
    pub const NONE: Self = Self(0);

    /// Construct a class set from raw bits, rejecting unknown classes.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the stable wire representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Return true when this set contains no classes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return the union of two class sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return true when every class in `self` is allowed by `other`.
    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// Return true when this set includes every class in `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        other.is_subset_of(self)
    }
}

/// Error returned by flow-label construction or transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    /// A source label was created without any data class.
    EmptyClasses,
    /// A task scope identifier was all zeroes.
    EmptyTaskScope,
    /// A sink identifier was all zeroes.
    EmptySink,
    /// A source or transformation tag was empty.
    EmptyTag,
    /// A source or transformation tag exceeded [`MAX_FLOW_TAG_BYTES`].
    TagTooLarge,
    /// A join was requested without parent labels.
    NoParents,
    /// A join exceeded [`MAX_FLOW_PARENTS`].
    TooManyParents,
    /// Parent labels from different task scopes were mixed.
    CrossTaskJoin,
}

/// Result type for flow operations.
pub type FlowResult<T> = core::result::Result<T, FlowError>;

/// Monotonic sensitivity and lineage attached to a context value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowLabel {
    classes: FlowClasses,
    task_scope: [u8; 32],
    lineage_hash: [u8; 32],
}

impl FlowLabel {
    /// Create a source label.
    ///
    /// `source_tag` should identify the originating evidence or artifact. It is
    /// hashed into the lineage and is never interpreted as authority.
    ///
    /// # Errors
    ///
    /// Rejects an empty class set, an all-zero task scope, an empty tag, or a
    /// tag larger than [`MAX_FLOW_TAG_BYTES`].
    pub fn source(
        classes: FlowClasses,
        task_scope: [u8; 32],
        source_tag: &[u8],
    ) -> FlowResult<Self> {
        validate_source(classes, &task_scope, source_tag)?;
        let tag_len = u16::try_from(source_tag.len()).map_err(|_| FlowError::TagTooLarge)?;
        let mut hasher = Sha256::new();
        hasher.update(FLOW_SOURCE_DOMAIN);
        hasher.update(classes.bits().to_be_bytes());
        hasher.update(task_scope);
        hasher.update(tag_len.to_be_bytes());
        hasher.update(source_tag);
        Ok(Self {
            classes,
            task_scope,
            lineage_hash: hasher.finalize().into(),
        })
    }

    /// Derive a child label while preserving all parent sensitivity classes.
    ///
    /// # Errors
    ///
    /// Rejects an empty transformation tag or a tag larger than
    /// [`MAX_FLOW_TAG_BYTES`].
    pub fn derive(&self, transform_tag: &[u8]) -> FlowResult<Self> {
        validate_tag(transform_tag)?;
        let tag_len = u16::try_from(transform_tag.len()).map_err(|_| FlowError::TagTooLarge)?;
        let mut hasher = Sha256::new();
        hasher.update(FLOW_DERIVE_DOMAIN);
        hasher.update(self.lineage_hash);
        hasher.update(self.classes.bits().to_be_bytes());
        hasher.update(tag_len.to_be_bytes());
        hasher.update(transform_tag);
        Ok(Self {
            classes: self.classes,
            task_scope: self.task_scope,
            lineage_hash: hasher.finalize().into(),
        })
    }

    /// Join multiple parents into one label, unioning every sensitivity class.
    ///
    /// Parent order is intentionally committed to the lineage because ordered
    /// transformations may have different semantics. No parent class can be
    /// removed by a join.
    ///
    /// # Errors
    ///
    /// Rejects zero parents, too many parents, mixed task scopes, or an invalid
    /// transformation tag.
    pub fn join(parents: &[Self], transform_tag: &[u8]) -> FlowResult<Self> {
        if parents.is_empty() {
            return Err(FlowError::NoParents);
        }
        if parents.len() > MAX_FLOW_PARENTS {
            return Err(FlowError::TooManyParents);
        }
        validate_tag(transform_tag)?;

        let parent_count = u8::try_from(parents.len()).map_err(|_| FlowError::TooManyParents)?;
        let tag_len = u16::try_from(transform_tag.len()).map_err(|_| FlowError::TagTooLarge)?;
        let task_scope = parents[0].task_scope;
        let mut classes = FlowClasses::NONE;
        for parent in parents {
            if parent.task_scope != task_scope {
                return Err(FlowError::CrossTaskJoin);
            }
            classes = classes.union(parent.classes);
        }

        let mut hasher = Sha256::new();
        hasher.update(FLOW_JOIN_DOMAIN);
        hasher.update([parent_count]);
        for parent in parents {
            hasher.update(parent.lineage_hash);
            hasher.update(parent.classes.bits().to_be_bytes());
        }
        hasher.update(tag_len.to_be_bytes());
        hasher.update(transform_tag);

        Ok(Self {
            classes,
            task_scope,
            lineage_hash: hasher.finalize().into(),
        })
    }

    /// Return the sensitivity classes carried by this value.
    #[must_use]
    pub const fn classes(&self) -> FlowClasses {
        self.classes
    }

    /// Return the exact task scope to which this value belongs.
    #[must_use]
    pub const fn task_scope(&self) -> &[u8; 32] {
        &self.task_scope
    }

    /// Return the deterministic evidence-lineage digest.
    #[must_use]
    pub const fn lineage_hash(&self) -> &[u8; 32] {
        &self.lineage_hash
    }
}

/// Reason recorded for an egress authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressDecision {
    /// The label fits the sink's explicit task scope and class budget.
    Allowed,
    /// The data belongs to a different task scope from the sink budget.
    TaskScopeMismatch,
    /// At least one sensitivity class is not allowed to reach the sink.
    ClassDenied,
}

impl EgressDecision {
    /// Return true only for an allowed disclosure decision.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Explicit disclosure budget for one sink and one task scope.
///
/// This object must be constructed from trusted policy state. Tool metadata,
/// model output, memory, and peer-agent messages must never be permitted to
/// manufacture or widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EgressBudget {
    sink_id: [u8; 32],
    task_scope: [u8; 32],
    allowed_classes: FlowClasses,
}

impl EgressBudget {
    /// Construct a sink-specific disclosure budget.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero sink identifier or task scope.
    pub fn new(
        sink_id: [u8; 32],
        task_scope: [u8; 32],
        allowed_classes: FlowClasses,
    ) -> FlowResult<Self> {
        if is_zero(&sink_id) {
            return Err(FlowError::EmptySink);
        }
        if is_zero(&task_scope) {
            return Err(FlowError::EmptyTaskScope);
        }
        Ok(Self {
            sink_id,
            task_scope,
            allowed_classes,
        })
    }

    /// Evaluate whether a labeled value may be disclosed to this sink.
    ///
    /// The method always returns a receipt so denied flows are as observable as
    /// allowed flows. Callers must still hold whatever RVM execution capability
    /// is required to invoke the sink.
    #[must_use]
    pub fn check(&self, label: &FlowLabel) -> EgressReceipt {
        let decision = if label.task_scope != self.task_scope {
            EgressDecision::TaskScopeMismatch
        } else if !label.classes.is_subset_of(self.allowed_classes) {
            EgressDecision::ClassDenied
        } else {
            EgressDecision::Allowed
        };
        EgressReceipt {
            sink_id: self.sink_id,
            task_scope: label.task_scope,
            lineage_hash: label.lineage_hash,
            classes: label.classes,
            decision,
        }
    }

    /// Return the sink identity committed by this budget.
    #[must_use]
    pub const fn sink_id(&self) -> &[u8; 32] {
        &self.sink_id
    }

    /// Return the task scope accepted by this budget.
    #[must_use]
    pub const fn task_scope(&self) -> &[u8; 32] {
        &self.task_scope
    }

    /// Return the maximum classes this sink may receive.
    #[must_use]
    pub const fn allowed_classes(&self) -> FlowClasses {
        self.allowed_classes
    }
}

/// Auditable result of checking one data label against one sink budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EgressReceipt {
    sink_id: [u8; 32],
    task_scope: [u8; 32],
    lineage_hash: [u8; 32],
    classes: FlowClasses,
    decision: EgressDecision,
}

impl EgressReceipt {
    /// Return the sink identity that was checked.
    #[must_use]
    pub const fn sink_id(&self) -> &[u8; 32] {
        &self.sink_id
    }

    /// Return the task scope carried by the candidate data.
    #[must_use]
    pub const fn task_scope(&self) -> &[u8; 32] {
        &self.task_scope
    }

    /// Return the evidence lineage of the candidate data.
    #[must_use]
    pub const fn lineage_hash(&self) -> &[u8; 32] {
        &self.lineage_hash
    }

    /// Return the data classes presented to the sink policy.
    #[must_use]
    pub const fn classes(&self) -> FlowClasses {
        self.classes
    }

    /// Return the policy decision.
    #[must_use]
    pub const fn decision(&self) -> EgressDecision {
        self.decision
    }
}

fn validate_source(classes: FlowClasses, task_scope: &[u8; 32], tag: &[u8]) -> FlowResult<()> {
    if classes.is_empty() {
        return Err(FlowError::EmptyClasses);
    }
    if is_zero(task_scope) {
        return Err(FlowError::EmptyTaskScope);
    }
    validate_tag(tag)
}

fn validate_tag(tag: &[u8]) -> FlowResult<()> {
    if tag.is_empty() {
        return Err(FlowError::EmptyTag);
    }
    if tag.len() > MAX_FLOW_TAG_BYTES {
        return Err(FlowError::TagTooLarge);
    }
    Ok(())
}

const fn is_zero(value: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < value.len() {
        if value[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const TASK_A: [u8; 32] = [1; 32];
    const TASK_B: [u8; 32] = [2; 32];
    const SINK: [u8; 32] = [7; 32];

    fn source(classes: FlowClasses) -> FlowLabel {
        FlowLabel::source(classes, TASK_A, b"source").expect("valid source")
    }

    #[test]
    fn permits_only_explicitly_budgeted_classes() {
        let label = source(FlowClasses::TASK_INPUT);
        let budget = EgressBudget::new(SINK, TASK_A, FlowClasses::TASK_INPUT).unwrap();
        assert_eq!(budget.check(&label).decision(), EgressDecision::Allowed);
    }

    #[test]
    fn runtime_context_is_denied_without_explicit_budget() {
        let label = source(FlowClasses::RUNTIME_CONTEXT);
        let budget = EgressBudget::new(SINK, TASK_A, FlowClasses::TASK_INPUT).unwrap();
        assert_eq!(budget.check(&label).decision(), EgressDecision::ClassDenied);
    }

    #[test]
    fn task_scope_mismatch_fails_closed() {
        let label = source(FlowClasses::TASK_INPUT);
        let budget = EgressBudget::new(SINK, TASK_B, FlowClasses::ALL).unwrap();
        assert_eq!(
            budget.check(&label).decision(),
            EgressDecision::TaskScopeMismatch
        );
    }

    #[test]
    fn derivation_preserves_classes_and_changes_lineage() {
        let parent = source(FlowClasses::RUNTIME_CONTEXT);
        let child = parent.derive(b"summary").unwrap();
        assert_eq!(child.classes(), parent.classes());
        assert_ne!(child.lineage_hash(), parent.lineage_hash());
    }

    #[test]
    fn join_unions_sensitivity() {
        let task = source(FlowClasses::TASK_INPUT);
        let memory = source(FlowClasses::PERSISTENT_MEMORY);
        let joined = FlowLabel::join(&[task, memory], b"compose").unwrap();
        assert!(joined.classes().contains(FlowClasses::TASK_INPUT));
        assert!(joined.classes().contains(FlowClasses::PERSISTENT_MEMORY));
    }

    #[test]
    fn cross_task_join_is_rejected() {
        let a = source(FlowClasses::TASK_INPUT);
        let b = FlowLabel::source(FlowClasses::PUBLIC, TASK_B, b"other").unwrap();
        assert_eq!(
            FlowLabel::join(&[a, b], b"compose"),
            Err(FlowError::CrossTaskJoin)
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert_eq!(
            FlowLabel::source(FlowClasses::NONE, TASK_A, b"source"),
            Err(FlowError::EmptyClasses)
        );
        assert_eq!(
            FlowLabel::source(FlowClasses::PUBLIC, [0; 32], b"source"),
            Err(FlowError::EmptyTaskScope)
        );
        assert_eq!(
            FlowLabel::source(FlowClasses::PUBLIC, TASK_A, b""),
            Err(FlowError::EmptyTag)
        );
        assert!(FlowClasses::from_bits(FlowClasses::ALL.bits() | (1 << 15)).is_none());
    }

    #[test]
    fn tool_metadata_cannot_widen_an_egress_budget() {
        let task = source(FlowClasses::TASK_INPUT);
        let metadata = source(FlowClasses::TOOL_METADATA);
        let influenced = FlowLabel::join(&[task, metadata], b"tool-call-arguments").unwrap();
        let budget = EgressBudget::new(SINK, TASK_A, FlowClasses::TASK_INPUT).unwrap();
        assert_eq!(
            budget.check(&influenced).decision(),
            EgressDecision::ClassDenied
        );
    }

    #[test]
    fn deny_all_budget_denies_even_public_data() {
        let label = source(FlowClasses::PUBLIC);
        let budget = EgressBudget::new(SINK, TASK_A, FlowClasses::NONE).unwrap();
        assert!(!budget.check(&label).decision().is_allowed());
    }

    #[test]
    fn parent_limit_blocks_resource_exhaustion() {
        let parent = source(FlowClasses::PUBLIC);
        let parents = vec![parent; MAX_FLOW_PARENTS + 1];
        assert_eq!(
            FlowLabel::join(&parents, b"too-many"),
            Err(FlowError::TooManyParents)
        );
    }
}
