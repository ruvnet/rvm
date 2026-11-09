//! Observation-scoped execution prefix selection for already-authorized actions.
//!
//! This module deliberately does not authorize effects. It constrains how many
//! actions a host may batch before it must obtain a fresh observation and rerun
//! the ordinary RVM authorization path for each action.

/// One million parts per million, representing probability one.
pub const RISK_PPM_MAX: u32 = 1_000_000;

/// A fixed digest used to bind policy, evaluator, observations, and actions.
pub type PrefixDigest = [u8; 32];

/// Host-owned limits for one observation-scoped execution prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptiblePrefixPolicy {
    /// Maximum actions that may be dispatched before a fresh observation.
    pub max_steps: u16,
    /// Maximum cumulative estimated failure risk in parts per million.
    pub max_cumulative_risk_ppm: u32,
    /// Maximum estimated failure risk for any individual action.
    pub max_step_risk_ppm: u32,
    /// Maximum accepted age of the evidence used to assess the actions.
    pub max_observation_age_ticks: u64,
    /// Capability epoch that must still be current at selection time.
    pub required_capability_epoch: u64,
    /// Digest of the independently selected risk and execution policy.
    pub policy_digest: PrefixDigest,
    /// Digest of the independently selected evaluator implementation.
    pub evaluator_digest: PrefixDigest,
}

/// Evidence about one proposed action under a shared observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssessedAction {
    /// Canonical digest of the action and its material parameters.
    pub action_digest: PrefixDigest,
    /// Estimated action failure risk in parts per million.
    pub estimated_failure_risk_ppm: u32,
    /// Whether current evidence says the action precondition still holds.
    pub precondition_met: bool,
    /// Whether the host can fully undo the action if the next observation invalidates the plan.
    pub reversible: bool,
}

/// Shared evidence under which a sequence of actions was assessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixAssessment<'a> {
    /// Tick at which the shared observation was captured.
    pub observation_tick: u64,
    /// Digest of the observation or state snapshot used for assessment.
    pub observation_digest: PrefixDigest,
    /// Capability epoch observed by the assessment path.
    pub capability_epoch: u64,
    /// Policy digest used by the assessment path.
    pub policy_digest: PrefixDigest,
    /// Evaluator digest used by the assessment path.
    pub evaluator_digest: PrefixDigest,
    /// Ordered actions proposed under this observation.
    pub actions: &'a [AssessedAction],
}

/// Why selection stopped before dispatching another action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixStopReason {
    /// Every proposed action fits the policy and evidence boundary.
    Complete,
    /// The host-owned maximum prefix length was reached.
    MaxSteps,
    /// Adding the next action would exceed the cumulative risk budget.
    CumulativeRisk,
    /// The next action exceeds the per-action risk ceiling.
    StepRisk,
    /// Current evidence says the next action precondition is not satisfied.
    PreconditionFailed,
    /// The next action is not reversible and therefore cannot be batched.
    IrreversibleBoundary,
    /// The assessment observation is older than policy permits.
    StaleObservation,
    /// The assessment came from a different capability epoch.
    CapabilityEpochMismatch,
    /// The assessment used a different policy.
    PolicyMismatch,
    /// The assessment used a different evaluator.
    EvaluatorMismatch,
    /// Policy or evidence is malformed and the entire prefix is rejected.
    InvalidInput,
}

/// Deterministic result of prefix selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixDecision {
    /// Number of actions from the start of the sequence that may be considered for dispatch.
    ///
    /// Each selected action still requires ordinary RVM authorization. This field grants no capability.
    pub dispatch_steps: u16,
    /// Sum of estimated failure risk across the selected actions.
    pub cumulative_risk_ppm: u32,
    /// Reason no additional action was selected.
    pub stop_reason: PrefixStopReason,
}

impl PrefixDecision {
    const fn reject(reason: PrefixStopReason) -> Self {
        Self {
            dispatch_steps: 0,
            cumulative_risk_ppm: 0,
            stop_reason: reason,
        }
    }
}

/// Select the maximal reversible action prefix allowed by a host-owned policy.
///
/// `current_tick` and `current_capability_epoch` must come from trusted host state.
/// Risk estimates and precondition results are evidence only. A positive decision
/// never authorizes an effect and must be composed with the ordinary RVM capability
/// gate for every selected action.
#[must_use]
pub fn select_interruptible_prefix(
    policy: &InterruptiblePrefixPolicy,
    assessment: &PrefixAssessment<'_>,
    current_tick: u64,
    current_capability_epoch: u64,
) -> PrefixDecision {
    if !valid_policy(policy) || !valid_assessment(assessment) {
        return PrefixDecision::reject(PrefixStopReason::InvalidInput);
    }
    if current_tick < assessment.observation_tick {
        return PrefixDecision::reject(PrefixStopReason::InvalidInput);
    }
    if current_capability_epoch != policy.required_capability_epoch
        || assessment.capability_epoch != current_capability_epoch
    {
        return PrefixDecision::reject(PrefixStopReason::CapabilityEpochMismatch);
    }
    if assessment.policy_digest != policy.policy_digest {
        return PrefixDecision::reject(PrefixStopReason::PolicyMismatch);
    }
    if assessment.evaluator_digest != policy.evaluator_digest {
        return PrefixDecision::reject(PrefixStopReason::EvaluatorMismatch);
    }
    if current_tick - assessment.observation_tick > policy.max_observation_age_ticks {
        return PrefixDecision::reject(PrefixStopReason::StaleObservation);
    }

    let mut selected = 0_u16;
    let mut cumulative = 0_u32;

    for action in assessment.actions {
        if selected >= policy.max_steps {
            return decision(selected, cumulative, PrefixStopReason::MaxSteps);
        }
        if !action.precondition_met {
            return decision(selected, cumulative, PrefixStopReason::PreconditionFailed);
        }
        if !action.reversible {
            return decision(selected, cumulative, PrefixStopReason::IrreversibleBoundary);
        }
        if action.estimated_failure_risk_ppm > policy.max_step_risk_ppm {
            return decision(selected, cumulative, PrefixStopReason::StepRisk);
        }
        let Some(next_risk) = cumulative.checked_add(action.estimated_failure_risk_ppm) else {
            return PrefixDecision::reject(PrefixStopReason::InvalidInput);
        };
        if next_risk > policy.max_cumulative_risk_ppm {
            return decision(selected, cumulative, PrefixStopReason::CumulativeRisk);
        }
        cumulative = next_risk;
        selected = selected.saturating_add(1);
    }

    decision(selected, cumulative, PrefixStopReason::Complete)
}

const fn decision(
    dispatch_steps: u16,
    cumulative_risk_ppm: u32,
    stop_reason: PrefixStopReason,
) -> PrefixDecision {
    PrefixDecision {
        dispatch_steps,
        cumulative_risk_ppm,
        stop_reason,
    }
}

fn valid_policy(policy: &InterruptiblePrefixPolicy) -> bool {
    policy.max_steps > 0
        && policy.max_cumulative_risk_ppm <= RISK_PPM_MAX
        && policy.max_step_risk_ppm <= RISK_PPM_MAX
        && policy.max_step_risk_ppm <= policy.max_cumulative_risk_ppm
        && !zero_digest(&policy.policy_digest)
        && !zero_digest(&policy.evaluator_digest)
}

fn valid_assessment(assessment: &PrefixAssessment<'_>) -> bool {
    !zero_digest(&assessment.observation_digest)
        && !zero_digest(&assessment.policy_digest)
        && !zero_digest(&assessment.evaluator_digest)
        && u16::try_from(assessment.actions.len()).is_ok()
        && assessment.actions.iter().all(|action| {
            !zero_digest(&action.action_digest)
                && action.estimated_failure_risk_ppm <= RISK_PPM_MAX
        })
}

fn zero_digest(digest: &PrefixDigest) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::{
        select_interruptible_prefix, AssessedAction, InterruptiblePrefixPolicy, PrefixAssessment,
        PrefixDecision, PrefixStopReason,
    };

    const POLICY: [u8; 32] = [1; 32];
    const EVALUATOR: [u8; 32] = [2; 32];
    const OBSERVATION: [u8; 32] = [3; 32];

    fn policy() -> InterruptiblePrefixPolicy {
        InterruptiblePrefixPolicy {
            max_steps: 4,
            max_cumulative_risk_ppm: 120_000,
            max_step_risk_ppm: 60_000,
            max_observation_age_ticks: 10,
            required_capability_epoch: 7,
            policy_digest: POLICY,
            evaluator_digest: EVALUATOR,
        }
    }

    fn action(id: u8, risk: u32) -> AssessedAction {
        AssessedAction {
            action_digest: [id; 32],
            estimated_failure_risk_ppm: risk,
            precondition_met: true,
            reversible: true,
        }
    }

    fn assessment<'a>(actions: &'a [AssessedAction]) -> PrefixAssessment<'a> {
        PrefixAssessment {
            observation_tick: 100,
            observation_digest: OBSERVATION,
            capability_epoch: 7,
            policy_digest: POLICY,
            evaluator_digest: EVALUATOR,
            actions,
        }
    }

    #[test]
    fn selects_maximal_prefix_under_cumulative_budget() {
        let actions = [action(1, 30_000), action(2, 40_000), action(3, 60_000)];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 7);
        assert_eq!(
            result,
            PrefixDecision {
                dispatch_steps: 2,
                cumulative_risk_ppm: 70_000,
                stop_reason: PrefixStopReason::CumulativeRisk,
            }
        );
    }

    #[test]
    fn maximum_step_count_forces_refresh() {
        let actions = [
            action(1, 10_000),
            action(2, 10_000),
            action(3, 10_000),
            action(4, 10_000),
            action(5, 10_000),
        ];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 7);
        assert_eq!(result.dispatch_steps, 4);
        assert_eq!(result.stop_reason, PrefixStopReason::MaxSteps);
    }

    #[test]
    fn stale_observation_rejects_whole_prefix() {
        let actions = [action(1, 10_000)];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 111, 7);
        assert_eq!(result, PrefixDecision::reject(PrefixStopReason::StaleObservation));
    }

    #[test]
    fn capability_epoch_mismatch_rejects_whole_prefix() {
        let actions = [action(1, 10_000)];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 8);
        assert_eq!(
            result,
            PrefixDecision::reject(PrefixStopReason::CapabilityEpochMismatch)
        );
    }

    #[test]
    fn policy_and_evaluator_substitution_fail_closed() {
        let actions = [action(1, 10_000)];
        let mut wrong_policy = assessment(&actions);
        wrong_policy.policy_digest = [9; 32];
        assert_eq!(
            select_interruptible_prefix(&policy(), &wrong_policy, 105, 7).stop_reason,
            PrefixStopReason::PolicyMismatch
        );

        let mut wrong_evaluator = assessment(&actions);
        wrong_evaluator.evaluator_digest = [8; 32];
        assert_eq!(
            select_interruptible_prefix(&policy(), &wrong_evaluator, 105, 7).stop_reason,
            PrefixStopReason::EvaluatorMismatch
        );
    }

    #[test]
    fn changed_precondition_stops_before_action() {
        let mut second = action(2, 10_000);
        second.precondition_met = false;
        let actions = [action(1, 10_000), second, action(3, 10_000)];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 7);
        assert_eq!(result.dispatch_steps, 1);
        assert_eq!(result.stop_reason, PrefixStopReason::PreconditionFailed);
    }

    #[test]
    fn irreversible_action_is_never_batched() {
        let mut second = action(2, 10_000);
        second.reversible = false;
        let actions = [action(1, 10_000), second];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 7);
        assert_eq!(result.dispatch_steps, 1);
        assert_eq!(result.stop_reason, PrefixStopReason::IrreversibleBoundary);
    }

    #[test]
    fn individual_risk_limit_stops_before_action() {
        let actions = [action(1, 61_000)];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 7);
        assert_eq!(result.dispatch_steps, 0);
        assert_eq!(result.stop_reason, PrefixStopReason::StepRisk);
    }

    #[test]
    fn malformed_digests_and_out_of_range_risk_fail_closed() {
        let mut malformed = action(1, 10_000);
        malformed.action_digest = [0; 32];
        let malformed_actions = [malformed];
        assert_eq!(
            select_interruptible_prefix(&policy(), &assessment(&malformed_actions), 105, 7)
                .stop_reason,
            PrefixStopReason::InvalidInput
        );

        let over_range_actions = [action(1, 1_000_001)];
        assert_eq!(
            select_interruptible_prefix(&policy(), &assessment(&over_range_actions), 105, 7)
                .stop_reason,
            PrefixStopReason::InvalidInput
        );
    }

    #[test]
    fn complete_prefix_reports_exact_risk() {
        let actions = [action(1, 20_000), action(2, 30_000)];
        let result = select_interruptible_prefix(&policy(), &assessment(&actions), 105, 7);
        assert_eq!(result.dispatch_steps, 2);
        assert_eq!(result.cumulative_risk_ppm, 50_000);
        assert_eq!(result.stop_reason, PrefixStopReason::Complete);
    }
}
