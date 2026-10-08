//! Default-deny semantic mediation for trusted host integrations.
//!
//! This broker is not an OS sandbox or a Dogwood interpreter. The embedding
//! host must route every effect through it, provide live capability checks,
//! retain policy history across restarts, and prevent access to its executor.
//! Receipts must be durably accepted before an allowed effect is dispatched.

use alloc::vec::Vec;
use rvm_rvf::CapabilityClass;

/// A structured operation produced by a trusted protocol/language adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Execute one resolved program with exact arguments.
    Shell {
        /// Resolved program identity.
        program: alloc::string::String,
        /// Arguments, never shell text.
        args: Vec<alloc::string::String>,
    },
    /// Execute an identified Python payload through a mediated interpreter.
    Python([u8; 32]),
    /// Invoke a named MCP tool on a named server.
    Mcp {
        /// Server identity.
        server: alloc::string::String,
        /// Tool name.
        tool: alloc::string::String,
        /// Canonical input digest.
        input: [u8; 32],
    },
    /// Read a host-resolved resource.
    Read(alloc::string::String),
    /// Write a host-resolved resource.
    Write(alloc::string::String),
    /// Send an identified request to a canonical destination.
    Network {
        /// Canonical destination.
        destination: alloc::string::String,
        /// Canonical request digest.
        request: [u8; 32],
    },
}
impl Action {
    /// The live authority required before semantic policy is considered.
    #[must_use]
    pub const fn capability(&self) -> CapabilityClass {
        match self {
            Self::Shell { .. } | Self::Python(_) => CapabilityClass::Process,
            Self::Mcp { .. } => CapabilityClass::Mcp,
            Self::Read(_) | Self::Write(_) => CapabilityClass::Filesystem,
            Self::Network { .. } => CapabilityClass::Network,
        }
    }
}
/// Trusted execution identity. Obtain artifact identity from `VerifiedPackage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    /// Full RVF identity.
    pub artifact: [u8; 32],
    /// Agent instance identity; not supplied by guest input.
    pub instance: u64,
}
/// Complete receipt for export to an RVF witness/evidence sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Execution identity.
    pub subject: Subject,
    /// Pinned policy identity.
    pub policy: [u8; 32],
    /// Per-broker sequence.
    pub sequence: u64,
    /// Host monotonic time.
    pub now_ns: u64,
    /// Exact action being decided.
    pub action: Action,
    /// Decision, including failure reason.
    pub decision: Decision,
}
/// Explicit, default-deny decision reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Both live authority and semantic policy allowed the operation.
    Allow,
    /// Authority absent or revoked.
    CapabilityDenied,
    /// No policy rule permitted this action, or an explicit forbid applied.
    PolicyDenied,
    /// Policy service failed.
    PolicyUnavailable,
    /// Host time regressed.
    ClockRegressed,
}
/// Refusal before effect dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Recorded denial.
    Denied(Decision),
    /// Audit sink could not persist a receipt. No effect occurred.
    AuditUnavailable,
    /// Receipt sequence exhausted. No effect occurred.
    SequenceExhausted,
}
/// Trusted live capability lookup. Must enforce revocation and subject scope.
pub trait Authority {
    /// Check current authority, not a cached grant or a guest boolean.
    fn permits(&mut self, subject: Subject, class: CapabilityClass) -> bool;
}
/// Semantic policy engine boundary; may be backed by Dogwood in a host adapter.
pub trait Policy {
    /// Digest of the operator-authorized policy bytes.
    fn identity(&self) -> [u8; 32];
    /// Evaluate and atomically reserve history/quota before returning allow.
    ///
    /// `None` means unavailable and always denies. Allowed attempts remain
    /// charged even when audit or downstream execution fails.
    fn decide(&mut self, subject: Subject, action: &Action, now_ns: u64) -> Option<bool>;
}
/// Durable, fail-closed audit sink. Do not silently overwrite unread receipts.
pub trait Audit {
    /// Persist the full receipt before returning true.
    fn persist(&mut self, receipt: &Receipt) -> bool;
}
/// Private downstream effect handler owned by the broker.
pub trait Executor {
    /// Result returned by the effect handler, including execution failures.
    type Output;
    /// Dispatch the exact action that was authorized, without reinterpretation.
    fn execute(&mut self, action: &Action) -> Self::Output;
}
/// Single serialized authority, policy, audit, effect boundary.
///
/// This type deliberately exposes no executor accessor and no separate permit
/// token that could be replayed against changed arguments. Parallel hosts must
/// synchronize shared quota storage across brokers, not copy policy state.
pub struct Broker<A, P, W, E> {
    subject: Subject,
    authority: A,
    policy: P,
    audit: W,
    executor: E,
    sequence: u64,
    last_ns: u64,
}
impl<A: Authority, P: Policy, W: Audit, E: Executor> Broker<A, P, W, E> {
    /// Construct a trusted host boundary. Guests must not construct this type.
    pub fn new(subject: Subject, authority: A, policy: P, audit: W, executor: E) -> Self {
        Self {
            subject,
            authority,
            policy,
            audit,
            executor,
            sequence: 0,
            last_ns: 0,
        }
    }
    /// Check live authority, decide policy, persist evidence, then dispatch.
    ///
    /// # Errors
    /// Returns a refusal without invoking the executor on every failure path.
    pub fn dispatch(&mut self, action: Action, now_ns: u64) -> Result<E::Output, Refusal> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(Refusal::SequenceExhausted)?;
        let decision = if now_ns < self.last_ns {
            Decision::ClockRegressed
        } else if !self.authority.permits(self.subject, action.capability()) {
            Decision::CapabilityDenied
        } else {
            match self.policy.decide(self.subject, &action, now_ns) {
                Some(true) => Decision::Allow,
                Some(false) => Decision::PolicyDenied,
                None => Decision::PolicyUnavailable,
            }
        };
        self.last_ns = self.last_ns.max(now_ns);
        let receipt = Receipt {
            subject: self.subject,
            policy: self.policy.identity(),
            sequence: self.sequence,
            now_ns,
            action,
            decision,
        };
        self.sequence = next;
        if !self.audit.persist(&receipt) {
            return Err(Refusal::AuditUnavailable);
        }
        if decision != Decision::Allow {
            return Err(Refusal::Denied(decision));
        }
        Ok(self.executor.execute(&receipt.action))
    }
}
/// Exact-action rule. A forbid always wins, independent of rule order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Exact normalized action.
    pub action: Action,
    /// Whether this rule permits or forbids.
    pub permit: bool,
}
/// Bounded reference policy, not a replacement for the Dogwood language.
///
/// Its lifetime quota charges allowed attempts. Reuse one state per budget
/// scope; it is in-memory and must not be used for durable daily spend limits.
pub struct Rules {
    identity: [u8; 32],
    entries: Vec<Rule>,
    remaining: u64,
}
impl Rules {
    /// Operator-provided rules and lifetime attempt quota.
    #[must_use]
    pub fn new(identity: [u8; 32], rules: Vec<Rule>, attempts: u64) -> Self {
        Self {
            identity,
            entries: rules,
            remaining: attempts,
        }
    }
}
impl Policy for Rules {
    fn identity(&self) -> [u8; 32] {
        self.identity
    }
    fn decide(&mut self, _: Subject, action: &Action, _: u64) -> Option<bool> {
        if self.remaining == 0 {
            return Some(false);
        }
        let mut permitted = false;
        for entry in &self.entries {
            if &entry.action == action {
                if !entry.permit {
                    return Some(false);
                }
                permitted = true;
            }
        }
        if !permitted {
            return Some(false);
        }
        self.remaining -= 1;
        Some(true)
    }
}
/// Sliding-window attempt quota composed around a semantic engine.
///
/// Serializes check-and-reserve via exclusive access. In-memory state must be
/// retained for the entire budget window; durable multi-process limits belong
/// in a shared transactional policy engine. Denied actions consume no slots;
/// allowed attempts remain charged on audit or execution failure.
pub struct WindowQuota<P> {
    inner: P,
    limit: usize,
    window_ns: u64,
    admitted: Vec<u64>,
}
impl<P: Policy> WindowQuota<P> {
    /// Configure at most 4096 tracked attempts and a nonzero window.
    /// Returns `None` for an invalid budget, never an unlimited fallback.
    #[must_use]
    pub fn new(inner: P, limit: usize, window_ns: u64) -> Option<Self> {
        if limit == 0 || limit > 4096 || window_ns == 0 {
            return None;
        }
        Some(Self {
            inner,
            limit,
            window_ns,
            admitted: Vec::with_capacity(limit),
        })
    }
}
impl<P: Policy> Policy for WindowQuota<P> {
    fn identity(&self) -> [u8; 32] {
        self.inner.identity()
    }
    fn decide(&mut self, subject: Subject, action: &Action, now_ns: u64) -> Option<bool> {
        // Future entries indicate a regressing clock: refuse, never expire them.
        if self.admitted.iter().any(|at| *at > now_ns) {
            return None;
        }
        self.admitted.retain(|at| now_ns - *at < self.window_ns);
        if self.admitted.len() >= self.limit {
            return Some(false);
        }
        match self.inner.decide(subject, action, now_ns) {
            Some(true) => {
                self.admitted.push(now_ns);
                Some(true)
            }
            other => other,
        }
    }
}

/// Revision-bound prerequisite state for policies such as tests before push.
///
/// Only the trusted executor may mark success after observing exit status zero.
/// Every relevant workspace mutation must change the revision. An immutable
/// tree/content digest prevents branch switches and edits from reusing tests.
#[derive(Debug, Default)]
pub struct TestedRevision {
    passed: Option<([u8; 32], u64)>,
}
impl TestedRevision {
    /// Record a trusted test result, clearing previous success on failure.
    pub fn record(&mut self, revision: [u8; 32], now_ns: u64, success: bool) {
        self.passed = if success {
            Some((revision, now_ns))
        } else {
            None
        };
    }
    /// Require matching content, non-regressing time and bounded age.
    #[must_use]
    pub fn permits(&self, revision: [u8; 32], now_ns: u64, max_age_ns: u64) -> bool {
        self.passed.is_some_and(|(tested, at)| {
            tested == revision && now_ns.checked_sub(at).is_some_and(|age| age <= max_age_ns)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec};
    struct Auth(bool);
    impl Authority for Auth {
        fn permits(&mut self, _: Subject, _: CapabilityClass) -> bool {
            self.0
        }
    }
    #[derive(Default)]
    struct Sink {
        records: Vec<Receipt>,
        fail: bool,
    }
    impl Audit for Sink {
        fn persist(&mut self, r: &Receipt) -> bool {
            if self.fail {
                false
            } else {
                self.records.push(r.clone());
                true
            }
        }
    }
    #[derive(Default)]
    struct Effects(Vec<Action>);
    impl Executor for Effects {
        type Output = usize;
        fn execute(&mut self, a: &Action) -> usize {
            self.0.push(a.clone());
            self.0.len()
        }
    }
    fn action() -> Action {
        Action::Read(String::from("/project/readme"))
    }
    fn broker(allow: bool, rules: Vec<Rule>, quota: u64) -> Broker<Auth, Rules, Sink, Effects> {
        Broker::new(
            Subject {
                artifact: [1; 32],
                instance: 9,
            },
            Auth(allow),
            Rules::new([2; 32], rules, quota),
            Sink::default(),
            Effects::default(),
        )
    }
    fn permit() -> Rule {
        Rule {
            action: action(),
            permit: true,
        }
    }
    #[test]
    fn sliding_window_refuses_sixty_first_attempt_and_recovers_at_boundary() {
        let subject = Subject {
            artifact: [1; 32],
            instance: 1,
        };
        let policy = Rules::new([2; 32], vec![permit()], 1000);
        let mut q = WindowQuota::new(policy, 60, 100).unwrap();
        for _ in 0..60 {
            assert_eq!(q.decide(subject, &action(), 1), Some(true));
        }
        assert_eq!(q.decide(subject, &action(), 100), Some(false));
        assert_eq!(q.decide(subject, &action(), 0), None);
        assert_eq!(q.decide(subject, &action(), 101), Some(true));
        assert!(WindowQuota::new(Rules::new([0; 32], vec![], 1), 0, 1).is_none());
    }

    #[test]
    fn default_deny_and_forbid_precedence() {
        for rules in [
            vec![],
            vec![
                permit(),
                Rule {
                    action: action(),
                    permit: false,
                },
            ],
            vec![
                Rule {
                    action: action(),
                    permit: false,
                },
                permit(),
            ],
        ] {
            let mut b = broker(true, rules, 10);
            assert_eq!(
                b.dispatch(action(), 1),
                Err(Refusal::Denied(Decision::PolicyDenied))
            );
            assert_eq!(b.executor.0.len(), 0);
        }
    }
    #[test]
    fn live_revocation_wins_over_policy() {
        let mut b = broker(true, vec![permit()], 10);
        assert_eq!(b.dispatch(action(), 1), Ok(1));
        b.authority.0 = false;
        assert_eq!(
            b.dispatch(action(), 2),
            Err(Refusal::Denied(Decision::CapabilityDenied))
        );
        assert_eq!(b.executor.0.len(), 1);
        assert_eq!(b.policy.remaining, 9);
    }
    #[test]
    fn quota_is_reserved_before_dispatch_and_failed_audit_cannot_execute() {
        let mut b = broker(true, vec![permit()], 1);
        b.audit.fail = true;
        assert_eq!(b.dispatch(action(), 1), Err(Refusal::AuditUnavailable));
        b.audit.fail = false;
        assert_eq!(
            b.dispatch(action(), 2),
            Err(Refusal::Denied(Decision::PolicyDenied))
        );
        assert_eq!(b.executor.0.len(), 0);
    }
    #[test]
    fn exact_arguments_and_all_surfaces_are_default_denied() {
        let mut b = broker(true, vec![permit()], 10);
        for a in [
            Action::Shell {
                program: String::from("git"),
                args: vec![String::from("push")],
            },
            Action::Python([0; 32]),
            Action::Mcp {
                server: String::from("aws"),
                tool: String::from("pay"),
                input: [0; 32],
            },
            Action::Write(String::from("/project/readme")),
            Action::Network {
                destination: String::from("example.com"),
                request: [0; 32],
            },
        ] {
            assert!(b.dispatch(a, 1).is_err());
        }
        assert_eq!(b.executor.0.len(), 0);
    }
    #[test]
    fn receipts_bind_full_action_artifact_policy_and_sequence() {
        let mut b = broker(true, vec![permit()], 10);
        b.dispatch(action(), 3).unwrap();
        assert_eq!(
            b.audit.records[0],
            Receipt {
                subject: b.subject,
                policy: [2; 32],
                sequence: 0,
                now_ns: 3,
                action: action(),
                decision: Decision::Allow
            }
        );
        assert_eq!(
            b.dispatch(action(), 2),
            Err(Refusal::Denied(Decision::ClockRegressed))
        );
        assert_eq!(b.executor.0.len(), 1);
    }
    #[test]
    fn test_evidence_is_bound_to_revision_and_age_and_failure_clears_it() {
        let mut t = TestedRevision::default();
        assert!(!t.permits([1; 32], 1, 10));
        t.record([1; 32], 5, true);
        assert!(t.permits([1; 32], 15, 10));
        assert!(!t.permits([2; 32], 6, 10));
        assert!(!t.permits([1; 32], 4, 10));
        assert!(!t.permits([1; 32], 16, 10));
        t.record([1; 32], 6, false);
        assert!(!t.permits([1; 32], 7, 10));
    }
    #[test]
    fn unavailable_policy_and_exhausted_sequence_never_dispatch() {
        struct Offline;
        impl Policy for Offline {
            fn identity(&self) -> [u8; 32] {
                [0; 32]
            }
            fn decide(&mut self, _: Subject, _: &Action, _: u64) -> Option<bool> {
                None
            }
        }
        let mut b = Broker::new(
            Subject {
                artifact: [1; 32],
                instance: 1,
            },
            Auth(true),
            Offline,
            Sink::default(),
            Effects::default(),
        );
        assert_eq!(
            b.dispatch(action(), 1),
            Err(Refusal::Denied(Decision::PolicyUnavailable))
        );
        b.sequence = u64::MAX;
        assert_eq!(b.dispatch(action(), 2), Err(Refusal::SequenceExhausted));
        assert_eq!(b.executor.0.len(), 0);
    }
}
