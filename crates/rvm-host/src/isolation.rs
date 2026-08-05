//! What isolation an adapter actually obtained, and why it cannot overstate it.
//!
//! ADR-285 is a decision about vocabulary as much as about mechanism: hosted
//! RVM is a normal desktop process with the user's ambient authority, and the
//! failure mode the ADR exists to prevent is describing it in bare-metal terms.
//! So [`IsolationClaim`] is never something an adapter *asserts*. It is
//! [derived](IsolationClaim::derive) from two things the adapter cannot fake
//! cheaply:
//!
//! 1. its [`HostEnvironment`], where the bare-metal variant can only be built
//!    from a [`PartitionEvidence`] that in turn requires a live partition in a
//!    real [`PartitionManager`]; and
//! 2. its [`MechanismSet`], where the `OsSandboxWasm` claim requires an
//!    *engaged* mechanism belonging to the operating system it is running on.
//!
//! A hosted process has no partition manager, so it cannot produce the
//! evidence, so [`IsolationClaim::derive`] has no branch that can return
//! [`IsolationClaim::Partition`] for it. That is the encoding: the honest
//! answer is the only reachable one.

use crate::mechanism::{HostOs, MechanismSet};
use core::fmt;
use rvm_partition::{PartitionId, PartitionManager};

/// Proof that the caller holds a live partition.
///
/// The only constructor takes a [`PartitionManager`] and checks that the
/// partition is actually in it. This is what stands between "I am bare metal"
/// and being able to say so: a hosted desktop process has no partition
/// manager, and a synthesized [`rvm_partition::Partition`] value is not
/// enough, because it was never registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionEvidence {
    partition: PartitionId,
}

impl PartitionEvidence {
    /// Evidence that `partition` is live in `manager`.
    ///
    /// Returns `None` when the manager does not hold it, which is the case a
    /// caller must not be able to talk its way past.
    #[must_use]
    pub fn from_manager(manager: &PartitionManager, partition: PartitionId) -> Option<Self> {
        manager.get(partition).map(|_| Self { partition })
    }

    /// The partition this evidence is about.
    #[must_use]
    pub const fn partition(self) -> PartitionId {
        self.partition
    }
}

/// Where an adapter is running.
///
/// A struct wrapping a private enum, so the bare-metal case cannot be written
/// by a caller who does not hold [`PartitionEvidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEnvironment {
    kind: EnvironmentKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvironmentKind {
    BareMetal(PartitionEvidence),
    Hosted(HostOs),
    Portable,
}

impl HostEnvironment {
    /// A WASM runtime with no operating-system integration: the browser, an
    /// embedded interpreter, or a build that has not wired one up.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            kind: EnvironmentKind::Portable,
        }
    }

    /// A normal desktop process on `os`.
    #[must_use]
    pub const fn hosted(os: HostOs) -> Self {
        Self {
            kind: EnvironmentKind::Hosted(os),
        }
    }

    /// Bare-metal RVM, holding the partition the agent will run in.
    #[must_use]
    pub const fn bare_metal(evidence: PartitionEvidence) -> Self {
        Self {
            kind: EnvironmentKind::BareMetal(evidence),
        }
    }

    /// The operating system, for a hosted environment.
    #[must_use]
    pub const fn host_os(self) -> Option<HostOs> {
        match self.kind {
            EnvironmentKind::Hosted(os) => Some(os),
            _ => None,
        }
    }

    /// Whether this is bare-metal RVM.
    #[must_use]
    pub const fn is_bare_metal(self) -> bool {
        matches!(self.kind, EnvironmentKind::BareMetal(_))
    }

    /// Whether this is a hosted desktop process.
    #[must_use]
    pub const fn is_hosted(self) -> bool {
        matches!(self.kind, EnvironmentKind::Hosted(_))
    }

    /// The partition backing a bare-metal environment.
    #[must_use]
    pub const fn partition(self) -> Option<PartitionId> {
        match self.kind {
            EnvironmentKind::BareMetal(e) => Some(e.partition()),
            _ => None,
        }
    }

    /// The stable name, for witness aux data and operator output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.kind {
            EnvironmentKind::BareMetal(_) => "bare-metal",
            EnvironmentKind::Hosted(_) => "hosted",
            EnvironmentKind::Portable => "portable",
        }
    }
}

impl fmt::Display for HostEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EnvironmentKind::Hosted(os) => write!(f, "hosted/{os}"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// The isolation an adapter obtained, as reported to the witness chain and the
/// operator.
///
/// | Claim | Boundary |
/// |---|---|
/// | [`Partition`](Self::Partition) | stage-2 partition memory isolation, capability tables, device leases, measured boot, witnessed security gates |
/// | [`OsSandboxWasm`](Self::OsSandboxWasm) | WASM isolation plus the operating system's confinement of the host process |
/// | [`WasmOnly`](Self::WasmOnly) | WASM isolation, default-deny capabilities, and quotas — nothing beneath |
///
/// `Partition` is not a stronger label for the same thing; it is a different
/// boundary. Hosted execution reports `OsSandboxWasm` at best, and degrades to
/// `WasmOnly` when no operating-system mechanism actually engaged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsolationClaim {
    /// Bare-metal RVM partition isolation.
    Partition,
    /// Operating-system confinement composed under WASM isolation.
    OsSandboxWasm,
    /// WASM isolation alone.
    WasmOnly,
}

impl IsolationClaim {
    /// Derive the claim from where the adapter runs and what it engaged.
    ///
    /// The three branches are exhaustive and none of them can produce
    /// [`Self::Partition`] for a hosted or portable environment. That is the
    /// ADR-285 rule expressed as control flow rather than as a review comment.
    #[must_use]
    pub fn derive(environment: HostEnvironment, mechanisms: &MechanismSet) -> Self {
        // A hosted environment returns here, before the bare-metal case is
        // ever reached. Its best answer is `OsSandboxWasm`, and it earns even
        // that only by engaging a mechanism belonging to the operating system
        // it is running on: a declared stack that did not take hold is WASM
        // and nothing else.
        if let Some(os) = environment.host_os() {
            return if mechanisms.any_os_confinement_engaged(os) {
                Self::OsSandboxWasm
            } else {
                Self::WasmOnly
            };
        }
        if environment.is_bare_metal() {
            return Self::Partition;
        }
        Self::WasmOnly
    }

    /// Whether this claim asserts a hypervisor-class boundary.
    #[must_use]
    pub const fn is_bare_metal(self) -> bool {
        matches!(self, Self::Partition)
    }

    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Partition => "partition",
            Self::OsSandboxWasm => "os-sandbox+wasm",
            Self::WasmOnly => "wasm-only",
        }
    }

    /// The discriminant written into witness aux data.
    #[must_use]
    pub const fn witness_code(self) -> u8 {
        match self {
            Self::Partition => 1,
            Self::OsSandboxWasm => 2,
            Self::WasmOnly => 3,
        }
    }
}

impl fmt::Display for IsolationClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanism::{IsolationMechanism, MechanismStatus};
    use rvm_partition::PartitionType;

    fn core() -> MechanismSet {
        MechanismSet::new().with_all(
            &IsolationMechanism::PORTABLE_CORE,
            MechanismStatus::Engaged,
        )
    }

    fn live_partition() -> (PartitionManager, PartitionId) {
        let mut mgr = PartitionManager::new();
        let id = mgr.create(PartitionType::Agent, 1, 0).unwrap();
        (mgr, id)
    }

    #[test]
    fn hosted_never_claims_partition_whatever_it_engaged() {
        // Every OS, every subset of its stack, plus the bare-metal mechanisms
        // wrongly stapled on: none of it can produce a Partition claim.
        for os in HostOs::ALL {
            let env = HostEnvironment::hosted(os);
            for stack in [
                MechanismSet::new(),
                core(),
                core().with_all(IsolationMechanism::stack_for(os), MechanismStatus::Engaged),
                core()
                    .with_all(IsolationMechanism::stack_for(os), MechanismStatus::Engaged)
                    .with_all(
                        &IsolationMechanism::BARE_METAL_ONLY,
                        MechanismStatus::Engaged,
                    ),
            ] {
                let claim = IsolationClaim::derive(env, &stack);
                assert!(!claim.is_bare_metal(), "{os} claimed {claim}");
                assert_ne!(claim, IsolationClaim::Partition);
            }
        }
    }

    #[test]
    fn hosted_with_an_engaged_os_mechanism_claims_os_sandbox_wasm() {
        let env = HostEnvironment::hosted(HostOs::Linux);
        let set = core().with(IsolationMechanism::LinuxSeccomp, MechanismStatus::Engaged);
        assert_eq!(IsolationClaim::derive(env, &set), IsolationClaim::OsSandboxWasm);
    }

    #[test]
    fn hosted_with_a_declared_but_unengaged_stack_degrades_to_wasm_only() {
        let env = HostEnvironment::hosted(HostOs::Linux);
        let set = core().with_all(
            IsolationMechanism::stack_for(HostOs::Linux),
            MechanismStatus::Unimplemented,
        );
        assert_eq!(IsolationClaim::derive(env, &set), IsolationClaim::WasmOnly);
    }

    #[test]
    fn a_mechanism_from_another_os_does_not_earn_the_claim() {
        // Engaging seccomp does nothing for a process running on Windows.
        let env = HostEnvironment::hosted(HostOs::Windows);
        let set = core().with(IsolationMechanism::LinuxSeccomp, MechanismStatus::Engaged);
        assert_eq!(IsolationClaim::derive(env, &set), IsolationClaim::WasmOnly);
    }

    #[test]
    fn portable_is_always_wasm_only() {
        let env = HostEnvironment::portable();
        assert_eq!(IsolationClaim::derive(env, &core()), IsolationClaim::WasmOnly);
        assert_eq!(
            IsolationClaim::derive(
                env,
                &core().with_all(
                    &IsolationMechanism::BARE_METAL_ONLY,
                    MechanismStatus::Engaged
                )
            ),
            IsolationClaim::WasmOnly
        );
    }

    #[test]
    fn bare_metal_requires_a_partition_that_is_actually_live() {
        let (mgr, id) = live_partition();
        assert!(PartitionEvidence::from_manager(&mgr, id).is_some());
        // An identifier the manager never issued produces no evidence, so no
        // bare-metal environment and no Partition claim can be built from it.
        assert!(PartitionEvidence::from_manager(&mgr, PartitionId::new(4095)).is_none());
    }

    #[test]
    fn bare_metal_claims_partition() {
        let (mgr, id) = live_partition();
        let evidence = PartitionEvidence::from_manager(&mgr, id).unwrap();
        let env = HostEnvironment::bare_metal(evidence);
        assert_eq!(IsolationClaim::derive(env, &core()), IsolationClaim::Partition);
        assert_eq!(env.partition(), Some(id));
        assert!(env.is_bare_metal());
        assert!(!env.is_hosted());
    }

    #[test]
    fn claims_render_and_encode_distinctly() {
        let all = [
            IsolationClaim::Partition,
            IsolationClaim::OsSandboxWasm,
            IsolationClaim::WasmOnly,
        ];
        let mut codes: alloc::vec::Vec<u8> = all.iter().map(|c| c.witness_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 3);
        assert_eq!(IsolationClaim::OsSandboxWasm.as_str(), "os-sandbox+wasm");
    }

    #[test]
    fn environments_render_with_their_operating_system() {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        write!(&mut s, "{}", HostEnvironment::hosted(HostOs::MacOs)).unwrap();
        assert_eq!(s, "hosted/macos");
    }
}
