//! The confinement mechanisms an adapter can compose beneath WASM, and
//! whether it actually engaged each one.
//!
//! ADR-285 §3 lists a different stack per platform and adds one rule that
//! shapes this whole module: *an adapter that could not apply a mechanism
//! reports that rather than silently running with a weaker stack.* So a
//! mechanism is never a boolean. It is one of three states, and "I meant to
//! but could not" is a distinct answer from both "engaged" and "not part of my
//! stack".

use alloc::vec::Vec;
use core::fmt;

/// The desktop operating systems with their own confinement stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostOs {
    /// Windows: job objects, restricted tokens, filesystem and network controls.
    Windows,
    /// macOS: application sandbox, hardened runtime, entitlements, notarization.
    MacOs,
    /// Linux: namespaces, cgroups, seccomp, restricted mounts, network namespaces.
    Linux,
}

impl HostOs {
    /// Every host operating system, in declaration order.
    pub const ALL: [Self; 3] = [Self::Windows, Self::MacOs, Self::Linux];

    /// The wire name, e.g. `macos`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
        }
    }
}

impl fmt::Display for HostOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One confinement mechanism.
///
/// The portable three are properties of the RVM stack itself and hold on every
/// backend. The per-OS entries are the ADR-285 §3 stacks. The bare-metal
/// entries are the hypervisor-class controls that only a real RVM partition
/// has, and no hosted adapter can report them — see [`crate::IsolationClaim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsolationMechanism {
    /// WASM linear memories are disjoint; one component cannot read another's.
    WasmMemoryIsolation,
    /// Undeclared capability classes resolve to no right (ADR-286 §1).
    CapabilityDefaultDeny,
    /// Memory, instruction, wall-time, storage, and invocation quotas.
    QuotaEnforcement,

    /// Windows job object bounding the host process tree.
    WindowsJobObject,
    /// Windows restricted token dropping the process's ambient privileges.
    WindowsRestrictedToken,
    /// Windows filesystem restrictions on the host process.
    WindowsFilesystemRestriction,
    /// Windows outbound network controls on the host process.
    WindowsOutboundNetworkControl,

    /// macOS application sandbox profile applied to the host process.
    MacosAppSandbox,
    /// macOS hardened runtime.
    MacosHardenedRuntime,
    /// macOS scoped entitlements, granting only the declared surfaces.
    MacosScopedEntitlements,
    /// macOS notarization of the shipped binary.
    MacosNotarization,

    /// Linux namespaces (mount, pid, user, uts, ipc).
    LinuxNamespaces,
    /// Linux cgroups bounding memory and CPU.
    LinuxCgroups,
    /// Linux seccomp filter over the syscall surface.
    LinuxSeccomp,
    /// Linux restricted mounts, so only declared paths are reachable.
    LinuxRestrictedMounts,
    /// Linux network namespace, so undeclared destinations are unroutable.
    LinuxNetworkNamespace,

    /// Stage-2 partition memory isolation.
    PartitionMemoryIsolation,
    /// Kernel-managed capability tables (ADR-135).
    CapabilityTable,
    /// Time-bounded device leases (ADR-150).
    DeviceLease,
    /// Measured boot (ADR-137).
    MeasuredBoot,
    /// The `rvm-security` three-stage gate on every privileged operation.
    WitnessedSecurityGate,
}

impl IsolationMechanism {
    /// The three mechanisms every RVM backend provides.
    pub const PORTABLE_CORE: [Self; 3] = [
        Self::WasmMemoryIsolation,
        Self::CapabilityDefaultDeny,
        Self::QuotaEnforcement,
    ];

    /// The bare-metal-only controls (ADR-285 §3, "for contrast").
    pub const BARE_METAL_ONLY: [Self; 5] = [
        Self::PartitionMemoryIsolation,
        Self::CapabilityTable,
        Self::DeviceLease,
        Self::MeasuredBoot,
        Self::WitnessedSecurityGate,
    ];

    /// The confinement stack ADR-285 §3 assigns to `os`.
    #[must_use]
    pub const fn stack_for(os: HostOs) -> &'static [Self] {
        match os {
            HostOs::Windows => &[
                Self::WindowsJobObject,
                Self::WindowsRestrictedToken,
                Self::WindowsFilesystemRestriction,
                Self::WindowsOutboundNetworkControl,
            ],
            HostOs::MacOs => &[
                Self::MacosAppSandbox,
                Self::MacosHardenedRuntime,
                Self::MacosScopedEntitlements,
                Self::MacosNotarization,
            ],
            HostOs::Linux => &[
                Self::LinuxNamespaces,
                Self::LinuxCgroups,
                Self::LinuxSeccomp,
                Self::LinuxRestrictedMounts,
                Self::LinuxNetworkNamespace,
            ],
        }
    }

    /// The operating system this mechanism belongs to, or `None` when it is
    /// portable or bare-metal.
    ///
    /// This is what [`crate::IsolationClaim`] consults: a hosted adapter earns
    /// the `OsSandboxWasm` claim only by engaging a mechanism that belongs to
    /// the operating system it is actually running on.
    #[must_use]
    pub const fn host_os(self) -> Option<HostOs> {
        match self {
            Self::WindowsJobObject
            | Self::WindowsRestrictedToken
            | Self::WindowsFilesystemRestriction
            | Self::WindowsOutboundNetworkControl => Some(HostOs::Windows),
            Self::MacosAppSandbox
            | Self::MacosHardenedRuntime
            | Self::MacosScopedEntitlements
            | Self::MacosNotarization => Some(HostOs::MacOs),
            Self::LinuxNamespaces
            | Self::LinuxCgroups
            | Self::LinuxSeccomp
            | Self::LinuxRestrictedMounts
            | Self::LinuxNetworkNamespace => Some(HostOs::Linux),
            _ => None,
        }
    }

    /// Whether this mechanism confines paths the agent may reach.
    ///
    /// A hosted adapter may enforce the `filesystem` capability class only
    /// when one of these is engaged; without it, "declared paths only" is an
    /// assertion rather than a boundary.
    #[must_use]
    pub const fn confines_filesystem(self) -> bool {
        matches!(
            self,
            Self::WindowsFilesystemRestriction
                | Self::MacosAppSandbox
                | Self::MacosScopedEntitlements
                | Self::LinuxRestrictedMounts
                | Self::LinuxNamespaces
        )
    }

    /// Whether this mechanism confines the destinations the agent may reach.
    #[must_use]
    pub const fn confines_network(self) -> bool {
        matches!(
            self,
            Self::WindowsOutboundNetworkControl
                | Self::MacosAppSandbox
                | Self::LinuxNetworkNamespace
        )
    }

    /// Whether this mechanism confines process creation.
    #[must_use]
    pub const fn confines_process(self) -> bool {
        matches!(
            self,
            Self::WindowsJobObject
                | Self::WindowsRestrictedToken
                | Self::MacosAppSandbox
                | Self::LinuxNamespaces
                | Self::LinuxSeccomp
        )
    }

    /// The stable name used in documentation and witness aux data.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmMemoryIsolation => "wasm-memory-isolation",
            Self::CapabilityDefaultDeny => "capability-default-deny",
            Self::QuotaEnforcement => "quota-enforcement",
            Self::WindowsJobObject => "windows-job-object",
            Self::WindowsRestrictedToken => "windows-restricted-token",
            Self::WindowsFilesystemRestriction => "windows-filesystem-restriction",
            Self::WindowsOutboundNetworkControl => "windows-outbound-network-control",
            Self::MacosAppSandbox => "macos-app-sandbox",
            Self::MacosHardenedRuntime => "macos-hardened-runtime",
            Self::MacosScopedEntitlements => "macos-scoped-entitlements",
            Self::MacosNotarization => "macos-notarization",
            Self::LinuxNamespaces => "linux-namespaces",
            Self::LinuxCgroups => "linux-cgroups",
            Self::LinuxSeccomp => "linux-seccomp",
            Self::LinuxRestrictedMounts => "linux-restricted-mounts",
            Self::LinuxNetworkNamespace => "linux-network-namespace",
            Self::PartitionMemoryIsolation => "partition-memory-isolation",
            Self::CapabilityTable => "capability-table",
            Self::DeviceLease => "device-lease",
            Self::MeasuredBoot => "measured-boot",
            Self::WitnessedSecurityGate => "witnessed-security-gate",
        }
    }
}

impl fmt::Display for IsolationMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What became of one mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MechanismStatus {
    /// Applied, and the adapter may rely on it.
    Engaged = 0,
    /// Part of this adapter's stack, but the platform refused or lacked it.
    Unavailable = 1,
    /// Part of this adapter's stack, but nothing in this build applies it.
    ///
    /// This crate is `no_std` and portable; it cannot itself call
    /// `CreateJobObject`, `sandbox_init`, or `unshare(2)`. Those belong to the
    /// host integration, which reports back through
    /// [`crate::HostedAdapter::engaging`]. Until it does, the honest status is
    /// `Unimplemented`, and the isolation claim degrades accordingly rather
    /// than assuming the mechanism took hold.
    Unimplemented = 2,
}

impl MechanismStatus {
    /// Whether the adapter may rely on the mechanism.
    #[must_use]
    pub const fn is_engaged(self) -> bool {
        matches!(self, Self::Engaged)
    }
}

/// One mechanism and its status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MechanismReport {
    /// The mechanism.
    pub mechanism: IsolationMechanism,
    /// Whether it took hold.
    pub status: MechanismStatus,
}

/// Everything an adapter has to say about its confinement stack.
///
/// A set holds every mechanism the adapter *declares*, engaged or not, so a
/// reader can tell a stack that was never attempted from one that failed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MechanismSet {
    entries: Vec<MechanismReport>,
}

impl MechanismSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record `mechanism` with `status`, replacing any prior entry for it.
    #[must_use]
    pub fn with(mut self, mechanism: IsolationMechanism, status: MechanismStatus) -> Self {
        self.set(mechanism, status);
        self
    }

    /// Record every mechanism in `mechanisms` with `status`.
    #[must_use]
    pub fn with_all(mut self, mechanisms: &[IsolationMechanism], status: MechanismStatus) -> Self {
        for m in mechanisms {
            self.set(*m, status);
        }
        self
    }

    fn set(&mut self, mechanism: IsolationMechanism, status: MechanismStatus) {
        match self.entries.iter_mut().find(|e| e.mechanism == mechanism) {
            Some(existing) => existing.status = status,
            None => self.entries.push(MechanismReport { mechanism, status }),
        }
    }

    /// Every declared mechanism and its status.
    #[must_use]
    pub fn reports(&self) -> &[MechanismReport] {
        &self.entries
    }

    /// The status of `mechanism`, or `None` when it is not part of this stack.
    #[must_use]
    pub fn status_of(&self, mechanism: IsolationMechanism) -> Option<MechanismStatus> {
        self.entries
            .iter()
            .find(|e| e.mechanism == mechanism)
            .map(|e| e.status)
    }

    /// Whether `mechanism` is engaged.
    #[must_use]
    pub fn is_engaged(&self, mechanism: IsolationMechanism) -> bool {
        self.status_of(mechanism)
            .is_some_and(MechanismStatus::is_engaged)
    }

    /// Whether any engaged mechanism satisfies `predicate`.
    #[must_use]
    pub fn any_engaged(&self, predicate: impl Fn(IsolationMechanism) -> bool) -> bool {
        self.entries
            .iter()
            .any(|e| e.status.is_engaged() && predicate(e.mechanism))
    }

    /// Whether any engaged mechanism belongs to `os`.
    ///
    /// This is the whole test for the `OsSandboxWasm` claim: an adapter that
    /// declares the Linux stack but engaged none of it has WASM isolation and
    /// nothing else, and must say so.
    #[must_use]
    pub fn any_os_confinement_engaged(&self, os: HostOs) -> bool {
        self.any_engaged(|m| m.host_os() == Some(os))
    }

    /// The mechanisms that are declared but did not take hold.
    #[must_use]
    pub fn not_engaged(&self) -> Vec<IsolationMechanism> {
        self.entries
            .iter()
            .filter(|e| !e.status.is_engaged())
            .map(|e| e.mechanism)
            .collect()
    }

    /// How many mechanisms are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_os_stack_belongs_to_that_os_and_no_other() {
        for os in HostOs::ALL {
            for m in IsolationMechanism::stack_for(os) {
                assert_eq!(m.host_os(), Some(os), "{m} is filed under the wrong OS");
            }
        }
    }

    #[test]
    fn portable_and_bare_metal_mechanisms_belong_to_no_os() {
        for m in IsolationMechanism::PORTABLE_CORE {
            assert_eq!(m.host_os(), None);
        }
        for m in IsolationMechanism::BARE_METAL_ONLY {
            assert_eq!(m.host_os(), None);
        }
    }

    #[test]
    fn a_declared_but_unimplemented_mechanism_is_not_engaged() {
        let set = MechanismSet::new()
            .with(
                IsolationMechanism::LinuxSeccomp,
                MechanismStatus::Unimplemented,
            )
            .with(
                IsolationMechanism::WasmMemoryIsolation,
                MechanismStatus::Engaged,
            );

        assert!(!set.is_engaged(IsolationMechanism::LinuxSeccomp));
        assert_eq!(
            set.status_of(IsolationMechanism::LinuxSeccomp),
            Some(MechanismStatus::Unimplemented)
        );
        assert_eq!(set.not_engaged(), [IsolationMechanism::LinuxSeccomp]);
    }

    #[test]
    fn a_mechanism_not_in_the_stack_has_no_status_at_all() {
        let set = MechanismSet::new().with_all(
            &IsolationMechanism::PORTABLE_CORE,
            MechanismStatus::Engaged,
        );
        assert_eq!(set.status_of(IsolationMechanism::LinuxCgroups), None);
        assert!(!set.is_engaged(IsolationMechanism::LinuxCgroups));
    }

    #[test]
    fn setting_a_mechanism_twice_replaces_rather_than_duplicates() {
        let set = MechanismSet::new()
            .with(
                IsolationMechanism::LinuxSeccomp,
                MechanismStatus::Unimplemented,
            )
            .with(IsolationMechanism::LinuxSeccomp, MechanismStatus::Engaged);
        assert_eq!(set.len(), 1);
        assert!(set.is_engaged(IsolationMechanism::LinuxSeccomp));
    }

    #[test]
    fn os_confinement_is_detected_only_for_the_matching_os() {
        let set = MechanismSet::new().with(IsolationMechanism::LinuxCgroups, MechanismStatus::Engaged);
        assert!(set.any_os_confinement_engaged(HostOs::Linux));
        assert!(!set.any_os_confinement_engaged(HostOs::Windows));
        assert!(!set.any_os_confinement_engaged(HostOs::MacOs));
    }

    #[test]
    fn every_mechanism_has_a_distinct_name() {
        let mut names: Vec<&str> = IsolationMechanism::PORTABLE_CORE
            .iter()
            .chain(IsolationMechanism::BARE_METAL_ONLY.iter())
            .chain(HostOs::ALL.iter().flat_map(|os| IsolationMechanism::stack_for(*os)))
            .map(|m| m.as_str())
            .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
        assert_eq!(total, 21);
    }
}
