//! The fifteen RVF capability classes and their mapping into `rvm-cap`.
//!
//! ADR-286 §1 defines fifteen classes and one rule: nothing is granted unless
//! the RVF declares it, and an absent declaration is a *denial* rather than an
//! unspecified case for a host to resolve. [`CapabilityMapping`] therefore has
//! no third state — a class is either in `granted` or it is denied.
//!
//! # Where declarations come from
//!
//! Declarations live in `META` segments as `rvf.capabilities=network,clock`.
//! Reading them is byte scanning over inert metadata; no other segment kind is
//! consulted, and in particular an executable segment is never parsed to infer
//! what it might do (ADR-284 §1.7).
//!
//! An *unrecognized* class name is skipped, because it cannot widen the
//! granted set: RVM is default-deny, so a class RVM does not know is a class
//! RVM does not grant. A *recognized but unrepresentable* class is a different
//! matter and is refused — see [`RvmBinding`].

use crate::container::ParsedSegment;
use crate::error::{RvfError, RvfResult};
use crate::format::SEG_TYPE_META;
use alloc::vec::Vec;
use core::fmt;
use rvm_cap::CapabilityTable;
use rvm_types::{CapRights, CapToken, CapType, DeviceClass, PartitionId};

/// The `META` key under which an RVF declares its capability classes.
pub const CAPABILITY_DECLARATION_KEY: &str = "rvf.capabilities";

/// The fifteen capability classes of ADR-286 §1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityClass {
    /// Memory quotas; one component may never read another's memory.
    Memory,
    /// Declared filesystem paths only.
    Filesystem,
    /// Declared network destinations only.
    Network,
    /// Which model segments may be loaded, bounded by signed maximum size.
    Model,
    /// MCP tool surfaces, first-class rather than implied by network access.
    Mcp,
    /// Process creation and control.
    Process,
    /// Wall clock; deniable, with a deterministic virtual mode.
    Clock,
    /// Randomness; deniable, with a seeded deterministic mode.
    Randomness,
    /// GPU access.
    Gpu,
    /// Sensor access.
    Sensor,
    /// Display access.
    Display,
    /// Audio access.
    Audio,
    /// Clipboard access.
    Clipboard,
    /// Persistent state; bound to the base RVF lineage.
    PersistentState,
    /// Inter-agent messaging.
    InterAgentMessaging,
}

impl CapabilityClass {
    /// Every class, in declaration order.
    pub const ALL: [Self; 15] = [
        Self::Memory,
        Self::Filesystem,
        Self::Network,
        Self::Model,
        Self::Mcp,
        Self::Process,
        Self::Clock,
        Self::Randomness,
        Self::Gpu,
        Self::Sensor,
        Self::Display,
        Self::Audio,
        Self::Clipboard,
        Self::PersistentState,
        Self::InterAgentMessaging,
    ];

    /// The kebab-case wire name, e.g. `persistent-state`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Model => "model",
            Self::Mcp => "mcp",
            Self::Process => "process",
            Self::Clock => "clock",
            Self::Randomness => "randomness",
            Self::Gpu => "gpu",
            Self::Sensor => "sensor",
            Self::Display => "display",
            Self::Audio => "audio",
            Self::Clipboard => "clipboard",
            Self::PersistentState => "persistent-state",
            Self::InterAgentMessaging => "inter-agent-messaging",
        }
    }

    /// Parse a wire name.
    ///
    /// Returns `None` for anything unrecognized; callers must treat that as a
    /// denial, never as a wildcard.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// How RVM represents this class, or `None` when it cannot.
    ///
    /// A class is representable when RVM has an object kind whose authority
    /// *is* that class's authority — not merely a bucket the class can be
    /// dropped into. Two classes fail that test today:
    ///
    /// - **Clipboard** is an operating-system session construct, not a
    ///   leasable device. The nearest fit, `DeviceClass::Generic`, is an MMIO
    ///   region, and granting one to express clipboard access would hand the
    ///   agent authority it never declared.
    /// - **Randomness** has no entropy-source object in RVM, and ADR-284 §3.6
    ///   requires a *seeded deterministic* mode, which is a runtime facility
    ///   rather than a device lease.
    ///
    /// Both refuse rather than degrade (ADR-286 §3). When RVM grows the
    /// corresponding object kinds, they move into the table and the refusal
    /// disappears without any change to callers.
    #[must_use]
    pub const fn rvm_binding(self) -> Option<RvmBinding> {
        let (cap_type, rights, device) = match self {
            // Memory quotas and persistent-state deltas are both authority
            // over memory regions.
            Self::Memory | Self::PersistentState => (
                CapType::Region,
                CapRights::READ.union(CapRights::WRITE),
                None,
            ),
            // The base RVF is immutable, so a model segment is mapped
            // read-only however large the grant.
            Self::Model => (CapType::Region, CapRights::READ, None),
            // Tool surfaces and agent-to-agent traffic are both edges in the
            // coherence graph.
            Self::Mcp | Self::InterAgentMessaging => (
                CapType::CommEdge,
                CapRights::READ.union(CapRights::WRITE),
                None,
            ),
            // Process creation is partition creation.
            Self::Process => (CapType::Partition, CapRights::WRITE, None),
            Self::Filesystem => (
                CapType::Device,
                CapRights::READ.union(CapRights::WRITE),
                Some(DeviceClass::Storage),
            ),
            Self::Network => (
                CapType::Device,
                CapRights::READ.union(CapRights::WRITE),
                Some(DeviceClass::Network),
            ),
            Self::Gpu => (
                CapType::Device,
                CapRights::READ.union(CapRights::WRITE),
                Some(DeviceClass::Graphics),
            ),
            Self::Display => (
                CapType::Device,
                CapRights::WRITE,
                Some(DeviceClass::Graphics),
            ),
            Self::Clock => (CapType::Device, CapRights::READ, Some(DeviceClass::Timer)),
            Self::Sensor => (CapType::Device, CapRights::READ, Some(DeviceClass::Generic)),
            Self::Audio => (
                CapType::Device,
                CapRights::READ.union(CapRights::WRITE),
                Some(DeviceClass::Generic),
            ),
            Self::Clipboard | Self::Randomness => return None,
        };
        Some(RvmBinding {
            class: self,
            cap_type,
            rights,
            device_class: device,
        })
    }

    /// Whether RVM can represent this class at all.
    #[must_use]
    pub const fn is_representable(self) -> bool {
        self.rvm_binding().is_some()
    }
}

impl fmt::Display for CapabilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How one capability class becomes an `rvm-cap` capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RvmBinding {
    /// The RVF class this binding satisfies.
    pub class: CapabilityClass,
    /// The RVM object kind the capability is issued over.
    pub cap_type: CapType,
    /// The rights the capability carries.
    pub rights: CapRights,
    /// The device taxonomy entry, for classes that map to a device lease.
    pub device_class: Option<DeviceClass>,
}

/// The result of mapping an RVF's declarations into `rvm-cap`.
///
/// Every one of the fifteen classes appears in exactly one of `granted` and
/// `denied`, so "was this granted?" always has an answer that does not depend
/// on a host default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityMapping {
    granted: Vec<RvmBinding>,
    denied: Vec<CapabilityClass>,
}

impl CapabilityMapping {
    /// The bindings the RVF declared and RVM will issue.
    #[must_use]
    pub fn granted(&self) -> &[RvmBinding] {
        &self.granted
    }

    /// The classes that stay closed, which is everything not declared.
    #[must_use]
    pub fn denied(&self) -> &[CapabilityClass] {
        &self.denied
    }

    /// Whether `class` is granted.
    #[must_use]
    pub fn is_granted(&self, class: CapabilityClass) -> bool {
        self.granted.iter().any(|b| b.class == class)
    }

    /// The rights `class` carries, or the empty set when it is denied.
    ///
    /// The empty set is the whole point: an undeclared class resolves to no
    /// right rather than to an absent entry a caller might paper over.
    #[must_use]
    pub fn rights_for(&self, class: CapabilityClass) -> CapRights {
        self.granted
            .iter()
            .find(|b| b.class == class)
            .map_or(CapRights::empty(), |b| b.rights)
    }

    /// Install every granted binding into `table` as a root capability.
    ///
    /// Capability identifiers run from `first_cap_id`; the badge carries the
    /// class discriminant so a later audit can tell which declaration a
    /// capability came from. Returns the number of capabilities inserted.
    ///
    /// # Errors
    ///
    /// [`RvfError::CapabilityTableFull`] when the table runs out of slots.
    /// Slots already inserted are left in place: the caller holds the table
    /// and is the only party that can decide whether to unwind it.
    pub fn install<const N: usize>(
        &self,
        table: &mut CapabilityTable<N>,
        owner: PartitionId,
        epoch: u32,
        first_cap_id: u64,
    ) -> RvfResult<usize> {
        for (i, binding) in self.granted.iter().enumerate() {
            let id = first_cap_id.wrapping_add(i as u64);
            let token = CapToken::new(id, binding.cap_type, binding.rights, epoch);
            let badge = binding.class as u64;
            // `insert_root` can only fail by running out of slots; every
            // other CapError variant belongs to lookup and derivation.
            if table.insert_root(token, owner, badge).is_err() {
                return Err(RvfError::CapabilityTableFull);
            }
        }
        Ok(self.granted.len())
    }
}

/// Map a set of declared classes into `rvm-cap` bindings, default-deny.
///
/// # Errors
///
/// [`RvfError::UnsupportedCapability`] when a declared class is one RVM
/// cannot represent. ADR-286 §3 requires refusal here rather than dropping
/// the class and starting anyway.
pub fn map_declared(declared: &[CapabilityClass]) -> RvfResult<CapabilityMapping> {
    let mut granted = Vec::new();
    let mut denied = Vec::new();

    for class in CapabilityClass::ALL {
        if !declared.contains(&class) {
            denied.push(class);
            continue;
        }
        let binding = class
            .rvm_binding()
            .ok_or(RvfError::UnsupportedCapability(class))?;
        granted.push(binding);
    }

    Ok(CapabilityMapping { granted, denied })
}

/// The capability classes an RVF declares, read from its `META` segments.
///
/// Encrypted metadata is skipped rather than guessed at, and a segment whose
/// payload is not UTF-8 contributes nothing. Both are conservative: skipping
/// can only narrow the granted set.
#[must_use]
pub fn declared_classes(data: &[u8], segments: &[ParsedSegment]) -> Vec<CapabilityClass> {
    let mut found: Vec<CapabilityClass> = Vec::new();

    for seg in segments {
        if seg.header.seg_type != SEG_TYPE_META || seg.header.is_encrypted() {
            continue;
        }
        let Ok(text) = core::str::from_utf8(seg.payload(data)) else {
            continue;
        };
        for line in text.lines() {
            let Some(rest) = line.strip_prefix(CAPABILITY_DECLARATION_KEY) else {
                continue;
            };
            let Some(value) = rest.strip_prefix('=') else {
                continue;
            };
            for name in value.split(',') {
                if let Some(class) = CapabilityClass::from_wire(name.trim()) {
                    if !found.contains(&class) {
                        found.push(class);
                    }
                }
            }
        }
    }

    found.sort_unstable();
    found
}

#[cfg(test)]
#[path = "capability_tests.rs"]
mod tests;
