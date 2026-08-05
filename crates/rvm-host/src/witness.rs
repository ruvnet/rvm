//! Witness emission at the host boundary.
//!
//! ADR-285 acceptance criterion 2 requires every capability request and denial
//! to appear in the witness chain, and ADR-289 criterion 2 requires each
//! adapter's actual isolation class to appear there too. Both are recorded
//! here, and both are recorded *before* the decision is acted on, so a refusal
//! is an auditable event rather than a silent error.
//!
//! # Mapping onto `ActionKind`
//!
//! | [`HostEvent`] | [`ActionKind`] | Tier | Reading |
//! |---|---|---|---|
//! | `CapabilityGranted` | `CapabilityGrant` | 1 | a declared class became a live capability |
//! | `CapabilityDenied` | `ProofRejected` | 1 | an undeclared class stays closed |
//! | `CapabilityRefused` | `ProofRejected` | 2 | a declared class the adapter cannot enforce; the start is abandoned |
//! | `IsolationPrepared` | `ProofVerifiedP2` | 2 | the isolation context and the class it claims |
//! | `ModuleAdmitted` | `ProofVerifiedP2` | 2 | a module passed the adapter's admission checks |
//! | `ModuleRefused` | `ProofRejected` | 2 | a module was refused before any execution |
//!
//! `CapabilityDenied` and `CapabilityRefused` share an `ActionKind` because
//! both are refusals, and are told apart by `flags` and by `aux[0]`. They are
//! genuinely different events: the first is the default-deny boundary working
//! as designed, the second is an adapter that cannot honour a declaration and
//! therefore will not start.

use rvm_rvf::CapabilityClass;
use rvm_types::{fnv1a_32, ActionKind, PartitionId, WitnessRecord};
use rvm_witness::WitnessLog;

use crate::isolation::{HostEnvironment, IsolationClaim};

/// A host-boundary event worth a witness record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HostEvent {
    /// A declared class became a live capability.
    CapabilityGranted = 1,
    /// An undeclared class stays closed.
    CapabilityDenied = 2,
    /// A declared class this adapter cannot enforce; the start is abandoned.
    CapabilityRefused = 3,
    /// An isolation context was prepared, with the class it claims.
    IsolationPrepared = 4,
    /// A module passed the adapter's admission checks.
    ModuleAdmitted = 5,
    /// A module was refused before any execution.
    ModuleRefused = 6,
}

impl HostEvent {
    /// Every event, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::CapabilityGranted,
        Self::CapabilityDenied,
        Self::CapabilityRefused,
        Self::IsolationPrepared,
        Self::ModuleAdmitted,
        Self::ModuleRefused,
    ];

    /// The `ActionKind` this event is recorded under.
    #[must_use]
    pub const fn action_kind(self) -> ActionKind {
        match self {
            Self::CapabilityGranted => ActionKind::CapabilityGrant,
            Self::CapabilityDenied | Self::CapabilityRefused | Self::ModuleRefused => {
                ActionKind::ProofRejected
            }
            Self::IsolationPrepared | Self::ModuleAdmitted => ActionKind::ProofVerifiedP2,
        }
    }

    /// The proof tier this event is discharged at.
    #[must_use]
    pub const fn proof_tier(self) -> u8 {
        match self {
            Self::CapabilityGranted | Self::CapabilityDenied => 1,
            _ => 2,
        }
    }

    /// Whether this event records a refusal.
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        matches!(
            self,
            Self::CapabilityDenied | Self::CapabilityRefused | Self::ModuleRefused
        )
    }
}

/// Who is emitting, about which artifact, under which claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostWitnessContext {
    /// SHA-256 of the container the event is about.
    pub rvf_identity: [u8; 32],
    /// The partition the agent is placed in.
    pub partition: PartitionId,
    /// Where the adapter is running.
    pub environment: HostEnvironment,
    /// The isolation class the adapter obtained.
    pub claim: IsolationClaim,
    /// Nanosecond timestamp. Supplied rather than sampled: this crate is
    /// `no_std` and has no clock.
    pub timestamp_ns: u64,
}

impl HostWitnessContext {
    /// A context for `identity` in `partition`.
    #[must_use]
    pub const fn new(
        rvf_identity: [u8; 32],
        partition: PartitionId,
        environment: HostEnvironment,
        claim: IsolationClaim,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            rvf_identity,
            partition,
            environment,
            claim,
            timestamp_ns,
        }
    }
}

/// The `aux[1]` value for an event that is not about a capability class.
pub const NO_CLASS: u8 = 0xFF;

/// The environment discriminant written to `aux[3]`.
#[must_use]
const fn environment_code(env: HostEnvironment) -> u8 {
    if env.is_bare_metal() {
        1
    } else if env.is_hosted() {
        2
    } else {
        3
    }
}

/// Build the record for one host-boundary event.
///
/// The record binds to the artifact the way `rvm-rvf` does: `capability_hash`
/// is an FNV-1a fold of the container identity and `payload` carries its first
/// eight bytes, so a record cannot be replayed against a different artifact
/// and still read as evidence about it.
///
/// `aux` packs the event, the capability class it concerns (or [`NO_CLASS`]),
/// the isolation claim, the environment, and a four-byte event detail.
#[must_use]
pub fn build_record(
    event: HostEvent,
    ctx: &HostWitnessContext,
    class: Option<CapabilityClass>,
    detail: u32,
) -> WitnessRecord {
    let mut r = WitnessRecord::zeroed();
    r.action_kind = event.action_kind() as u8;
    r.proof_tier = event.proof_tier();
    r.flags = event as u8;
    r.actor_partition_id = ctx.partition.as_u32();
    r.target_object_id = class.map_or(0, |c| c as u64);
    r.capability_hash = fnv1a_32(&ctx.rvf_identity);
    r.timestamp_ns = ctx.timestamp_ns;
    r.payload.copy_from_slice(&ctx.rvf_identity[..8]);

    r.aux[0] = event as u8;
    r.aux[1] = class.map_or(NO_CLASS, |c| c as u8);
    r.aux[2] = ctx.claim.witness_code();
    r.aux[3] = environment_code(ctx.environment);
    r.aux[4..8].copy_from_slice(&detail.to_le_bytes());
    r
}

/// Append one host-boundary event, returning the sequence the log assigned.
pub fn emit<const N: usize>(
    log: &WitnessLog<N>,
    event: HostEvent,
    ctx: &HostWitnessContext,
    class: Option<CapabilityClass>,
    detail: u32,
) -> u64 {
    log.append(build_record(event, ctx, class, detail))
}

/// Read the [`HostEvent`] back out of a record this module wrote.
///
/// Returns `None` for records emitted by another subsystem, which is what
/// makes an instance's own host decisions separable from everything else
/// sharing the log.
#[must_use]
pub const fn event_of(record: &WitnessRecord) -> Option<HostEvent> {
    match record.aux[0] {
        1 => Some(HostEvent::CapabilityGranted),
        2 => Some(HostEvent::CapabilityDenied),
        3 => Some(HostEvent::CapabilityRefused),
        4 => Some(HostEvent::IsolationPrepared),
        5 => Some(HostEvent::ModuleAdmitted),
        6 => Some(HostEvent::ModuleRefused),
        _ => None,
    }
}

/// Read the isolation claim out of a record this module wrote.
#[must_use]
pub const fn claim_of(record: &WitnessRecord) -> Option<IsolationClaim> {
    match record.aux[2] {
        1 => Some(IsolationClaim::Partition),
        2 => Some(IsolationClaim::OsSandboxWasm),
        3 => Some(IsolationClaim::WasmOnly),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanism::HostOs;
    use alloc::vec::Vec;

    fn ctx(claim: IsolationClaim) -> HostWitnessContext {
        HostWitnessContext::new(
            [7u8; 32],
            PartitionId::new(3),
            HostEnvironment::hosted(HostOs::Linux),
            claim,
            1_000,
        )
    }

    #[test]
    fn a_grant_and_a_denial_are_distinguishable_in_the_record() {
        let c = ctx(IsolationClaim::WasmOnly);
        let granted = build_record(
            HostEvent::CapabilityGranted,
            &c,
            Some(CapabilityClass::Clock),
            0,
        );
        let denied = build_record(
            HostEvent::CapabilityDenied,
            &c,
            Some(CapabilityClass::Network),
            0,
        );

        assert_eq!(granted.action_kind, ActionKind::CapabilityGrant as u8);
        assert_eq!(denied.action_kind, ActionKind::ProofRejected as u8);
        assert_eq!(event_of(&granted), Some(HostEvent::CapabilityGranted));
        assert_eq!(event_of(&denied), Some(HostEvent::CapabilityDenied));
        assert_eq!(granted.aux[1], CapabilityClass::Clock as u8);
        assert_eq!(denied.aux[1], CapabilityClass::Network as u8);
    }

    #[test]
    fn a_refusal_and_a_denial_share_an_action_kind_but_not_an_event() {
        let c = ctx(IsolationClaim::WasmOnly);
        let denied = build_record(HostEvent::CapabilityDenied, &c, None, 0);
        let refused = build_record(HostEvent::CapabilityRefused, &c, None, 0);

        assert_eq!(denied.action_kind, refused.action_kind);
        assert_ne!(denied.flags, refused.flags);
        assert_ne!(event_of(&denied), event_of(&refused));
        assert_eq!(denied.proof_tier, 1);
        assert_eq!(refused.proof_tier, 2);
    }

    #[test]
    fn the_isolation_claim_travels_in_the_record() {
        for claim in [
            IsolationClaim::Partition,
            IsolationClaim::OsSandboxWasm,
            IsolationClaim::WasmOnly,
        ] {
            let r = build_record(HostEvent::IsolationPrepared, &ctx(claim), None, 0);
            assert_eq!(claim_of(&r), Some(claim));
        }
    }

    #[test]
    fn records_bind_to_the_artifact_they_describe() {
        let mut other = ctx(IsolationClaim::WasmOnly);
        other.rvf_identity = [9u8; 32];

        let a = build_record(HostEvent::IsolationPrepared, &ctx(IsolationClaim::WasmOnly), None, 0);
        let b = build_record(HostEvent::IsolationPrepared, &other, None, 0);

        assert_ne!(a.capability_hash, b.capability_hash);
        assert_ne!(a.payload, b.payload);
        assert_eq!(&a.payload[..], &[7u8; 32][..8]);
    }

    #[test]
    fn an_event_with_no_class_says_so_rather_than_naming_class_zero() {
        let r = build_record(HostEvent::ModuleAdmitted, &ctx(IsolationClaim::WasmOnly), None, 0);
        assert_eq!(r.aux[1], NO_CLASS);
        assert_ne!(r.aux[1], CapabilityClass::Memory as u8);
        assert_eq!(r.target_object_id, 0);
    }

    #[test]
    fn emitted_records_chain() {
        let log = WitnessLog::<32>::new();
        let c = ctx(IsolationClaim::WasmOnly);
        for event in HostEvent::ALL {
            emit(&log, event, &c, None, 0);
        }
        let records: Vec<_> = (0..HostEvent::ALL.len())
            .filter_map(|i| log.get(i))
            .collect();
        assert_eq!(records.len(), 6);
        assert!(rvm_witness::verify_chain(&records).is_ok());
    }

    #[test]
    fn every_event_has_a_distinct_code_that_round_trips() {
        let c = ctx(IsolationClaim::WasmOnly);
        let mut codes: Vec<u8> = Vec::new();
        for event in HostEvent::ALL {
            let r = build_record(event, &c, None, 0);
            assert_eq!(event_of(&r), Some(event));
            assert_eq!(r.flags, event as u8);
            codes.push(event as u8);
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), HostEvent::ALL.len());
    }

    #[test]
    fn refusal_events_are_the_ones_recorded_as_rejected() {
        for event in HostEvent::ALL {
            let rejected = event.action_kind() == ActionKind::ProofRejected;
            assert_eq!(rejected, event.is_refusal(), "{event:?}");
        }
    }

    #[test]
    fn the_detail_word_survives_the_round_trip() {
        let r = build_record(
            HostEvent::ModuleRefused,
            &ctx(IsolationClaim::WasmOnly),
            None,
            0x0DED_BEEF,
        );
        assert_eq!(u32::from_le_bytes(r.aux[4..8].try_into().unwrap()), 0x0DED_BEEF);
    }
}
