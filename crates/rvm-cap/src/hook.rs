//! Capability-bound authorization for lifecycle-hook updates.
//!
//! A lifecycle hook can execute outside the model decision path, so changing a
//! hook binding is treated as a fresh privileged control-plane event. This
//! module performs deterministic scope validation only. A successful result is
//! not a substitute for the independently issued RVM capability that authorized
//! the update grant.

use rvm_types::CapRights;

/// Runtime lifecycle events that may have host-side hooks attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HookEvent {
    /// Session initialization.
    SessionStart = 0,
    /// Immediately before a tool invocation.
    BeforeTool = 1,
    /// Immediately after a tool invocation.
    AfterTool = 2,
    /// Immediately before a file write.
    BeforeFileWrite = 3,
    /// Immediately after a file write.
    AfterFileWrite = 4,
    /// Project or workspace open.
    ProjectOpen = 5,
    /// Dependency update or installation lifecycle event.
    DependencyUpdate = 6,
    /// Plugin update lifecycle event.
    PluginUpdate = 7,
}

impl HookEvent {
    /// Returns the bit used to represent this event in an allowed-event mask.
    #[must_use]
    pub const fn bit(self) -> u16 {
        1u16 << (self as u8)
    }
}

/// Independently authorized scope for one lifecycle-hook update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookUpdateGrant {
    /// Digest of the plugin identity that may be updated.
    pub plugin_digest: [u8; 32],
    /// Digest of the exact previously approved plugin manifest.
    pub previous_manifest_digest: [u8; 32],
    /// Bit mask of lifecycle events this grant permits.
    pub allowed_events: u16,
    /// Maximum effective capability rights that the updated hook may receive.
    pub max_rights: CapRights,
    /// Capability epoch in which the grant is valid.
    pub epoch: u32,
    /// Last monotonic tick on which the grant remains valid.
    pub expires_at_tick: u64,
}

/// Requested lifecycle-hook update presented to the authorization gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookUpdateRequest {
    /// Digest of the plugin identity being updated.
    pub plugin_digest: [u8; 32],
    /// Digest of the manifest from which this update claims continuity.
    pub previous_manifest_digest: [u8; 32],
    /// Digest of the new manifest proposed for approval.
    pub next_manifest_digest: [u8; 32],
    /// Digest of the exact host-side command or executable binding.
    pub command_digest: [u8; 32],
    /// Lifecycle event requested for the binding.
    pub event: HookEvent,
    /// Effective rights requested by the hook binding.
    pub requested_rights: CapRights,
    /// Capability epoch observed at validation time.
    pub epoch: u32,
    /// Current monotonic tick observed at validation time.
    pub now_tick: u64,
}

/// Validated hook binding returned after all deterministic scope checks pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookBinding {
    /// Digest of the plugin identity bound to this result.
    pub plugin_digest: [u8; 32],
    /// Digest of the newly approved manifest.
    pub manifest_digest: [u8; 32],
    /// Digest of the exact approved host-side command.
    pub command_digest: [u8; 32],
    /// Approved lifecycle event.
    pub event: HookEvent,
    /// Approved effective capability rights.
    pub rights: CapRights,
    /// Capability epoch in which this binding was validated.
    pub epoch: u32,
}

/// Deterministic lifecycle-hook update validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookUpdateError {
    /// The request targets a different plugin identity than the grant.
    PluginMismatch,
    /// The request does not continue from the exact approved prior manifest.
    PreviousManifestMismatch,
    /// The requested lifecycle event is outside the grant scope.
    EventNotAllowed,
    /// The requested effective rights exceed the grant ceiling.
    RightsEscalation,
    /// The request was evaluated under a different capability epoch.
    EpochMismatch,
    /// The grant is no longer fresh at the supplied monotonic tick.
    GrantExpired,
}

/// Result type for lifecycle-hook update validation.
pub type HookUpdateResult<T> = core::result::Result<T, HookUpdateError>;

/// Validates one lifecycle-hook update against an independently issued grant.
///
/// The function is intentionally model-independent and allocation-free. It
/// proves only that the requested binding remains inside the grant's declared
/// identity, continuity, event, rights, epoch, and freshness envelope.
/// Callers must separately prove that the grant itself was issued by an
/// authenticated RVM authority.
///
/// # Errors
///
/// Returns [`HookUpdateError::PluginMismatch`] when plugin identity differs,
/// [`HookUpdateError::PreviousManifestMismatch`] when approved-manifest
/// continuity is not exact, [`HookUpdateError::EventNotAllowed`] when the
/// requested lifecycle event is outside the grant, and
/// [`HookUpdateError::RightsEscalation`] when requested rights exceed the
/// declared ceiling. Returns [`HookUpdateError::EpochMismatch`] for stale or
/// foreign capability epochs and [`HookUpdateError::GrantExpired`] after the
/// grant's monotonic expiry tick.
pub fn validate_hook_update(
    grant: &HookUpdateGrant,
    request: &HookUpdateRequest,
) -> HookUpdateResult<HookBinding> {
    if request.plugin_digest != grant.plugin_digest {
        return Err(HookUpdateError::PluginMismatch);
    }
    if request.previous_manifest_digest != grant.previous_manifest_digest {
        return Err(HookUpdateError::PreviousManifestMismatch);
    }
    if grant.allowed_events & request.event.bit() == 0 {
        return Err(HookUpdateError::EventNotAllowed);
    }
    if !grant.max_rights.contains(request.requested_rights) {
        return Err(HookUpdateError::RightsEscalation);
    }
    if request.epoch != grant.epoch {
        return Err(HookUpdateError::EpochMismatch);
    }
    if request.now_tick > grant.expires_at_tick {
        return Err(HookUpdateError::GrantExpired);
    }

    Ok(HookBinding {
        plugin_digest: request.plugin_digest,
        manifest_digest: request.next_manifest_digest,
        command_digest: request.command_digest,
        event: request.event,
        rights: request.requested_rights,
        epoch: request.epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLUGIN: [u8; 32] = [1; 32];
    const PREVIOUS: [u8; 32] = [2; 32];
    const NEXT: [u8; 32] = [3; 32];
    const COMMAND: [u8; 32] = [4; 32];

    fn grant() -> HookUpdateGrant {
        HookUpdateGrant {
            plugin_digest: PLUGIN,
            previous_manifest_digest: PREVIOUS,
            allowed_events: HookEvent::PluginUpdate.bit() | HookEvent::BeforeTool.bit(),
            max_rights: CapRights::READ.union(CapRights::EXECUTE),
            epoch: 7,
            expires_at_tick: 100,
        }
    }

    fn request() -> HookUpdateRequest {
        HookUpdateRequest {
            plugin_digest: PLUGIN,
            previous_manifest_digest: PREVIOUS,
            next_manifest_digest: NEXT,
            command_digest: COMMAND,
            event: HookEvent::PluginUpdate,
            requested_rights: CapRights::EXECUTE,
            epoch: 7,
            now_tick: 99,
        }
    }

    #[test]
    fn accepts_update_inside_authorized_envelope() {
        let binding = validate_hook_update(&grant(), &request()).unwrap();
        assert_eq!(binding.plugin_digest, PLUGIN);
        assert_eq!(binding.manifest_digest, NEXT);
        assert_eq!(binding.command_digest, COMMAND);
        assert_eq!(binding.event, HookEvent::PluginUpdate);
        assert_eq!(binding.rights, CapRights::EXECUTE);
        assert_eq!(binding.epoch, 7);
    }

    #[test]
    fn rejects_plugin_substitution() {
        let mut candidate = request();
        candidate.plugin_digest = [9; 32];
        assert_eq!(
            validate_hook_update(&grant(), &candidate),
            Err(HookUpdateError::PluginMismatch)
        );
    }

    #[test]
    fn rejects_manifest_discontinuity() {
        let mut candidate = request();
        candidate.previous_manifest_digest = [9; 32];
        assert_eq!(
            validate_hook_update(&grant(), &candidate),
            Err(HookUpdateError::PreviousManifestMismatch)
        );
    }

    #[test]
    fn rejects_event_widening() {
        let mut candidate = request();
        candidate.event = HookEvent::SessionStart;
        assert_eq!(
            validate_hook_update(&grant(), &candidate),
            Err(HookUpdateError::EventNotAllowed)
        );
    }

    #[test]
    fn rejects_rights_widening() {
        let mut candidate = request();
        candidate.requested_rights = CapRights::EXECUTE.union(CapRights::WRITE);
        assert_eq!(
            validate_hook_update(&grant(), &candidate),
            Err(HookUpdateError::RightsEscalation)
        );
    }

    #[test]
    fn rejects_epoch_mismatch() {
        let mut candidate = request();
        candidate.epoch = 8;
        assert_eq!(
            validate_hook_update(&grant(), &candidate),
            Err(HookUpdateError::EpochMismatch)
        );
    }

    #[test]
    fn rejects_expired_grant() {
        let mut candidate = request();
        candidate.now_tick = 101;
        assert_eq!(
            validate_hook_update(&grant(), &candidate),
            Err(HookUpdateError::GrantExpired)
        );
    }

    #[test]
    fn accepts_exact_expiry_tick() {
        let mut candidate = request();
        candidate.now_tick = 100;
        assert!(validate_hook_update(&grant(), &candidate).is_ok());
    }

    #[test]
    fn accepts_attenuated_rights() {
        let mut candidate = request();
        candidate.requested_rights = CapRights::READ;
        let binding = validate_hook_update(&grant(), &candidate).unwrap();
        assert_eq!(binding.rights, CapRights::READ);
    }
}
