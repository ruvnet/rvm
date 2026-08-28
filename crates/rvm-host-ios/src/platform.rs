//! iOS facts and the isolation profile they can truthfully support.

use sha2::{Digest, Sha256};

const FACTS_DOMAIN: &[u8] = b"RVM-HOSTED-IOS-PLATFORM-FACTS-V1";

/// Current operating-system authorization for a protected resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IosAuthorization {
    /// The host may ask through user-facing UI, but access is not yet granted.
    NotDetermined = 0,
    /// The user or system denied the request.
    Denied = 1,
    /// Device policy restricts the resource.
    Restricted = 2,
    /// The operating system currently authorizes access.
    Authorized = 3,
    /// The API or resource does not exist on this device.
    Unavailable = 4,
}

impl IosAuthorization {
    /// Whether access is currently authorized. `NotDetermined` is false.
    #[must_use]
    pub const fn is_authorized(self) -> bool {
        matches!(self, Self::Authorized)
    }
}

/// Platform facts sampled by the native host immediately before dispatch.
///
/// These values are evidence supplied by the app integration. This Rust crate
/// cannot query AVFoundation, ARKit, Core Motion, Core Bluetooth, Metal, or
/// Core ML itself, so a false statement here remains inside the native trusted
/// computing base and must be tested on physical hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// These are orthogonal OS/runtime observations, not interchangeable state
// flags; collapsing them would weaken the evidence digest.
#[allow(clippy::struct_excessive_bools)]
pub struct IosPlatformFacts {
    /// The application sandbox is present for the installed app.
    pub app_sandbox: bool,
    /// AVFoundation video authorization.
    pub camera: IosAuthorization,
    /// The app obtained explicit, purpose-specific consent for this sensor session.
    pub explicit_sensor_consent: bool,
    /// A clear visual or audible recording indicator is currently active.
    pub recording_indicator_active: bool,
    /// Whether ARKit exposes requested scene depth/reconstruction features.
    pub lidar_supported: bool,
    /// Core Motion authorization/availability for the requested stream.
    pub motion: IosAuthorization,
    /// Core Bluetooth authorization.
    pub bluetooth: IosAuthorization,
    /// Whether the host operator enabled bounded outbound networking.
    pub network_enabled: bool,
    /// Whether Metal is available for allowlisted precompiled pipelines.
    pub metal_available: bool,
    /// Whether Core ML is available for an allowlisted compiled model.
    pub core_ml_available: bool,
    /// Whether the process is in Low Power Mode.
    pub low_power_mode: bool,
    /// ProcessInfo thermal state encoded as nominal=0, fair=1, serious=2,
    /// critical=3. Unknown values must be mapped to critical by the host.
    pub thermal_state: u8,
}

impl Default for IosPlatformFacts {
    fn default() -> Self {
        Self {
            app_sandbox: false,
            camera: IosAuthorization::NotDetermined,
            explicit_sensor_consent: false,
            recording_indicator_active: false,
            lidar_supported: false,
            motion: IosAuthorization::NotDetermined,
            bluetooth: IosAuthorization::NotDetermined,
            network_enabled: false,
            metal_available: false,
            core_ml_available: false,
            low_power_mode: false,
            thermal_state: 3,
        }
    }
}

impl IosPlatformFacts {
    /// SHA-256 of the complete, canonically encoded host-supplied fact set.
    ///
    /// The digest binds receipts to what the native app reported at decision
    /// time without retaining device or sensor data. It is evidence of the
    /// app's assertion, not remote attestation of iOS or Apple hardware.
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(FACTS_DOMAIN);
        hasher.update([
            u8::from(self.app_sandbox),
            self.camera as u8,
            u8::from(self.explicit_sensor_consent),
            u8::from(self.recording_indicator_active),
            u8::from(self.lidar_supported),
            self.motion as u8,
            self.bluetooth as u8,
            u8::from(self.network_enabled),
            u8::from(self.metal_available),
            u8::from(self.core_ml_available),
            u8::from(self.low_power_mode),
            self.thermal_state,
        ]);
        let bytes = hasher.finalize();
        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes);
        digest
    }
}

/// Honest HostedIOS isolation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedIosProfile {
    /// Policy checks exist, but the app sandbox was not evidenced.
    PolicyShell,
    /// iOS app sandbox plus policy, without a live guest interpreter.
    IosAppSandboxPolicy,
    /// iOS app sandbox plus a live fuel/memory-bounded WASM interpreter.
    IosAppSandboxWasm,
}

impl HostedIosProfile {
    /// Derive the strongest profile a caller-supplied platform fact set can
    /// establish on its own. Interpreter activity is runtime-owned and cannot
    /// be asserted through this public input.
    #[must_use]
    pub const fn derive(facts: &IosPlatformFacts) -> Self {
        if facts.app_sandbox {
            Self::IosAppSandboxPolicy
        } else {
            Self::PolicyShell
        }
    }

    pub(crate) const fn derive_for_turn(
        facts: &IosPlatformFacts,
        interpreter_active: bool,
    ) -> Self {
        if facts.app_sandbox && interpreter_active {
            Self::IosAppSandboxWasm
        } else {
            Self::derive(facts)
        }
    }

    /// Stable receipt/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyShell => "hosted-ios/policy-shell",
            Self::IosAppSandboxPolicy => "hosted-ios/app-sandbox+policy",
            Self::IosAppSandboxWasm => "hosted-ios/app-sandbox+wasm",
        }
    }

    /// Stable numeric receipt code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::PolicyShell => 1,
            Self::IosAppSandboxPolicy => 2,
            Self::IosAppSandboxWasm => 3,
        }
    }
}

/// Guarantees HostedIOS explicitly does not make on stock iOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// The explicit all-false surface prevents a caller from inferring one absent
// hardware guarantee from another.
#[allow(clippy::struct_excessive_bools)]
pub struct HostedIosNonGuarantees {
    /// No app-controlled stage-2 address translation.
    pub stage2_mmu: bool,
    /// No app-controlled IOMMU.
    pub iommu: bool,
    /// No hypervisor hardware partition.
    pub hardware_partition: bool,
    /// No exclusive physical sensor or accelerator lease.
    pub physical_device_exclusivity: bool,
    /// No RVM-controlled GPU context isolation.
    pub gpu_context_isolation: bool,
    /// No RVM measured boot claim.
    pub measured_boot: bool,
    /// No guarantee that Core ML selected the Neural Engine.
    pub exact_ane_selection: bool,
    /// No hard real-time guarantee.
    pub hard_realtime: bool,
    /// No guarantee iOS keeps the app alive in the background.
    pub background_liveness: bool,
}

impl HostedIosNonGuarantees {
    /// The fixed, all-false stock-iOS guarantee set.
    pub const STOCK_IOS: Self = Self {
        stage2_mmu: false,
        iommu: false,
        hardware_partition: false,
        physical_device_exclusivity: false,
        gpu_context_isolation: false,
        measured_boot: false,
        exact_ane_selection: false,
        hard_realtime: false,
        background_liveness: false,
    };
}
