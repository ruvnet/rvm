//! Canonical, signer-bound HostedIOS policy parsing.

use core::fmt;
use rvm_host::VerifiedPackage;
use rvm_rvf::{sha256, CapabilityClass, CAPABILITY_DECLARATION_KEY};

/// Signed metadata key for the HostedIOS policy version.
pub const IOS_POLICY_VERSION_KEY: &str = "rvf.ios-policy-version";
/// Signed metadata key for fine-grained HostedIOS scopes.
pub const IOS_CAPABILITY_KEY: &str = "rvf.ios-capabilities";

/// Fine-grained rights understood by HostedIOS v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum IosScope {
    /// Read camera frames through a host-owned AVFoundation/ARKit session.
    CameraRead = 1,
    /// Read ARKit scene depth or reconstruction; also requires camera.read.
    LidarRead = 2,
    /// Read a bounded Core Motion stream.
    ImuRead = 3,
    /// Scan only an operator-allowlisted BLE service set.
    BleScan = 4,
    /// Connect to an operator-allowlisted network resource.
    NetworkConnect = 5,
    /// Submit an allowlisted, precompiled Metal workload.
    GpuExecute = 6,
    /// Run an allowlisted compiled Core ML model.
    ModelInfer = 7,
    /// Read an owned, bounded logical memory region.
    MemoryRead = 8,
    /// Write an owned, bounded logical memory region.
    MemoryWrite = 9,
    /// Read the host-provided clock.
    ClockRead = 10,
}

impl IosScope {
    /// Every v1 scope in canonical wire order.
    pub const ALL: [Self; 10] = [
        Self::CameraRead,
        Self::LidarRead,
        Self::ImuRead,
        Self::BleScan,
        Self::NetworkConnect,
        Self::GpuExecute,
        Self::ModelInfer,
        Self::MemoryRead,
        Self::MemoryWrite,
        Self::ClockRead,
    ];

    /// Stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CameraRead => "camera.read",
            Self::LidarRead => "lidar.read",
            Self::ImuRead => "imu.read",
            Self::BleScan => "ble.scan",
            Self::NetworkConnect => "network.connect",
            Self::GpuExecute => "gpu.execute",
            Self::ModelInfer => "model.infer",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::ClockRead => "clock.read",
        }
    }

    /// Parse one exact wire name.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == value)
    }

    /// Broad RVF class that must also be present in signed metadata.
    #[must_use]
    pub const fn broad_class(self) -> CapabilityClass {
        match self {
            Self::CameraRead | Self::LidarRead | Self::ImuRead | Self::BleScan => {
                CapabilityClass::Sensor
            }
            Self::NetworkConnect => CapabilityClass::Network,
            Self::GpuExecute => CapabilityClass::Gpu,
            Self::ModelInfer => CapabilityClass::Model,
            Self::MemoryRead | Self::MemoryWrite => CapabilityClass::Memory,
            Self::ClockRead => CapabilityClass::Clock,
        }
    }

    /// Stable numeric code exposed to the WASM `rvm.request` import.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Decode a WASM host-call scope code.
    #[must_use]
    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.code() == code)
    }
}

impl fmt::Display for IosScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A canonical policy parsed only from exact trusted signed metadata bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosPolicy {
    version: u32,
    scopes: Vec<IosScope>,
    digest: [u8; 32],
    trusted_signer: [u8; 32],
    rvf_identity: [u8; 32],
}

impl IosPolicy {
    /// Parse and bind HostedIOS policy to `package`.
    ///
    /// The metadata is canonical only when it contains exactly three lines in
    /// this order, with enum-order comma lists and no whitespace or trailing
    /// newline. The broad capability list must exactly equal the package's
    /// resolved mapping, closing the legacy path where unsigned metadata could
    /// otherwise add a broad class.
    ///
    /// # Errors
    ///
    /// Refuses metadata that is unsigned/untrusted, malformed, noncanonical,
    /// unsupported, inconsistent with the package, or violates a dependency.
    pub fn from_signed_metadata(
        package: &VerifiedPackage,
        metadata: &[u8],
    ) -> Result<Self, IosPolicyError> {
        let trusted_signer = package
            .trusted_metadata_signer(metadata)
            .ok_or(IosPolicyError::MetadataNotTrusted)?;
        if package.trusted_root_signer() != Some(trusted_signer) {
            return Err(IosPolicyError::RootNotTrustedByPolicySigner);
        }
        let text = core::str::from_utf8(metadata).map_err(|_| IosPolicyError::InvalidUtf8)?;
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() != 3 {
            return Err(IosPolicyError::Malformed);
        }
        let base_value = value_for(lines[0], CAPABILITY_DECLARATION_KEY)?;
        let version_value = value_for(lines[1], IOS_POLICY_VERSION_KEY)?;
        let ios_value = value_for(lines[2], IOS_CAPABILITY_KEY)?;
        let version = version_value
            .parse::<u32>()
            .map_err(|_| IosPolicyError::UnsupportedVersion)?;
        if version != crate::HOSTED_IOS_CONTRACT_VERSION {
            return Err(IosPolicyError::UnsupportedVersion);
        }

        let base = parse_base_classes(base_value)?;
        if base != package.granted_classes() {
            return Err(IosPolicyError::BroadCapabilityMismatch);
        }
        let scopes = parse_scopes(ios_value)?;
        for scope in &scopes {
            if !base.contains(&scope.broad_class()) {
                return Err(IosPolicyError::MissingBroadCapability(*scope));
            }
        }
        for class in &base {
            if !scopes.iter().any(|scope| scope.broad_class() == *class) {
                return Err(IosPolicyError::UnscopedBroadCapability(*class));
            }
        }
        if scopes.contains(&IosScope::LidarRead) && !scopes.contains(&IosScope::CameraRead) {
            return Err(IosPolicyError::MissingDependency {
                scope: IosScope::LidarRead,
                requires: IosScope::CameraRead,
            });
        }

        let canonical = canonical_text(&base, version, &scopes);
        if canonical.as_bytes() != metadata {
            return Err(IosPolicyError::NonCanonical);
        }
        Ok(Self {
            version,
            scopes,
            digest: sha256(metadata),
            trusted_signer,
            rvf_identity: *package.identity(),
        })
    }

    /// Policy contract version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// SHA-256 of the exact signer-bound canonical policy bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Trusted key shared by the policy and root manifest.
    #[must_use]
    pub const fn trusted_signer(&self) -> &[u8; 32] {
        &self.trusted_signer
    }

    /// Whole-container identity from the package that supplied this policy.
    #[must_use]
    pub const fn rvf_identity(&self) -> &[u8; 32] {
        &self.rvf_identity
    }

    /// Whether the signed artifact requested `scope`.
    #[must_use]
    pub fn permits(&self, scope: IosScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Canonically ordered scopes.
    #[must_use]
    pub fn scopes(&self) -> &[IosScope] {
        &self.scopes
    }
}

/// Why signer-bound HostedIOS policy was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosPolicyError {
    /// Exact bytes were not among trusted signed metadata identities.
    MetadataNotTrusted,
    /// The root manifest was not signed by the same trusted key as policy.
    RootNotTrustedByPolicySigner,
    /// Metadata is not UTF-8.
    InvalidUtf8,
    /// Required lines or key/value structure are absent.
    Malformed,
    /// Policy version is absent, invalid, or unsupported.
    UnsupportedVersion,
    /// A broad capability name is unknown or duplicated.
    InvalidBroadCapability,
    /// A fine-grained scope name is unknown or duplicated.
    InvalidScope,
    /// Broad signed declarations do not equal the package mapping.
    BroadCapabilityMismatch,
    /// A fine scope lacks its corresponding broad class.
    MissingBroadCapability(IosScope),
    /// A broad class exists without a fine-grained HostedIOS scope.
    UnscopedBroadCapability(CapabilityClass),
    /// A scope lacks another required scope.
    MissingDependency {
        /// Requested scope.
        scope: IosScope,
        /// Scope that must also be present.
        requires: IosScope,
    },
    /// Semantically valid fields were not encoded canonically.
    NonCanonical,
}

impl fmt::Display for IosPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetadataNotTrusted => f.write_str("HostedIOS metadata is not trusted and signed"),
            Self::RootNotTrustedByPolicySigner => {
                f.write_str("HostedIOS root manifest is not trusted by the policy signer")
            }
            Self::InvalidUtf8 => f.write_str("HostedIOS metadata is not UTF-8"),
            Self::Malformed => f.write_str("HostedIOS metadata is malformed"),
            Self::UnsupportedVersion => f.write_str("HostedIOS policy version is unsupported"),
            Self::InvalidBroadCapability => f.write_str("broad capability list is invalid"),
            Self::InvalidScope => f.write_str("HostedIOS scope list is invalid"),
            Self::BroadCapabilityMismatch => {
                f.write_str("signed broad capabilities do not match the package mapping")
            }
            Self::MissingBroadCapability(scope) => {
                write!(f, "scope {scope} lacks its broad RVF capability")
            }
            Self::UnscopedBroadCapability(class) => {
                write!(f, "broad capability {class} has no HostedIOS scope")
            }
            Self::MissingDependency { scope, requires } => {
                write!(f, "scope {scope} requires {requires}")
            }
            Self::NonCanonical => f.write_str("HostedIOS policy encoding is noncanonical"),
        }
    }
}

fn value_for<'a>(line: &'a str, key: &str) -> Result<&'a str, IosPolicyError> {
    line.strip_prefix(key)
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or(IosPolicyError::Malformed)
}

fn parse_base_classes(value: &str) -> Result<Vec<CapabilityClass>, IosPolicyError> {
    parse_list(
        value,
        CapabilityClass::from_wire,
        IosPolicyError::InvalidBroadCapability,
    )
}

fn parse_scopes(value: &str) -> Result<Vec<IosScope>, IosPolicyError> {
    parse_list(value, IosScope::from_wire, IosPolicyError::InvalidScope)
}

fn parse_list<T: Copy + Ord>(
    value: &str,
    parse: impl Fn(&str) -> Option<T>,
    error: IosPolicyError,
) -> Result<Vec<T>, IosPolicyError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for raw in value.split(',') {
        let item = parse(raw).ok_or(error)?;
        if values.contains(&item) {
            return Err(error);
        }
        values.push(item);
    }
    let mut sorted = values.clone();
    sorted.sort_unstable();
    if values != sorted {
        return Err(IosPolicyError::NonCanonical);
    }
    Ok(values)
}

fn canonical_text(base: &[CapabilityClass], version: u32, scopes: &[IosScope]) -> String {
    let base = base
        .iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let scopes = scopes
        .iter()
        .map(|scope| scope.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{CAPABILITY_DECLARATION_KEY}={base}\n{IOS_POLICY_VERSION_KEY}={version}\n{IOS_CAPABILITY_KEY}={scopes}"
    )
}
