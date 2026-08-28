//! Typed sensor dispatch for HostedIOS.
//!
//! Native Apple framework objects stay in the host application. Agents receive
//! only bounded derived results or opaque handles. Stock iOS exposes no public
//! Wi-Fi CSI feed; CSI must arrive through a separately scoped network path to
//! an external RuView node.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use rvm_host_ios::{
    DispatchError, DispatchFailure, GovernedIosRuntime, IosOperationRequest, IosScope,
};

/// Maximum samples/results admitted by one typed sensor request.
pub const MAX_SENSOR_SAMPLES: u64 = 1_000_000;
/// Maximum requested sampling rate admitted by the typed adapter.
pub const MAX_SENSOR_RATE_HZ: u32 = 2_000;
/// Maximum duration admitted by one typed sensor request.
pub const MAX_SENSOR_DURATION_MS: u32 = 30_000;
/// Stable native failure when a host reports more results than requested.
pub const SENSOR_RESULT_LIMIT_FAILURE: u32 = 1;

/// Supported typed sensor surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorKind {
    /// AVFoundation/ARKit camera frames.
    Camera,
    /// ARKit scene depth or reconstruction; requires camera authorization.
    Lidar,
    /// Core Motion device-motion/accelerometer/gyro stream.
    Imu,
    /// Core Bluetooth scan constrained by a service-set digest.
    Ble,
}

impl SensorKind {
    /// Fine-grained HostedIOS scope for this sensor surface.
    #[must_use]
    pub const fn scope(self) -> IosScope {
        match self {
            Self::Camera => IosScope::CameraRead,
            Self::Lidar => IosScope::LidarRead,
            Self::Imu => IosScope::ImuRead,
            Self::Ble => IosScope::BleScan,
        }
    }
}

/// One bounded sensor request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorRequest {
    /// Sensor surface.
    pub kind: SensorKind,
    /// SHA-256 of BLE service allowlist; zero for camera/LiDAR/IMU.
    pub resource_digest: [u8; 32],
    /// Maximum samples/frames/results returned.
    pub max_samples: u64,
    /// Requested rate in hertz.
    pub rate_hz: u32,
    /// Maximum duration in milliseconds.
    pub duration_ms: u32,
}

/// Privacy-bounded native sensor outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorResult {
    /// Samples/frames/results actually delivered.
    pub delivered: u64,
}

/// Why a sensor request was rejected before HostedIOS authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorRequestError {
    /// BLE lacked a service-set digest, or a non-BLE sensor carried one.
    InvalidResourceDigest,
    /// The sample limit was zero or exceeded the adapter ceiling.
    InvalidSampleLimit,
    /// The requested rate was zero or exceeded the adapter ceiling.
    InvalidRate,
    /// The requested duration was zero or exceeded the adapter ceiling.
    InvalidDuration,
}

/// Convert a typed sensor request into the exact HostedIOS operation record.
#[must_use]
pub const fn sensor_operation_request(request: SensorRequest) -> IosOperationRequest {
    IosOperationRequest {
        scope: request.kind.scope(),
        resource_digest: request.resource_digest,
        units: request.max_samples,
        duration_ms: request.duration_ms,
        options: request.rate_hz,
    }
}

/// Validate a sensor request and return its exact HostedIOS operation record.
///
/// # Errors
///
/// Refuses zero bounds, an unbound/all-services BLE scan, or a digest attached
/// to camera, LiDAR, or IMU capture.
pub fn validate_sensor_request(
    request: SensorRequest,
) -> Result<IosOperationRequest, SensorRequestError> {
    let digest_valid = match request.kind {
        SensorKind::Ble => request.resource_digest != [0; 32],
        SensorKind::Camera | SensorKind::Lidar | SensorKind::Imu => {
            request.resource_digest == [0; 32]
        }
    };
    if !digest_valid {
        return Err(SensorRequestError::InvalidResourceDigest);
    }
    if request.max_samples == 0 || request.max_samples > MAX_SENSOR_SAMPLES {
        return Err(SensorRequestError::InvalidSampleLimit);
    }
    if request.rate_hz == 0 || request.rate_hz > MAX_SENSOR_RATE_HZ {
        return Err(SensorRequestError::InvalidRate);
    }
    if request.duration_ms == 0 || request.duration_ms > MAX_SENSOR_DURATION_MS {
        return Err(SensorRequestError::InvalidDuration);
    }
    Ok(sensor_operation_request(request))
}

/// Enforce the host result bound authenticated by a sensor request.
///
/// # Errors
///
/// Returns a stable native failure when the host reports more delivered
/// samples than the request allowed.
pub fn validate_sensor_result(
    request: SensorRequest,
    result: SensorResult,
) -> Result<SensorResult, DispatchFailure> {
    if result.delivered <= request.max_samples {
        Ok(result)
    } else {
        Err(DispatchFailure {
            code: SENSOR_RESULT_LIMIT_FAILURE,
        })
    }
}

/// Native Apple-sensor callback owned by the application.
pub trait SensorHost {
    /// Capture only the already validated request with host-owned sessions.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code.
    fn capture(&mut self, request: SensorRequest) -> Result<SensorResult, DispatchFailure>;
    /// Sample a monotonic completion timestamp.
    fn now_ns(&mut self) -> u64;
}

/// Validate, authorize, witness, and dispatch one sensor request.
///
/// # Errors
///
/// Refuses zero or oversized bounds, an unbound/all-services BLE scan, a digest
/// attached to another sensor kind, HostedIOS policy/platform denial, and
/// native failure.
pub fn dispatch_sensor(
    runtime: &mut GovernedIosRuntime,
    started_ns: u64,
    request: SensorRequest,
    host: &mut impl SensorHost,
) -> Result<SensorResult, DispatchError> {
    let operation = validate_sensor_request(request).map_err(|_| {
        runtime.refuse_invalid_request(sensor_operation_request(request), started_ns)
    })?;
    runtime.dispatch(operation, started_ns, || {
        match host
            .capture(request)
            .and_then(|result| validate_sensor_result(request, result))
        {
            Ok(result) => Ok((result, host.now_ns())),
            Err(error) => Err((error, host.now_ns())),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_preserves_rate_and_rejects_excess_rate() {
        let mut request = SensorRequest {
            kind: SensorKind::Imu,
            resource_digest: [0; 32],
            max_samples: 20,
            rate_hz: 200,
            duration_ms: 100,
        };
        assert_eq!(validate_sensor_request(request).unwrap().options, 200);
        request.rate_hz = MAX_SENSOR_RATE_HZ + 1;
        assert_eq!(
            validate_sensor_request(request),
            Err(SensorRequestError::InvalidRate)
        );
    }

    #[test]
    fn result_cannot_exceed_the_authenticated_sample_limit() {
        let request = SensorRequest {
            kind: SensorKind::Camera,
            resource_digest: [0; 32],
            max_samples: 2,
            rate_hz: 30,
            duration_ms: 100,
        };
        assert_eq!(
            validate_sensor_result(request, SensorResult { delivered: 3 }),
            Err(DispatchFailure {
                code: SENSOR_RESULT_LIMIT_FAILURE,
            })
        );
    }
}
