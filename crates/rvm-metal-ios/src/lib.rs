//! Typed `gpu.execute` dispatch for HostedIOS.
//!
//! This crate does not create a Metal device or command queue. The iOS app
//! owns those Apple objects and implements [`MetalHost`]. This boundary proves
//! policy, digest allowlisting, bounds, and receipts; it does not claim GPU
//! partitioning, context isolation, preemption, or physical-device exclusivity.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use rvm_host_ios::{
    DispatchError, DispatchFailure, GovernedIosRuntime, IosOperationRequest, IosScope,
};

/// Maximum buffer bytes admitted by this typed adapter in one dispatch.
pub const MAX_METAL_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum threadgroups admitted by this typed adapter in one dispatch.
pub const MAX_METAL_THREADGROUPS: u32 = 1 << 20;
/// Maximum duration admitted by one typed Metal dispatch.
pub const MAX_METAL_DURATION_MS: u32 = 30_000;
/// Stable native failure when a reported GPU duration exceeds the request.
pub const METAL_RESULT_DURATION_FAILURE: u32 = 1;

/// One allowlisted precompiled Metal dispatch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetalRequest {
    /// SHA-256 of the signed/allowlisted metallib + function + buffer schema.
    pub pipeline_digest: [u8; 32],
    /// Total bytes across host-owned buffers made visible to this operation.
    pub buffer_bytes: u64,
    /// Total submitted threadgroups.
    pub threadgroups: u32,
    /// Maximum requested duration in milliseconds.
    pub duration_ms: u32,
}

/// Result the native Metal bridge may report without exposing buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetalResult {
    /// Completed command-buffer GPU duration in nanoseconds, when available.
    /// Zero means the native host did not expose a measurement.
    pub measured_gpu_ns: u64,
}

/// Why a Metal request was rejected before HostedIOS authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetalRequestError {
    /// The signed pipeline identity was absent.
    MissingPipeline,
    /// The buffer-byte count was zero or exceeded the adapter ceiling.
    InvalidBufferBytes,
    /// The threadgroup count was zero or exceeded the adapter ceiling.
    InvalidThreadgroups,
    /// The requested duration was zero or exceeded the adapter ceiling.
    InvalidDuration,
}

/// Convert a typed Metal request into the exact HostedIOS operation record.
#[must_use]
pub const fn metal_operation_request(request: MetalRequest) -> IosOperationRequest {
    IosOperationRequest {
        scope: IosScope::GpuExecute,
        resource_digest: request.pipeline_digest,
        units: request.buffer_bytes,
        duration_ms: request.duration_ms,
        options: request.threadgroups,
    }
}

/// Validate a Metal request and return its exact HostedIOS operation record.
///
/// # Errors
///
/// Refuses absent identities and zero or oversized workload bounds.
pub fn validate_metal_request(
    request: MetalRequest,
) -> Result<IosOperationRequest, MetalRequestError> {
    if request.pipeline_digest == [0; 32] {
        return Err(MetalRequestError::MissingPipeline);
    }
    if request.buffer_bytes == 0 || request.buffer_bytes > MAX_METAL_BUFFER_BYTES {
        return Err(MetalRequestError::InvalidBufferBytes);
    }
    if request.threadgroups == 0 || request.threadgroups > MAX_METAL_THREADGROUPS {
        return Err(MetalRequestError::InvalidThreadgroups);
    }
    if request.duration_ms == 0 || request.duration_ms > MAX_METAL_DURATION_MS {
        return Err(MetalRequestError::InvalidDuration);
    }
    Ok(metal_operation_request(request))
}

/// Enforce a reported GPU-duration postcondition when the native host exposes one.
///
/// A zero duration remains an explicit "not measured" result. Wall-clock
/// completion is checked separately by the governed runtime.
///
/// # Errors
///
/// Returns a stable native failure when a non-zero measured duration exceeds
/// the request's admitted duration.
pub fn validate_metal_result(
    request: MetalRequest,
    result: MetalResult,
) -> Result<MetalResult, DispatchFailure> {
    let maximum_ns = u64::from(request.duration_ms) * 1_000_000;
    if result.measured_gpu_ns == 0 || result.measured_gpu_ns <= maximum_ns {
        Ok(result)
    } else {
        Err(DispatchFailure {
            code: METAL_RESULT_DURATION_FAILURE,
        })
    }
}

/// Native Metal callback owned by the application.
pub trait MetalHost {
    /// Encode/submit only the prevalidated request using host-owned resources.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code.
    fn execute(&mut self, request: MetalRequest) -> Result<MetalResult, DispatchFailure>;
    /// Sample a monotonic completion timestamp.
    fn now_ns(&mut self) -> u64;
}

/// Validate, authorize, witness, and dispatch one Metal request.
///
/// # Errors
///
/// Refuses zero/oversize requests before native code, any HostedIOS policy or
/// platform denial, and any native bridge failure.
pub fn dispatch_metal(
    runtime: &mut GovernedIosRuntime,
    started_ns: u64,
    request: MetalRequest,
    host: &mut impl MetalHost,
) -> Result<MetalResult, DispatchError> {
    let operation = validate_metal_request(request).map_err(|_| {
        runtime.refuse_invalid_request(metal_operation_request(request), started_ns)
    })?;
    runtime.dispatch(operation, started_ns, || {
        match host
            .execute(request)
            .and_then(|result| validate_metal_result(request, result))
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
    fn validator_preserves_options_and_rejects_excess_duration() {
        let mut request = MetalRequest {
            pipeline_digest: [1; 32],
            buffer_bytes: 4_096,
            threadgroups: 17,
            duration_ms: 25,
        };
        assert_eq!(validate_metal_request(request).unwrap().options, 17);
        request.duration_ms = MAX_METAL_DURATION_MS + 1;
        assert_eq!(
            validate_metal_request(request),
            Err(MetalRequestError::InvalidDuration)
        );
    }

    #[test]
    fn measured_gpu_duration_cannot_exceed_the_request() {
        let request = MetalRequest {
            pipeline_digest: [1; 32],
            buffer_bytes: 4_096,
            threadgroups: 1,
            duration_ms: 1,
        };
        assert_eq!(
            validate_metal_result(
                request,
                MetalResult {
                    measured_gpu_ns: 1_000_001,
                },
            ),
            Err(DispatchFailure {
                code: METAL_RESULT_DURATION_FAILURE,
            })
        );
    }
}
