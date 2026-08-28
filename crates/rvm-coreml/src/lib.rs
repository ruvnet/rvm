//! Typed `model.infer` dispatch for HostedIOS.
//!
//! [`RequestedComputePolicy`] is an allowed compute-unit set passed to Core
//! ML. It never proves that an inference ran on the Neural Engine, GPU, or any
//! particular core. Physical-device Instruments evidence is separate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use rvm_host_ios::{
    DispatchError, DispatchFailure, GovernedIosRuntime, IosOperationRequest, IosScope,
};

/// Maximum input elements admitted by one typed inference request.
pub const MAX_COREML_INPUT_ELEMENTS: u64 = 16_777_216;
/// Maximum batch size admitted by one typed inference request.
pub const MAX_COREML_BATCH: u32 = 256;
/// Maximum duration admitted by one typed inference request.
pub const MAX_COREML_DURATION_MS: u32 = 30_000;
/// Maximum output elements accepted from one typed inference.
pub const MAX_COREML_OUTPUT_ELEMENTS: u64 = 16_777_216;
/// Stable native failure when an output exceeds the typed adapter ceiling.
pub const COREML_RESULT_LIMIT_FAILURE: u32 = 1;

/// Core ML compute-unit set requested from the native host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RequestedComputePolicy {
    /// CPU only.
    CpuOnly = 1,
    /// CPU and GPU allowed.
    CpuAndGpu = 2,
    /// CPU and Neural Engine allowed; actual placement remains opaque.
    CpuAndNeuralEngine = 3,
    /// All Core ML compute units allowed; actual placement remains opaque.
    All = 4,
}

/// One allowlisted compiled-model inference request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreMlRequest {
    /// SHA-256 of compiled model identity + validated input/output schema.
    pub model_digest: [u8; 32],
    /// Number of tensor elements across bounded inputs.
    pub input_elements: u64,
    /// Requested batch size.
    pub batch: u32,
    /// Core ML allowed compute-unit set, not proof of actual placement.
    pub compute_policy: RequestedComputePolicy,
    /// Maximum requested duration in milliseconds.
    pub duration_ms: u32,
}

/// Privacy-bounded native inference outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreMlResult {
    /// Number of validated output elements returned to the caller.
    pub output_elements: u64,
}

/// Why a Core ML request was rejected before HostedIOS authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreMlRequestError {
    /// The compiled-model identity was absent.
    MissingModel,
    /// The input element count was zero or exceeded the adapter ceiling.
    InvalidInput,
    /// The batch size was zero or exceeded the adapter ceiling.
    InvalidBatch,
    /// Input elements multiplied by batch cannot be represented as `u64`.
    WorkUnitsOverflow,
    /// The requested duration was zero or exceeded the adapter ceiling.
    InvalidDuration,
}

/// Convert a typed Core ML request into its HostedIOS operation record.
///
/// An overflowing element-by-batch product is represented as `u64::MAX` only
/// for a refusal receipt; [`validate_coreml_request`] never accepts it.
#[must_use]
pub fn coreml_operation_request(request: CoreMlRequest) -> IosOperationRequest {
    IosOperationRequest {
        scope: IosScope::ModelInfer,
        resource_digest: request.model_digest,
        units: request
            .input_elements
            .saturating_mul(u64::from(request.batch)),
        duration_ms: request.duration_ms,
        options: request.compute_policy as u32,
    }
}

/// Validate a Core ML request and return its exact HostedIOS operation record.
///
/// `compute_policy` identifies compute units the native app may request from
/// Core ML. It is not evidence that Apple placed execution on the Neural
/// Engine, GPU, or any specific processor.
///
/// # Errors
///
/// Refuses absent model identity, empty work, multiplication overflow, or a
/// zero duration.
pub fn validate_coreml_request(
    request: CoreMlRequest,
) -> Result<IosOperationRequest, CoreMlRequestError> {
    if request.model_digest == [0; 32] {
        return Err(CoreMlRequestError::MissingModel);
    }
    if request.input_elements == 0 || request.input_elements > MAX_COREML_INPUT_ELEMENTS {
        return Err(CoreMlRequestError::InvalidInput);
    }
    if request.batch == 0 || request.batch > MAX_COREML_BATCH {
        return Err(CoreMlRequestError::InvalidBatch);
    }
    if request
        .input_elements
        .checked_mul(u64::from(request.batch))
        .is_none()
    {
        return Err(CoreMlRequestError::WorkUnitsOverflow);
    }
    if request.duration_ms == 0 || request.duration_ms > MAX_COREML_DURATION_MS {
        return Err(CoreMlRequestError::InvalidDuration);
    }
    Ok(coreml_operation_request(request))
}

/// Enforce the absolute output ceiling after native inference.
///
/// The allowlisted `model_digest` is expected to bind the more specific output
/// schema. This check prevents a compromised or faulty bridge from returning
/// an unbounded result count.
///
/// # Errors
///
/// Returns a stable native failure when the output is larger than the typed
/// adapter ceiling.
pub fn validate_coreml_result(result: CoreMlResult) -> Result<CoreMlResult, DispatchFailure> {
    if result.output_elements <= MAX_COREML_OUTPUT_ELEMENTS {
        Ok(result)
    } else {
        Err(DispatchFailure {
            code: COREML_RESULT_LIMIT_FAILURE,
        })
    }
}

/// Native Core ML callback owned by the application.
pub trait CoreMlHost {
    /// Invoke an already allowlisted compiled model and validated schema.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code.
    fn infer(&mut self, request: CoreMlRequest) -> Result<CoreMlResult, DispatchFailure>;
    /// Sample a monotonic completion timestamp.
    fn now_ns(&mut self) -> u64;
}

/// Validate, authorize, witness, and dispatch one Core ML inference.
///
/// # Errors
///
/// Refuses an empty model identity, zero or oversized work bounds, HostedIOS
/// policy/platform denial, and native failure.
pub fn dispatch_coreml(
    runtime: &mut GovernedIosRuntime,
    started_ns: u64,
    request: CoreMlRequest,
    host: &mut impl CoreMlHost,
) -> Result<CoreMlResult, DispatchError> {
    let operation = validate_coreml_request(request).map_err(|_| {
        runtime.refuse_invalid_request(coreml_operation_request(request), started_ns)
    })?;
    runtime.dispatch(operation, started_ns, || {
        match host.infer(request).and_then(validate_coreml_result) {
            Ok(result) => Ok((result, host.now_ns())),
            Err(error) => Err((error, host.now_ns())),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_preserves_allowed_compute_units_and_bounds_batch() {
        let mut request = CoreMlRequest {
            model_digest: [2; 32],
            input_elements: 64,
            batch: 3,
            compute_policy: RequestedComputePolicy::All,
            duration_ms: 50,
        };
        let operation = validate_coreml_request(request).unwrap();
        assert_eq!(operation.units, 192);
        assert_eq!(operation.options, RequestedComputePolicy::All as u32);
        request.batch = MAX_COREML_BATCH + 1;
        assert_eq!(
            validate_coreml_request(request),
            Err(CoreMlRequestError::InvalidBatch)
        );
    }

    #[test]
    fn output_count_has_an_absolute_postcondition() {
        assert_eq!(
            validate_coreml_result(CoreMlResult {
                output_elements: MAX_COREML_OUTPUT_ELEMENTS + 1,
            }),
            Err(DispatchFailure {
                code: COREML_RESULT_LIMIT_FAILURE,
            })
        );
    }
}
