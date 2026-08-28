//! Bridge from the sole hosted-WASM import into governed iOS dispatch.

use crate::runtime::{IOS_GUEST_DENIED, IOS_GUEST_INVALID_SCOPE};
use crate::{
    AgentExecutionLimits, AgentExecutionOutcome, AgentExecutionSeal, DispatchFailure,
    GovernedIosRuntime, IosOperationRequest, IosPlatformFacts, IosScope, ReceiptIntegrityError,
};
use rvm_host::VerifiedPackage;
use rvm_rvf::sha256;
use rvm_wasm_hosted::{
    execute_detailed, ExecutionReceipt, HostRequestHandler, HostedExecutionFailure,
    HostedWasmError, HostedWasmLimits, HOSTED_WASM_RUNTIME_ID,
};

/// Native bridge owned by the iOS application.
pub trait IosNativeBridge {
    /// Resample current OS authorization, support, power, and thermal facts.
    /// This is called immediately before every guest import authorization.
    fn sample_platform_facts(&mut self) -> IosPlatformFacts;
    /// Consume a host-owned descriptor and return its exact typed operation.
    ///
    /// Implementations must make descriptors one-shot. The returned scope,
    /// resource digest, units, duration, and options are host-owned values;
    /// guest arguments must never be used to reconstruct them.
    fn take_operation_request(
        &mut self,
        scope: IosScope,
        descriptor: i64,
    ) -> Option<IosOperationRequest>;
    /// Sample a monotonic host timestamp.
    fn now_ns(&mut self) -> u64;
    /// Perform a request after HostedIOS records authorization intent.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code; raw framework
    /// strings and sensor data must not cross this boundary.
    fn invoke(
        &mut self,
        descriptor: i64,
        request: IosOperationRequest,
    ) -> Result<i64, DispatchFailure>;
    /// Release any pending state for a consumed descriptor after denial or
    /// dispatch. This must not make the descriptor reusable.
    fn finish_operation(&mut self, descriptor: i64);
}

/// Adapter from `rvm.request` into governed iOS dispatch.
pub struct IosWasmHandler<B> {
    runtime: GovernedIosRuntime,
    bridge: B,
}

/// Verified-agent execution refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosAgentError {
    /// Runtime identity or supplied module bytes do not match the verified RVF.
    ExecutableNotVerified,
    /// The bounded interpreter refused the guest.
    Interpreter(HostedWasmError),
    /// Invocation evidence could not be opened or sealed consistently.
    EvidenceUnavailable,
}

/// Guest outcome plus the always-recoverable governed handler.
///
/// Returning the handler on both success and refusal preserves policy receipts
/// and native bridge state when a guest performs a governed call and then
/// traps.
pub struct IosAgentExecution<B> {
    outcome: Result<ExecutionReceipt, IosAgentError>,
    execution_seal: Result<AgentExecutionSeal, ReceiptIntegrityError>,
    handler: IosWasmHandler<B>,
}

impl<B> IosAgentExecution<B> {
    /// Borrow the guest outcome.
    pub const fn outcome(&self) -> &Result<ExecutionReceipt, IosAgentError> {
        &self.outcome
    }

    /// Borrow the authenticated invocation envelope.
    ///
    /// # Errors
    ///
    /// Returns the internal evidence error when the invocation could not be
    /// opened or sealed; callers must not treat an unsealed result as trusted.
    pub fn execution_seal(&self) -> Result<&AgentExecutionSeal, ReceiptIntegrityError> {
        self.execution_seal.as_ref().map_err(|error| *error)
    }

    /// Consume the result into outcome, authenticated evidence, and handler.
    pub fn into_parts(
        self,
    ) -> (
        Result<ExecutionReceipt, IosAgentError>,
        Result<AgentExecutionSeal, ReceiptIntegrityError>,
        IosWasmHandler<B>,
    ) {
        (self.outcome, self.execution_seal, self.handler)
    }
}

/// Execute the exact WASM payload retained by a passing RVF verification
/// report, using the single governed HostedIOS import.
///
/// This is the path that turns a verified package into real guest execution;
/// `rvm-host::HostAdapter::spawn` alone only registers an agent. The same bytes
/// can run unchanged on macOS for portability testing, but that is not
/// physical iPhone evidence.
///
/// # Errors
///
/// Refuses module/identity mismatch or interpreter validation, import, start,
/// entrypoint, memory, or fuel failure.
pub fn execute_verified_ios_agent<B: IosNativeBridge + 'static>(
    package: &VerifiedPackage,
    module: &[u8],
    entrypoint: &str,
    mut handler: IosWasmHandler<B>,
    limits: HostedWasmLimits,
) -> IosAgentExecution<B> {
    let module_digest = sha256(module);
    let entrypoint_digest = sha256(entrypoint.as_bytes());
    let runtime_digest = sha256(HOSTED_WASM_RUNTIME_ID.as_bytes());
    let Some(evidence_limits) = AgentExecutionLimits::from_hosted(limits) else {
        return IosAgentExecution {
            outcome: Err(IosAgentError::EvidenceUnavailable),
            execution_seal: Err(ReceiptIntegrityError::Invocation),
            handler,
        };
    };
    let executable_verified = handler.runtime.rvf_identity == *package.identity()
        && package.accepts_wasm_signed_by(module, handler.runtime.policy_signer());
    handler.runtime.set_interpreter_active(executable_verified);
    let facts = handler.bridge.sample_platform_facts();
    handler.runtime.update_platform_facts(facts);
    let started_ns = handler.bridge.now_ns();
    let context = match handler.runtime.begin_agent_execution(
        started_ns,
        module_digest,
        entrypoint_digest,
        runtime_digest,
        evidence_limits,
    ) {
        Ok(context) => context,
        Err(error) => {
            handler.runtime.set_interpreter_active(false);
            return IosAgentExecution {
                outcome: Err(IosAgentError::EvidenceUnavailable),
                execution_seal: Err(error),
                handler,
            };
        }
    };

    if !executable_verified {
        let ended_ns = handler.bridge.now_ns();
        let execution_seal = handler.runtime.seal_agent_execution(
            &context,
            ended_ns,
            AgentExecutionOutcome::ExecutableNotVerified,
            0,
            0,
            0,
            0,
        );
        let outcome = if execution_seal.is_ok() {
            Err(IosAgentError::ExecutableNotVerified)
        } else {
            Err(IosAgentError::EvidenceUnavailable)
        };
        handler.runtime.set_interpreter_active(false);
        return IosAgentExecution {
            outcome,
            execution_seal,
            handler,
        };
    }

    let execution = execute_detailed(module, entrypoint, &mut handler, limits);
    let ended_ns = handler.bridge.now_ns();
    let (mut outcome, execution_seal) = match execution {
        Ok(receipt) => {
            let seal = handler.runtime.seal_agent_execution(
                &context,
                ended_ns,
                AgentExecutionOutcome::Completed,
                receipt.result,
                receipt.fuel_consumed,
                receipt.host_calls_attempted,
                receipt.host_calls_dispatched,
            );
            (Ok(receipt), seal)
        }
        Err(failure) => {
            let seal = handler.runtime.seal_agent_execution(
                &context,
                ended_ns,
                execution_outcome(failure),
                0,
                failure.fuel_consumed,
                failure.host_calls_attempted,
                failure.host_calls_dispatched,
            );
            (Err(IosAgentError::Interpreter(failure.error)), seal)
        }
    };
    if execution_seal.is_err() {
        outcome = Err(IosAgentError::EvidenceUnavailable);
    }
    handler.runtime.set_interpreter_active(false);
    IosAgentExecution {
        outcome,
        execution_seal,
        handler,
    }
}

const fn execution_outcome(failure: HostedExecutionFailure) -> AgentExecutionOutcome {
    match failure.error {
        HostedWasmError::InvalidLimits => AgentExecutionOutcome::InvalidLimits,
        HostedWasmError::InvalidModule => AgentExecutionOutcome::InvalidModule,
        HostedWasmError::LinkRefused => AgentExecutionOutcome::LinkRefused,
        HostedWasmError::StartRefused => AgentExecutionOutcome::StartRefused,
        HostedWasmError::InvalidEntrypoint => AgentExecutionOutcome::InvalidEntrypoint,
        HostedWasmError::ExecutionRefused => AgentExecutionOutcome::ExecutionRefused,
        HostedWasmError::FuelUnavailable => AgentExecutionOutcome::FuelUnavailable,
    }
}

impl<B> IosWasmHandler<B> {
    /// Bind a runtime to its only native bridge.
    #[must_use]
    pub const fn new(runtime: GovernedIosRuntime, bridge: B) -> Self {
        Self { runtime, bridge }
    }

    /// Inspect the governed runtime and its receipts.
    #[must_use]
    pub const fn runtime(&self) -> &GovernedIosRuntime {
        &self.runtime
    }

    /// Consume the handler after guest execution.
    #[must_use]
    pub fn into_parts(self) -> (GovernedIosRuntime, B) {
        (self.runtime, self.bridge)
    }
}

impl<B: IosNativeBridge> HostRequestHandler for IosWasmHandler<B> {
    fn request(&mut self, scope_code: u32, descriptor: i64, reserved: i64) -> i64 {
        let Some(scope) = IosScope::from_code(scope_code) else {
            return IOS_GUEST_INVALID_SCOPE;
        };
        self.runtime
            .update_platform_facts(self.bridge.sample_platform_facts());
        let started_ns = self.bridge.now_ns();
        let invalid = IosOperationRequest {
            scope,
            resource_digest: [0; 32],
            units: 0,
            duration_ms: 0,
            options: 0,
        };
        if descriptor <= 0 {
            let _ = self.runtime.refuse_invalid_request(invalid, started_ns);
            return IOS_GUEST_DENIED;
        }
        let request = self.bridge.take_operation_request(scope, descriptor);
        let supported = matches!(
            scope,
            IosScope::CameraRead
                | IosScope::LidarRead
                | IosScope::ImuRead
                | IosScope::BleScan
                | IosScope::GpuExecute
                | IosScope::ModelInfer
        );
        let Some(request) = request else {
            let _ = self.runtime.refuse_invalid_request(invalid, started_ns);
            self.bridge.finish_operation(descriptor);
            return IOS_GUEST_DENIED;
        };
        if reserved != 0 || !supported || request.scope != scope {
            let _ = self.runtime.refuse_invalid_request(request, started_ns);
            self.bridge.finish_operation(descriptor);
            return IOS_GUEST_DENIED;
        }
        let runtime = &mut self.runtime;
        let bridge = &mut self.bridge;
        let outcome = runtime.dispatch(request, started_ns, || {
            match bridge.invoke(descriptor, request) {
                Ok(value) => Ok((value, bridge.now_ns())),
                Err(error) => Err((error, bridge.now_ns())),
            }
        });
        bridge.finish_operation(descriptor);
        outcome.unwrap_or(IOS_GUEST_DENIED)
    }
}
