use rvm_host::VerifiedPackage;
use rvm_host_ios::{
    execute_verified_ios_agent, verify_agent_execution_seal, AgentExecutionOutcome, DispatchError,
    GovernedIosRuntime, HostedIosProfile, IosAgentError, IosArtifactOrigin, IosAuthorization,
    IosBudget, IosNativeBridge, IosOperationRequest, IosOperatorPolicy, IosPlatformFacts,
    IosPolicy, IosPolicyError, IosReason, IosScope, IosWasmHandler, ReceiptEvent, IOS_GUEST_DENIED,
    IOS_NATIVE_DEADLINE_EXCEEDED, MAX_IOS_CALLS_PER_SCOPE,
};
use rvm_rvf::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
use rvm_rvf::testkit::{signed_segment, unsigned_segment, TestKeypair};
use rvm_rvf::{verify, VerifyOptions};
use rvm_wasm_hosted::HostedWasmLimits;

const DESCRIPTOR: i64 = 1;

struct Fixture {
    package: VerifiedPackage,
    policy: IosPolicy,
    wasm: Vec<u8>,
}

fn fixture(policy_bytes: &[u8], wasm: Vec<u8>) -> Fixture {
    let key = TestKeypair::deterministic(44);
    let mut data = signed_segment(SEG_TYPE_META, policy_bytes, 1, &key);
    data.extend(signed_segment(SEG_TYPE_WASM, &wasm, 2, &key));
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 3, &key));
    let report = verify(&data, &VerifyOptions::with_trusted_keys(vec![key.public])).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    let package = VerifiedPackage::from_report(&report).unwrap();
    let policy = IosPolicy::from_signed_metadata(&package, policy_bytes).unwrap();
    Fixture {
        package,
        policy,
        wasm,
    }
}

fn guest_request(scope: IosScope, descriptor: i64) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
            (func (export "run") (result i64)
                (call $request
                    (i32.const {})
                    (i64.const {descriptor})
                    (i64.const 0))))"#,
        scope.code()
    ))
    .unwrap()
}

fn guest_request_then_trap(scope: IosScope, descriptor: i64) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
            (func (export "run") (result i64)
                (drop (call $request
                    (i32.const {})
                    (i64.const {descriptor})
                    (i64.const 0)))
                unreachable))"#,
        scope.code()
    ))
    .unwrap()
}

fn facts() -> IosPlatformFacts {
    IosPlatformFacts {
        app_sandbox: true,
        camera: IosAuthorization::Authorized,
        explicit_sensor_consent: true,
        recording_indicator_active: true,
        lidar_supported: true,
        motion: IosAuthorization::Authorized,
        bluetooth: IosAuthorization::Authorized,
        network_enabled: true,
        metal_available: true,
        core_ml_available: true,
        low_power_mode: false,
        thermal_state: 0,
    }
}

struct Bridge {
    calls: u64,
    clock: u64,
    resource: Option<[u8; 32]>,
    result: i64,
    platform_facts: IosPlatformFacts,
    consumed: bool,
    pending: Option<(i64, IosOperationRequest)>,
}

impl Default for Bridge {
    fn default() -> Self {
        Self {
            calls: 0,
            clock: 0,
            resource: None,
            result: 0,
            platform_facts: facts(),
            consumed: false,
            pending: None,
        }
    }
}

impl IosNativeBridge for Bridge {
    fn sample_platform_facts(&mut self) -> IosPlatformFacts {
        self.platform_facts
    }

    fn take_operation_request(
        &mut self,
        scope: IosScope,
        descriptor: i64,
    ) -> Option<IosOperationRequest> {
        if self.consumed || descriptor <= 0 {
            return None;
        }
        self.consumed = true;
        let requires_resource = matches!(
            scope,
            IosScope::BleScan
                | IosScope::NetworkConnect
                | IosScope::GpuExecute
                | IosScope::ModelInfer
                | IosScope::MemoryRead
                | IosScope::MemoryWrite
        );
        let resource_digest = if requires_resource {
            self.resource?
        } else {
            [0; 32]
        };
        let request = IosOperationRequest {
            scope,
            resource_digest,
            units: 1,
            duration_ms: 10,
            options: 0,
        };
        self.pending = Some((descriptor, request));
        Some(request)
    }

    fn now_ns(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn invoke(
        &mut self,
        descriptor: i64,
        request: IosOperationRequest,
    ) -> Result<i64, rvm_host_ios::DispatchFailure> {
        if self.pending.take() != Some((descriptor, request)) {
            return Err(rvm_host_ios::DispatchFailure { code: 1 });
        }
        self.calls = self.calls.saturating_add(1);
        Ok(self.result)
    }

    fn finish_operation(&mut self, descriptor: i64) {
        if self.pending.is_some_and(|pending| pending.0 == descriptor) {
            self.pending = None;
        }
    }
}

fn runtime(
    fixture: &Fixture,
    scopes: Vec<IosScope>,
    resources: Vec<(IosScope, [u8; 32])>,
    facts: IosPlatformFacts,
) -> GovernedIosRuntime {
    let operator = IosOperatorPolicy::new(
        scopes,
        resources,
        *fixture.package.identity(),
        IosArtifactOrigin::EmbeddedAppBundle,
        Default::default(),
    )
    .unwrap();
    GovernedIosRuntime::new(fixture.policy.clone(), operator, facts, [8; 32], [9; 16]).unwrap()
}

#[test]
fn unsigned_policy_metadata_cannot_authorize_ios() {
    let policy_bytes =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let key = TestKeypair::deterministic(44);
    let wasm = guest_request(IosScope::CameraRead, DESCRIPTOR);
    let mut data = unsigned_segment(SEG_TYPE_META, policy_bytes, 1);
    data.extend(signed_segment(SEG_TYPE_WASM, &wasm, 2, &key));
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 3, &key));
    let report = verify(&data, &VerifyOptions::with_trusted_keys(vec![key.public])).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    let package = VerifiedPackage::from_report(&report).unwrap();

    assert_eq!(
        IosPolicy::from_signed_metadata(&package, policy_bytes),
        Err(IosPolicyError::MetadataNotTrusted)
    );
}

#[test]
fn unsigned_extra_broad_capability_breaks_signed_policy_binding() {
    let policy_bytes =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let key = TestKeypair::deterministic(44);
    let wasm = guest_request(IosScope::CameraRead, DESCRIPTOR);
    let mut data = signed_segment(SEG_TYPE_META, policy_bytes, 1, &key);
    data.extend(unsigned_segment(SEG_TYPE_META, b"rvf.capabilities=gpu", 2));
    data.extend(signed_segment(SEG_TYPE_WASM, &wasm, 3, &key));
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 4, &key));
    let report = verify(&data, &VerifyOptions::with_trusted_keys(vec![key.public])).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    let package = VerifiedPackage::from_report(&report).unwrap();

    assert_eq!(
        IosPolicy::from_signed_metadata(&package, policy_bytes),
        Err(IosPolicyError::BroadCapabilityMismatch)
    );
}

#[test]
fn root_policy_and_executable_must_share_one_trusted_signer() {
    let policy_bytes =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let policy_key = TestKeypair::deterministic(46);
    let root_key = TestKeypair::deterministic(47);
    let wasm = guest_request(IosScope::ClockRead, DESCRIPTOR);
    let mut data = signed_segment(SEG_TYPE_META, policy_bytes, 1, &policy_key);
    data.extend(signed_segment(SEG_TYPE_WASM, &wasm, 2, &policy_key));
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 3, &root_key));
    let report = verify(
        &data,
        &VerifyOptions::with_trusted_keys(vec![policy_key.public, root_key.public]),
    )
    .unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    let package = VerifiedPackage::from_report(&report).unwrap();
    assert_eq!(
        IosPolicy::from_signed_metadata(&package, policy_bytes),
        Err(IosPolicyError::RootNotTrustedByPolicySigner)
    );
}

#[test]
fn executable_from_another_trusted_signer_is_not_this_policy_agent() {
    let policy_bytes =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let policy_key = TestKeypair::deterministic(48);
    let executable_key = TestKeypair::deterministic(49);
    let wasm = guest_request(IosScope::ClockRead, DESCRIPTOR);
    let mut data = signed_segment(SEG_TYPE_META, policy_bytes, 1, &policy_key);
    data.extend(signed_segment(SEG_TYPE_WASM, &wasm, 2, &executable_key));
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 3, &policy_key));
    let report = verify(
        &data,
        &VerifyOptions::with_trusted_keys(vec![policy_key.public, executable_key.public]),
    )
    .unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    let package = VerifiedPackage::from_report(&report).unwrap();
    let policy = IosPolicy::from_signed_metadata(&package, policy_bytes).unwrap();
    let operator = IosOperatorPolicy::new(
        vec![IosScope::ClockRead],
        vec![],
        *package.identity(),
        IosArtifactOrigin::DevelopmentOnly,
        IosBudget::default(),
    )
    .unwrap();
    let runtime = GovernedIosRuntime::new(policy, operator, facts(), [8; 32], [9; 16]).unwrap();
    let execution = execute_verified_ios_agent(
        &package,
        &wasm,
        "run",
        IosWasmHandler::new(runtime, Bridge::default()),
        HostedWasmLimits::default(),
    );
    assert!(matches!(
        execution.outcome(),
        Err(IosAgentError::ExecutableNotVerified)
    ));
}

#[test]
fn same_signer_repackaging_is_refused_when_the_whole_agent_identity_is_not_pinned() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let approved = fixture(policy, guest_request(IosScope::ClockRead, DESCRIPTOR));
    let replacement = fixture(
        policy,
        guest_request_then_trap(IosScope::ClockRead, DESCRIPTOR),
    );
    assert_ne!(approved.package.identity(), replacement.package.identity());

    let operator = IosOperatorPolicy::new(
        vec![IosScope::ClockRead],
        vec![],
        *approved.package.identity(),
        IosArtifactOrigin::EmbeddedAppBundle,
        IosBudget::default(),
    )
    .unwrap();
    assert!(matches!(
        GovernedIosRuntime::new(replacement.policy, operator, facts(), [8; 32], [9; 16]),
        Err(IosReason::AgentIdentityDenied)
    ));
}

#[test]
fn development_verified_unsigned_wasm_is_not_hosted_ios_executable() {
    let policy_bytes =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let key = TestKeypair::deterministic(45);
    let wasm = guest_request(IosScope::ClockRead, DESCRIPTOR);
    let mut data = signed_segment(SEG_TYPE_META, policy_bytes, 1, &key);
    data.extend(unsigned_segment(SEG_TYPE_WASM, &wasm, 2));
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 3, &key));
    let options = VerifyOptions {
        allow_unsigned_executable: true,
        ..VerifyOptions::with_trusted_keys(vec![key.public])
    };
    let report = verify(&data, &options).unwrap();
    assert!(report.is_ok(), "{:?}", report.failures());
    let package = VerifiedPackage::from_report(&report).unwrap();
    let policy = IosPolicy::from_signed_metadata(&package, policy_bytes).unwrap();
    let operator = IosOperatorPolicy::new(
        vec![IosScope::ClockRead],
        vec![],
        *package.identity(),
        IosArtifactOrigin::DevelopmentOnly,
        IosBudget::default(),
    )
    .unwrap();
    let runtime = GovernedIosRuntime::new(policy, operator, facts(), [8; 32], [9; 16]).unwrap();
    let execution = execute_verified_ios_agent(
        &package,
        &wasm,
        "run",
        IosWasmHandler::new(runtime, Bridge::default()),
        HostedWasmLimits::default(),
    );
    assert!(matches!(
        execution.outcome(),
        Err(IosAgentError::ExecutableNotVerified)
    ));
}

#[test]
fn undeclared_camera_request_is_witnessed_and_never_reaches_native_code() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], facts());
    let handler = IosWasmHandler::new(
        runtime,
        Bridge {
            result: 42,
            ..Bridge::default()
        },
    );

    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        handler,
        HostedWasmLimits::default(),
    );
    let (outcome, execution_seal, handler) = execution.into_parts();
    assert!(execution_seal.is_ok());
    let execution = outcome.unwrap();
    assert_eq!(execution.result, IOS_GUEST_DENIED);
    let (runtime, bridge) = handler.into_parts();
    assert_eq!(bridge.calls, 0);
    assert_eq!(runtime.profile(), HostedIosProfile::IosAppSandboxPolicy);
    assert_eq!(runtime.receipts().receipts().len(), 1);
    assert_eq!(
        runtime.receipts().receipts()[0].profile,
        HostedIosProfile::IosAppSandboxWasm
    );
    assert_eq!(runtime.receipts().receipts()[0].event, ReceiptEvent::Denied);
    assert_eq!(
        runtime.receipts().receipts()[0].reason,
        IosReason::ManifestMissing
    );
    assert_eq!(runtime.receipts().verify(), Ok(1));
}

#[test]
fn declared_metal_request_executes_and_emits_intent_then_completion() {
    let policy =
        b"rvf.capabilities=gpu\nrvf.ios-policy-version=1\nrvf.ios-capabilities=gpu.execute";
    let fixture = fixture(policy, guest_request(IosScope::GpuExecute, 9));
    let digest = [77; 32];
    let runtime = runtime(
        &fixture,
        vec![IosScope::GpuExecute],
        vec![(IosScope::GpuExecute, digest)],
        facts(),
    );
    let handler = IosWasmHandler::new(
        runtime,
        Bridge {
            resource: Some(digest),
            result: 42,
            ..Bridge::default()
        },
    );

    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        handler,
        HostedWasmLimits::default(),
    );
    let (outcome, execution_seal, handler) = execution.into_parts();
    assert!(execution_seal.is_ok());
    let execution = outcome.unwrap();
    assert_eq!(execution.result, 42);
    let (runtime, bridge) = handler.into_parts();
    assert_eq!(bridge.calls, 1);
    assert_eq!(runtime.receipts().verify(), Ok(2));
    assert_eq!(runtime.receipts().receipts()[0].event, ReceiptEvent::Intent);
    assert_eq!(
        runtime.receipts().receipts()[1].event,
        ReceiptEvent::Completed
    );
}

#[test]
fn unresolved_guest_descriptor_is_witnessed_before_native_code() {
    let policy =
        b"rvf.capabilities=gpu\nrvf.ios-policy-version=1\nrvf.ios-capabilities=gpu.execute";
    let fixture = fixture(policy, guest_request(IosScope::GpuExecute, 9));
    let digest = [77; 32];
    let runtime = runtime(
        &fixture,
        vec![IosScope::GpuExecute],
        vec![(IosScope::GpuExecute, digest)],
        facts(),
    );
    let handler = IosWasmHandler::new(runtime, Bridge::default());

    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        handler,
        HostedWasmLimits::default(),
    );
    let (outcome, execution_seal, handler) = execution.into_parts();
    assert!(execution_seal.is_ok());
    let execution = outcome.unwrap();
    assert_eq!(execution.result, IOS_GUEST_DENIED);
    let (runtime, bridge) = handler.into_parts();
    assert_eq!(bridge.calls, 0);
    assert_eq!(runtime.receipts().receipts().len(), 1);
    assert_eq!(
        runtime.receipts().receipts()[0].reason,
        IosReason::InvalidRequest
    );
    assert_eq!(runtime.receipts().verify(), Ok(1));
}

#[test]
fn current_os_denial_revokes_camera_without_invoking_native_code() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let mut denied_facts = facts();
    denied_facts.camera = IosAuthorization::Denied;
    let runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], denied_facts);
    let handler = IosWasmHandler::new(
        runtime,
        Bridge {
            platform_facts: denied_facts,
            ..Bridge::default()
        },
    );

    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        handler,
        HostedWasmLimits::default(),
    );
    let (outcome, execution_seal, handler) = execution.into_parts();
    assert!(execution_seal.is_ok());
    let execution = outcome.unwrap();
    assert_eq!(execution.result, IOS_GUEST_DENIED);
    let (runtime, bridge) = handler.into_parts();
    assert_eq!(bridge.calls, 0);
    assert_eq!(
        runtime.receipts().receipts()[0].reason,
        IosReason::OsPermissionDenied
    );
}

#[test]
fn camera_requires_explicit_consent_and_an_active_recording_indicator() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let operation = IosOperationRequest {
        scope: IosScope::CameraRead,
        resource_digest: [0; 32],
        units: 1,
        duration_ms: 10,
        options: 0,
    };
    let mut cases = Vec::new();
    let mut missing_consent = facts();
    missing_consent.explicit_sensor_consent = false;
    cases.push((missing_consent, IosReason::UserConsentMissing));
    let mut missing_indicator = facts();
    missing_indicator.recording_indicator_active = false;
    cases.push((missing_indicator, IosReason::RecordingIndicatorMissing));

    for (platform_facts, expected) in cases {
        let mut runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], platform_facts);
        let mut native_calls = 0;
        assert_eq!(
            runtime.dispatch(operation, 1, || {
                native_calls += 1;
                Ok((42, 2))
            }),
            Err(DispatchError::Denied(expected))
        );
        assert_eq!(native_calls, 0);
        assert_eq!(runtime.receipts().receipts()[0].reason, expected);
    }
}

#[test]
fn governed_receipts_survive_a_guest_trap_and_turn_profile_resets() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(
        policy,
        guest_request_then_trap(IosScope::CameraRead, DESCRIPTOR),
    );
    let runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], facts());
    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        IosWasmHandler::new(
            runtime,
            Bridge {
                result: 42,
                ..Bridge::default()
            },
        ),
        HostedWasmLimits::default(),
    );
    assert!(matches!(
        execution.outcome(),
        Err(IosAgentError::Interpreter(
            rvm_wasm_hosted::HostedWasmError::ExecutionRefused
        ))
    ));
    let (_, execution_seal, handler) = execution.into_parts();
    let execution_seal = execution_seal.unwrap();
    let (runtime, bridge) = handler.into_parts();
    assert_eq!(bridge.calls, 1);
    assert_eq!(runtime.profile(), HostedIosProfile::IosAppSandboxPolicy);
    assert_eq!(runtime.receipts().verify(), Ok(2));
    assert!(runtime
        .receipts()
        .receipts()
        .iter()
        .all(|receipt| receipt.profile == HostedIosProfile::IosAppSandboxWasm));
    assert_eq!(
        execution_seal.outcome,
        AgentExecutionOutcome::ExecutionRefused
    );
    assert_eq!(execution_seal.host_calls_attempted, 1);
    assert_eq!(execution_seal.host_calls_dispatched, 1);
    assert_eq!(execution_seal.profile, HostedIosProfile::IosAppSandboxWasm);
    assert_eq!(
        verify_agent_execution_seal(runtime.receipts().receipts(), &[8; 32], &execution_seal),
        Ok(2)
    );
}

#[test]
fn substituted_wasm_is_refused_before_interpreter_execution() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let fixture = fixture(policy, guest_request(IosScope::ClockRead, DESCRIPTOR));
    let runtime = runtime(&fixture, vec![IosScope::ClockRead], vec![], facts());
    let handler = IosWasmHandler::new(runtime, Bridge::default());
    let substitute =
        wat::parse_str(r#"(module (func (export "run") (result i64) (i64.const 123)))"#).unwrap();

    let execution = execute_verified_ios_agent(
        &fixture.package,
        &substitute,
        "run",
        handler,
        HostedWasmLimits::default(),
    );
    assert!(matches!(
        execution.outcome(),
        Err(rvm_host_ios::IosAgentError::ExecutableNotVerified)
    ));
    let (_, execution_seal, handler) = execution.into_parts();
    assert!(execution_seal.is_ok());
    assert_eq!(
        handler.runtime().profile(),
        HostedIosProfile::IosAppSandboxPolicy
    );
}

#[test]
fn invalid_interpreter_limits_are_sealed_with_exact_refusal_evidence() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let fixture = fixture(policy, guest_request(IosScope::ClockRead, DESCRIPTOR));
    let runtime = runtime(&fixture, vec![IosScope::ClockRead], vec![], facts());
    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        IosWasmHandler::new(runtime, Bridge::default()),
        HostedWasmLimits {
            fuel: 0,
            ..HostedWasmLimits::default()
        },
    );
    assert!(matches!(
        execution.outcome(),
        Err(IosAgentError::Interpreter(
            rvm_wasm_hosted::HostedWasmError::InvalidLimits
        ))
    ));
    let (_, seal, handler) = execution.into_parts();
    let seal = seal.unwrap();
    assert_eq!(seal.outcome, AgentExecutionOutcome::InvalidLimits);
    assert_eq!(seal.limits.fuel, 0);
    assert_eq!(
        verify_agent_execution_seal(handler.runtime().receipts().receipts(), &[8; 32], &seal),
        Ok(0)
    );
}

#[test]
fn fact_changes_and_adapter_refusals_are_bound_into_receipts() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let initial_facts = facts();
    let mut runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], initial_facts);
    let operation = IosOperationRequest {
        scope: IosScope::CameraRead,
        resource_digest: [0; 32],
        units: 1,
        duration_ms: 10,
        options: 0,
    };

    assert_eq!(runtime.dispatch(operation, 1, || Ok((42, 2))), Ok(42));
    assert_eq!(
        runtime.receipts().receipts()[0].platform_facts_digest,
        initial_facts.evidence_digest()
    );

    let mut denied_facts = initial_facts;
    denied_facts.camera = IosAuthorization::Denied;
    runtime.update_platform_facts(denied_facts);
    assert_eq!(
        runtime.dispatch(operation, 3, || Ok((99, 4))),
        Err(DispatchError::Denied(IosReason::OsPermissionDenied))
    );
    assert_eq!(runtime.receipts().receipts().len(), 3);
    assert_eq!(
        runtime.receipts().receipts()[2].platform_facts_digest,
        denied_facts.evidence_digest()
    );

    let malformed = IosOperationRequest {
        units: 0,
        ..operation
    };
    assert_eq!(
        runtime.refuse_invalid_request(malformed, 5),
        DispatchError::Denied(IosReason::InvalidRequest)
    );
    assert_eq!(runtime.receipts().receipts().len(), 4);
    assert_eq!(runtime.receipts().receipts()[3].event, ReceiptEvent::Denied);

    runtime.update_platform_facts(initial_facts);
    let failure = rvm_host_ios::DispatchFailure { code: 41 };
    assert_eq!(
        runtime.dispatch::<i64>(operation, 6, || Err((failure, 7))),
        Err(DispatchError::Native(failure))
    );
    let failed = &runtime.receipts().receipts()[5];
    assert_eq!(failed.event, ReceiptEvent::Failed);
    assert_eq!(failed.units, operation.units);
    assert_eq!(failed.detail_code, failure.code);
    assert_eq!(runtime.receipts().verify(), Ok(6));
}

#[test]
fn completed_work_after_the_requested_deadline_is_failed_not_accepted() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let mut runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], facts());
    let operation = IosOperationRequest {
        scope: IosScope::CameraRead,
        resource_digest: [0; 32],
        units: 1,
        duration_ms: 1,
        options: 0,
    };

    assert_eq!(
        runtime.dispatch(operation, 10, || Ok((42, 1_000_011))),
        Err(DispatchError::Native(rvm_host_ios::DispatchFailure {
            code: IOS_NATIVE_DEADLINE_EXCEEDED,
        }))
    );
    assert_eq!(runtime.receipts().receipts().len(), 2);
    assert_eq!(runtime.receipts().receipts()[1].event, ReceiptEvent::Failed);
    assert_eq!(
        runtime.receipts().receipts()[1].detail_code,
        IOS_NATIVE_DEADLINE_EXCEEDED
    );
}

#[test]
fn exhausted_evidence_budget_fails_closed_before_more_native_work() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let operator = IosOperatorPolicy::new(
        vec![IosScope::CameraRead],
        vec![],
        *fixture.package.identity(),
        IosArtifactOrigin::EmbeddedAppBundle,
        IosBudget {
            max_receipts: 2,
            ..IosBudget::default()
        },
    )
    .unwrap();
    let mut runtime =
        GovernedIosRuntime::new(fixture.policy.clone(), operator, facts(), [8; 32], [9; 16])
            .unwrap();
    let operation = IosOperationRequest {
        scope: IosScope::CameraRead,
        resource_digest: [0; 32],
        units: 1,
        duration_ms: 10,
        options: 0,
    };
    let mut native_calls = 0;

    assert_eq!(
        runtime.dispatch(operation, 1, || {
            native_calls += 1;
            Ok((42, 2))
        }),
        Ok(42)
    );
    assert_eq!(
        runtime.dispatch(operation, 3, || {
            native_calls += 1;
            Ok((99, 4))
        }),
        Err(DispatchError::EvidenceUnavailable)
    );
    assert_eq!(native_calls, 1);
    assert_eq!(runtime.receipts().verify(), Ok(2));
}

#[test]
fn regressing_host_clock_is_evidenced_without_starting_more_native_work() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let mut runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], facts());
    let operation = IosOperationRequest {
        scope: IosScope::CameraRead,
        resource_digest: [0; 32],
        units: 1,
        duration_ms: 10,
        options: 0,
    };
    let mut native_calls = 0;

    assert_eq!(
        runtime.dispatch(operation, 10, || {
            native_calls += 1;
            Ok((42, 20))
        }),
        Ok(42)
    );
    assert_eq!(
        runtime.dispatch(operation, 15, || {
            native_calls += 1;
            Ok((99, 30))
        }),
        Err(DispatchError::EvidenceUnavailable)
    );
    assert_eq!(native_calls, 1);
    let denial = &runtime.receipts().receipts()[2];
    assert_eq!(denial.event, ReceiptEvent::Denied);
    assert_eq!(denial.reason, IosReason::ClockRegression);
    assert_eq!(denial.reported_timestamp_ns, 15);
    assert_eq!(denial.timestamp_ns, 20);
    assert_eq!(runtime.receipts().verify(), Ok(3));
}

#[test]
fn completed_native_effect_with_regressing_clock_is_failed_and_evidenced() {
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read";
    let fixture = fixture(policy, guest_request(IosScope::CameraRead, DESCRIPTOR));
    let mut runtime = runtime(&fixture, vec![IosScope::CameraRead], vec![], facts());
    let operation = IosOperationRequest {
        scope: IosScope::CameraRead,
        resource_digest: [0; 32],
        units: 1,
        duration_ms: 10,
        options: 0,
    };
    let mut native_calls = 0;

    assert_eq!(
        runtime.dispatch(operation, 10, || {
            native_calls += 1;
            Ok((42, 9))
        }),
        Err(DispatchError::EvidenceUnavailable)
    );
    assert_eq!(native_calls, 1);
    let outcome = &runtime.receipts().receipts()[1];
    assert_eq!(outcome.event, ReceiptEvent::Failed);
    assert_eq!(outcome.reason, IosReason::NativeFailure);
    assert_eq!(outcome.detail_code, IOS_NATIVE_DEADLINE_EXCEEDED);
    assert_eq!(outcome.reported_timestamp_ns, 9);
    assert_eq!(outcome.timestamp_ns, 10);
    assert_eq!(runtime.receipts().verify(), Ok(2));
}

#[test]
fn zero_receipt_key_is_refused_at_session_construction() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let fixture = fixture(policy, guest_request(IosScope::ClockRead, DESCRIPTOR));
    let operator = IosOperatorPolicy::new(
        vec![IosScope::ClockRead],
        vec![],
        *fixture.package.identity(),
        IosArtifactOrigin::EmbeddedAppBundle,
        IosBudget::default(),
    )
    .unwrap();

    assert!(matches!(
        GovernedIosRuntime::new(fixture.policy, operator, facts(), [0; 32], [9; 16],),
        Err(IosReason::InvalidRequest)
    ));
}

#[test]
fn operator_policy_rejects_effectively_unbounded_session_calls() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let fixture = fixture(policy, guest_request(IosScope::ClockRead, DESCRIPTOR));
    assert!(matches!(
        IosOperatorPolicy::new(
            vec![IosScope::ClockRead],
            vec![],
            *fixture.package.identity(),
            IosArtifactOrigin::EmbeddedAppBundle,
            IosBudget {
                max_calls_per_scope: MAX_IOS_CALLS_PER_SCOPE + 1,
                ..IosBudget::default()
            },
        ),
        Err(IosReason::InvalidRequest)
    ));
}

#[test]
fn operator_policy_digest_binds_artifact_origin_and_budget() {
    let policy =
        b"rvf.capabilities=clock\nrvf.ios-policy-version=1\nrvf.ios-capabilities=clock.read";
    let fixture = fixture(policy, guest_request(IosScope::ClockRead, DESCRIPTOR));
    let make = |origin, budget| {
        IosOperatorPolicy::new(
            vec![IosScope::ClockRead],
            vec![],
            *fixture.package.identity(),
            origin,
            budget,
        )
        .unwrap()
    };
    let embedded = make(IosArtifactOrigin::EmbeddedAppBundle, IosBudget::default());
    let development = make(IosArtifactOrigin::DevelopmentOnly, IosBudget::default());
    let tighter = make(
        IosArtifactOrigin::EmbeddedAppBundle,
        IosBudget {
            max_calls_per_scope: 1,
            ..IosBudget::default()
        },
    );

    assert_ne!(embedded.digest(), development.digest());
    assert_ne!(embedded.digest(), tighter.digest());
}
