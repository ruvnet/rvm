use rvm_coreml::{CoreMlRequest, CoreMlResult, RequestedComputePolicy};
use rvm_host::VerifiedPackage;
use rvm_host_ios::{
    execute_verified_ios_agent, verify_agent_execution_seal, DispatchFailure, GovernedIosRuntime,
    HostedIosProfile, IosArtifactOrigin, IosAuthorization, IosBudget, IosOperationRequest,
    IosOperatorPolicy, IosPlatformFacts, IosPolicy, IosReason, IosScope, IosWasmHandler,
    ReceiptEvent, IOS_GUEST_DENIED,
};
use rvm_ios_runtime::{IosGuestRouter, IosNativeHost, TypedIosRequest};
use rvm_metal_ios::{MetalRequest, MetalResult};
use rvm_rvf::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
use rvm_rvf::testkit::{signed_segment, TestKeypair};
use rvm_rvf::{sha256, verify, VerifyOptions};
use rvm_sensors_ios::{SensorKind, SensorRequest, SensorResult};
use rvm_wasm_hosted::HostedWasmLimits;

struct Fixture {
    package: VerifiedPackage,
    policy: IosPolicy,
    wasm: Vec<u8>,
}

fn fixture(policy_bytes: &[u8], wasm: Vec<u8>) -> Fixture {
    let key = TestKeypair::deterministic(71);
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

fn runtime(
    fixture: &Fixture,
    scopes: Vec<IosScope>,
    resources: Vec<(IosScope, [u8; 32])>,
) -> GovernedIosRuntime {
    let operator = IosOperatorPolicy::new(
        scopes,
        resources,
        *fixture.package.identity(),
        IosArtifactOrigin::EmbeddedAppBundle,
        IosBudget::default(),
    )
    .unwrap();
    GovernedIosRuntime::new(
        fixture.policy.clone(),
        operator,
        facts(),
        [31; 32],
        [41; 16],
    )
    .unwrap()
}

#[derive(Default)]
struct RecordingHost {
    clock: u64,
    sensors: Vec<SensorRequest>,
    metal: Vec<MetalRequest>,
    coreml: Vec<CoreMlRequest>,
}

impl IosNativeHost for RecordingHost {
    fn sample_platform_facts(&mut self) -> IosPlatformFacts {
        facts()
    }

    fn now_ns(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn capture_sensor(&mut self, request: SensorRequest) -> Result<SensorResult, DispatchFailure> {
        self.sensors.push(request);
        Ok(SensorResult { delivered: 6 })
    }

    fn execute_metal(&mut self, request: MetalRequest) -> Result<MetalResult, DispatchFailure> {
        self.metal.push(request);
        Ok(MetalResult {
            measured_gpu_ns: 777,
        })
    }

    fn infer_coreml(&mut self, request: CoreMlRequest) -> Result<CoreMlResult, DispatchFailure> {
        self.coreml.push(request);
        Ok(CoreMlResult {
            output_elements: 19,
        })
    }
}

fn execute(
    fixture: &Fixture,
    runtime: GovernedIosRuntime,
    router: IosGuestRouter<RecordingHost>,
) -> (i64, GovernedIosRuntime, RecordingHost) {
    let execution = execute_verified_ios_agent(
        &fixture.package,
        &fixture.wasm,
        "run",
        IosWasmHandler::new(runtime, router),
        HostedWasmLimits::default(),
    );
    let (outcome, execution_seal, handler) = execution.into_parts();
    let execution_seal = execution_seal.unwrap();
    let result = outcome.unwrap().result;
    let (runtime, router) = handler.into_parts();
    assert_eq!(execution_seal.profile, HostedIosProfile::IosAppSandboxWasm);
    assert_eq!(execution_seal.module_digest, sha256(&fixture.wasm));
    assert_eq!(
        verify_agent_execution_seal(runtime.receipts().receipts(), &[31; 32], &execution_seal),
        Ok(runtime.receipts().receipts().len())
    );
    (result, runtime, router.into_host())
}

fn assert_exact_receipt(runtime: &GovernedIosRuntime, operation: IosOperationRequest) {
    let receipts = runtime.receipts().receipts();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].event, ReceiptEvent::Intent);
    assert_eq!(receipts[1].event, ReceiptEvent::Completed);
    for receipt in receipts {
        assert_eq!(receipt.scope, operation.scope);
        assert_eq!(receipt.resource_digest, operation.resource_digest);
        assert_eq!(receipt.units, operation.units);
        assert_eq!(receipt.duration_ms, operation.duration_ms);
        assert_eq!(receipt.options, operation.options);
    }
    assert_eq!(runtime.receipts().verify(), Ok(2));
}

#[test]
fn signed_rvf_wasm_routes_exact_typed_ble_request() {
    let request = SensorRequest {
        kind: SensorKind::Ble,
        resource_digest: [12; 32],
        max_samples: 7,
        rate_hz: 33,
        duration_ms: 90,
    };
    let mut router = IosGuestRouter::new(RecordingHost::default(), 4).unwrap();
    let descriptor = router.register(TypedIosRequest::Sensor(request)).unwrap();
    let policy =
        b"rvf.capabilities=sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=ble.scan";
    let fixture = fixture(policy, guest_request(IosScope::BleScan, descriptor.raw()));
    let runtime = runtime(
        &fixture,
        vec![IosScope::BleScan],
        vec![(IosScope::BleScan, request.resource_digest)],
    );

    let (result, runtime, host) = execute(&fixture, runtime, router);

    assert_eq!(result, 6);
    assert_eq!(host.sensors, [request]);
    assert!(host.metal.is_empty() && host.coreml.is_empty());
    assert_exact_receipt(
        &runtime,
        IosOperationRequest {
            scope: IosScope::BleScan,
            resource_digest: request.resource_digest,
            units: 7,
            duration_ms: 90,
            options: 33,
        },
    );
}

#[test]
fn signed_rvf_wasm_routes_exact_typed_metal_request() {
    let request = MetalRequest {
        pipeline_digest: [22; 32],
        buffer_bytes: 4_096,
        threadgroups: 11,
        duration_ms: 120,
    };
    let mut router = IosGuestRouter::new(RecordingHost::default(), 4).unwrap();
    let descriptor = router.register(TypedIosRequest::Metal(request)).unwrap();
    let policy =
        b"rvf.capabilities=gpu\nrvf.ios-policy-version=1\nrvf.ios-capabilities=gpu.execute";
    let fixture = fixture(
        policy,
        guest_request(IosScope::GpuExecute, descriptor.raw()),
    );
    let runtime = runtime(
        &fixture,
        vec![IosScope::GpuExecute],
        vec![(IosScope::GpuExecute, request.pipeline_digest)],
    );

    let (result, runtime, host) = execute(&fixture, runtime, router);

    assert_eq!(result, 777);
    assert_eq!(host.metal, [request]);
    assert!(host.sensors.is_empty() && host.coreml.is_empty());
    assert_exact_receipt(
        &runtime,
        IosOperationRequest {
            scope: IosScope::GpuExecute,
            resource_digest: request.pipeline_digest,
            units: 4_096,
            duration_ms: 120,
            options: 11,
        },
    );
}

#[test]
fn signed_rvf_wasm_preserves_requested_coreml_units_without_claiming_ane_use() {
    let request = CoreMlRequest {
        model_digest: [32; 32],
        input_elements: 64,
        batch: 3,
        compute_policy: RequestedComputePolicy::CpuAndNeuralEngine,
        duration_ms: 200,
    };
    let mut router = IosGuestRouter::new(RecordingHost::default(), 4).unwrap();
    let descriptor = router.register(TypedIosRequest::CoreMl(request)).unwrap();
    let policy =
        b"rvf.capabilities=model\nrvf.ios-policy-version=1\nrvf.ios-capabilities=model.infer";
    let fixture = fixture(
        policy,
        guest_request(IosScope::ModelInfer, descriptor.raw()),
    );
    let runtime = runtime(
        &fixture,
        vec![IosScope::ModelInfer],
        vec![(IosScope::ModelInfer, request.model_digest)],
    );

    let (result, runtime, host) = execute(&fixture, runtime, router);

    assert_eq!(result, 19);
    assert_eq!(host.coreml, [request]);
    assert!(host.sensors.is_empty() && host.metal.is_empty());
    assert_exact_receipt(
        &runtime,
        IosOperationRequest {
            scope: IosScope::ModelInfer,
            resource_digest: request.model_digest,
            units: 192,
            duration_ms: 200,
            options: RequestedComputePolicy::CpuAndNeuralEngine as u32,
        },
    );
}

#[test]
fn network_memory_and_clock_have_no_typed_route_and_scope_smuggling_consumes_descriptors() {
    let camera = SensorRequest {
        kind: SensorKind::Camera,
        resource_digest: [0; 32],
        max_samples: 1,
        rate_hz: 30,
        duration_ms: 50,
    };
    let mut router = IosGuestRouter::new(RecordingHost::default(), 4).unwrap();
    let network_descriptor = router.register(TypedIosRequest::Sensor(camera)).unwrap();
    let memory_descriptor = router.register(TypedIosRequest::Sensor(camera)).unwrap();
    let clock_descriptor = router.register(TypedIosRequest::Sensor(camera)).unwrap();
    let wasm = wat::parse_str(format!(
        r#"(module
            (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
            (func (export "run") (result i64)
                (drop (call $request (i32.const {}) (i64.const {}) (i64.const 0)))
                (drop (call $request (i32.const {}) (i64.const {}) (i64.const 0)))
                (drop (call $request (i32.const {}) (i64.const {}) (i64.const 0)))
                (call $request (i32.const {}) (i64.const {}) (i64.const 0))))"#,
        IosScope::NetworkConnect.code(),
        network_descriptor.raw(),
        IosScope::MemoryRead.code(),
        memory_descriptor.raw(),
        IosScope::ClockRead.code(),
        clock_descriptor.raw(),
        IosScope::CameraRead.code(),
        network_descriptor.raw(),
    ))
    .unwrap();
    let policy = b"rvf.capabilities=memory,network,clock,sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read,network.connect,memory.read,clock.read";
    let fixture = fixture(policy, wasm);
    let runtime = runtime(
        &fixture,
        vec![
            IosScope::CameraRead,
            IosScope::NetworkConnect,
            IosScope::MemoryRead,
            IosScope::ClockRead,
        ],
        vec![],
    );

    let (result, runtime, host) = execute(&fixture, runtime, router);

    assert_eq!(result, IOS_GUEST_DENIED);
    assert!(host.sensors.is_empty() && host.metal.is_empty() && host.coreml.is_empty());
    let receipts = runtime.receipts().receipts();
    assert_eq!(receipts.len(), 4);
    assert!(receipts.iter().all(|receipt| {
        receipt.event == ReceiptEvent::Denied && receipt.reason == IosReason::InvalidRequest
    }));
    assert_eq!(runtime.receipts().verify(), Ok(4));
}
