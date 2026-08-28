use rvm_coreml::{
    dispatch_coreml, CoreMlHost, CoreMlRequest, CoreMlResult, RequestedComputePolicy,
};
use rvm_host::VerifiedPackage;
use rvm_host_ios::{
    DispatchError, DispatchFailure, GovernedIosRuntime, IosArtifactOrigin, IosAuthorization,
    IosOperatorPolicy, IosPlatformFacts, IosPolicy, IosReason, IosScope, ReceiptEvent,
};
use rvm_metal_ios::{dispatch_metal, MetalHost, MetalRequest, MetalResult};
use rvm_rvf::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META};
use rvm_rvf::testkit::{signed_segment, TestKeypair};
use rvm_rvf::{verify, VerifyOptions};
use rvm_sensors_ios::{dispatch_sensor, SensorHost, SensorKind, SensorRequest, SensorResult};

const METAL_DIGEST: [u8; 32] = [21; 32];
const MODEL_DIGEST: [u8; 32] = [22; 32];

fn runtime() -> GovernedIosRuntime {
    let metadata = b"rvf.capabilities=model,gpu,sensor\nrvf.ios-policy-version=1\nrvf.ios-capabilities=camera.read,gpu.execute,model.infer";
    let key = TestKeypair::deterministic(71);
    let mut data = signed_segment(SEG_TYPE_META, metadata, 1, &key);
    data.extend(signed_segment(SEG_TYPE_MANIFEST, b"root", 2, &key));
    let report = verify(&data, &VerifyOptions::with_trusted_keys(vec![key.public])).unwrap();
    let package = VerifiedPackage::from_report(&report).unwrap();
    let policy = IosPolicy::from_signed_metadata(&package, metadata).unwrap();
    let operator = IosOperatorPolicy::new(
        vec![
            IosScope::CameraRead,
            IosScope::GpuExecute,
            IosScope::ModelInfer,
        ],
        vec![
            (IosScope::GpuExecute, METAL_DIGEST),
            (IosScope::ModelInfer, MODEL_DIGEST),
        ],
        *package.identity(),
        IosArtifactOrigin::EmbeddedAppBundle,
        Default::default(),
    )
    .unwrap();
    GovernedIosRuntime::new(
        policy,
        operator,
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
        },
        [31; 32],
        [32; 16],
    )
    .unwrap()
}

#[derive(Default)]
struct NativeHosts {
    sensor_calls: u64,
    metal_calls: u64,
    model_calls: u64,
    now_ns: u64,
}

impl NativeHosts {
    fn tick(&mut self) -> u64 {
        self.now_ns = self.now_ns.saturating_add(1);
        self.now_ns
    }
}

impl SensorHost for NativeHosts {
    fn capture(&mut self, request: SensorRequest) -> Result<SensorResult, DispatchFailure> {
        self.sensor_calls = self.sensor_calls.saturating_add(1);
        Ok(SensorResult {
            delivered: request.max_samples,
        })
    }

    fn now_ns(&mut self) -> u64 {
        self.tick()
    }
}

impl MetalHost for NativeHosts {
    fn execute(&mut self, _request: MetalRequest) -> Result<MetalResult, DispatchFailure> {
        self.metal_calls = self.metal_calls.saturating_add(1);
        Ok(MetalResult {
            measured_gpu_ns: 500,
        })
    }

    fn now_ns(&mut self) -> u64 {
        self.tick()
    }
}

impl CoreMlHost for NativeHosts {
    fn infer(&mut self, request: CoreMlRequest) -> Result<CoreMlResult, DispatchFailure> {
        self.model_calls = self.model_calls.saturating_add(1);
        Ok(CoreMlResult {
            output_elements: request.batch.into(),
        })
    }

    fn now_ns(&mut self) -> u64 {
        self.tick()
    }
}

#[test]
fn typed_ios_adapters_dispatch_valid_work_and_witness_schema_refusals() {
    let mut runtime = runtime();
    let mut hosts = NativeHosts::default();

    let started = hosts.tick();
    let sensor = dispatch_sensor(
        &mut runtime,
        started,
        SensorRequest {
            kind: SensorKind::Camera,
            resource_digest: [0; 32],
            max_samples: 2,
            rate_hz: 30,
            duration_ms: 100,
        },
        &mut hosts,
    )
    .unwrap();
    assert_eq!(sensor.delivered, 2);

    let started = hosts.tick();
    let metal = dispatch_metal(
        &mut runtime,
        started,
        MetalRequest {
            pipeline_digest: METAL_DIGEST,
            buffer_bytes: 4096,
            threadgroups: 8,
            duration_ms: 50,
        },
        &mut hosts,
    )
    .unwrap();
    assert_eq!(metal.measured_gpu_ns, 500);

    let started = hosts.tick();
    let model = dispatch_coreml(
        &mut runtime,
        started,
        CoreMlRequest {
            model_digest: MODEL_DIGEST,
            input_elements: 256,
            batch: 1,
            compute_policy: RequestedComputePolicy::All,
            duration_ms: 75,
        },
        &mut hosts,
    )
    .unwrap();
    assert_eq!(model.output_elements, 1);
    assert_eq!(
        (hosts.sensor_calls, hosts.metal_calls, hosts.model_calls),
        (1, 1, 1)
    );

    let started = hosts.tick();
    let invalid = dispatch_metal(
        &mut runtime,
        started,
        MetalRequest {
            pipeline_digest: METAL_DIGEST,
            buffer_bytes: 0,
            threadgroups: 8,
            duration_ms: 50,
        },
        &mut hosts,
    );
    assert_eq!(
        invalid,
        Err(DispatchError::Denied(IosReason::InvalidRequest))
    );
    assert_eq!(hosts.metal_calls, 1);

    let receipts = runtime.receipts().receipts();
    assert_eq!(receipts.len(), 7);
    assert_eq!(receipts[6].event, ReceiptEvent::Denied);
    assert_eq!(receipts[6].reason, IosReason::InvalidRequest);
    assert_eq!(runtime.receipts().verify(), Ok(7));
}
