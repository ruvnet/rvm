//! Bounded typed routing from a HostedIOS WASM guest to native app adapters.
//!
//! The app registers already validated sensor, Metal, or Core ML requests and
//! gives the guest only an opaque one-shot descriptor. The descriptor resolves
//! to the complete host-owned [`IosOperationRequest`], including its typed
//! options. Network, memory, and clock operations have no registration path
//! here and remain fail-closed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

use rvm_coreml::{
    validate_coreml_request, validate_coreml_result, CoreMlRequest, CoreMlRequestError,
    CoreMlResult,
};
use rvm_host_ios::{
    DispatchFailure, IosNativeBridge, IosOperationRequest, IosPlatformFacts, IosScope,
};
use rvm_metal_ios::{
    validate_metal_request, validate_metal_result, MetalRequest, MetalRequestError, MetalResult,
};
use rvm_sensors_ios::{
    validate_sensor_request, validate_sensor_result, SensorRequest, SensorRequestError,
    SensorResult,
};

/// Largest descriptor table admitted by this router.
pub const MAX_DESCRIPTOR_CAPACITY: usize = 256;
/// Default maximum number of concurrently registered operations.
pub const DEFAULT_DESCRIPTOR_CAPACITY: usize = 64;
/// Stable native failure when bridge state does not match the governed call.
pub const NATIVE_BRIDGE_STATE_FAILURE: u32 = 1;
/// Stable native failure when a privacy-bounded count exceeds guest `i64`.
pub const NATIVE_RESULT_OUT_OF_RANGE: u32 = 2;
const MAX_DESCRIPTOR_GENERATION: u32 = 0x7fff_ffff;

/// Opaque, positive, one-shot value passed as `arg0` to `rvm.request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuestOperationDescriptor(i64);

impl GuestOperationDescriptor {
    /// Numeric value embedded in or supplied to the WASM guest.
    #[must_use]
    pub const fn raw(self) -> i64 {
        self.0
    }
}

/// Typed operations the app may make available to one guest execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedIosRequest {
    /// Camera, LiDAR, IMU, or BLE capture.
    Sensor(SensorRequest),
    /// Allowlisted precompiled Metal dispatch.
    Metal(MetalRequest),
    /// Allowlisted compiled Core ML inference.
    CoreMl(CoreMlRequest),
}

/// Failure to create or populate a bounded guest router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterError {
    /// Capacity was zero or larger than [`MAX_DESCRIPTOR_CAPACITY`].
    InvalidCapacity,
    /// Every bounded descriptor slot is active.
    TableFull,
    /// Typed sensor validation failed.
    Sensor(SensorRequestError),
    /// Typed Metal validation failed.
    Metal(MetalRequestError),
    /// Typed Core ML validation failed.
    CoreMl(CoreMlRequestError),
}

/// Native application surface used only after typed validation and HostedIOS
/// authorization. Implementations own all Apple framework objects.
pub trait IosNativeHost {
    /// Resample current authorization, hardware, power, and thermal facts.
    fn sample_platform_facts(&mut self) -> IosPlatformFacts;
    /// Sample a monotonic timestamp in nanoseconds.
    fn now_ns(&mut self) -> u64;
    /// Execute one prevalidated sensor request.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code.
    fn capture_sensor(&mut self, request: SensorRequest) -> Result<SensorResult, DispatchFailure>;
    /// Execute one prevalidated Metal request.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code.
    fn execute_metal(&mut self, request: MetalRequest) -> Result<MetalResult, DispatchFailure>;
    /// Request one prevalidated Core ML inference.
    ///
    /// `request.compute_policy` is only the set of compute units allowed in
    /// the Core ML configuration. Actual Neural Engine/GPU/CPU placement is
    /// opaque and is not represented by this API or its receipts.
    ///
    /// # Errors
    ///
    /// Returns a stable privacy-bounded native failure code.
    fn infer_coreml(&mut self, request: CoreMlRequest) -> Result<CoreMlResult, DispatchFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedOperation {
    Sensor(SensorRequest, IosOperationRequest),
    Metal(MetalRequest, IosOperationRequest),
    CoreMl(CoreMlRequest, IosOperationRequest),
}

impl PreparedOperation {
    fn prepare(request: TypedIosRequest) -> Result<Self, RouterError> {
        match request {
            TypedIosRequest::Sensor(request) => validate_sensor_request(request)
                .map(|operation| Self::Sensor(request, operation))
                .map_err(RouterError::Sensor),
            TypedIosRequest::Metal(request) => validate_metal_request(request)
                .map(|operation| Self::Metal(request, operation))
                .map_err(RouterError::Metal),
            TypedIosRequest::CoreMl(request) => validate_coreml_request(request)
                .map(|operation| Self::CoreMl(request, operation))
                .map_err(RouterError::CoreMl),
        }
    }

    const fn operation(self) -> IosOperationRequest {
        match self {
            Self::Sensor(_, operation) | Self::Metal(_, operation) | Self::CoreMl(_, operation) => {
                operation
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DescriptorSlot {
    generation: u32,
    prepared: Option<PreparedOperation>,
}

impl DescriptorSlot {
    const EMPTY: Self = Self {
        generation: 1,
        prepared: None,
    };
}

#[derive(Debug, Clone, Copy)]
struct PendingOperation {
    descriptor: GuestOperationDescriptor,
    prepared: PreparedOperation,
}

/// Aggregate bridge implementing the sole HostedIOS WASM native route.
///
/// Descriptor lookup is bounded by construction. A valid descriptor is
/// consumed before policy authorization, including on scope mismatch or
/// denial, and cannot be replayed.
pub struct IosGuestRouter<H> {
    host: H,
    slots: Vec<DescriptorSlot>,
    pending: Option<PendingOperation>,
}

impl<H> IosGuestRouter<H> {
    /// Create a router with a fixed one-shot descriptor capacity.
    ///
    /// # Errors
    ///
    /// Refuses zero capacity or more than [`MAX_DESCRIPTOR_CAPACITY`] slots.
    pub fn new(host: H, capacity: usize) -> Result<Self, RouterError> {
        if capacity == 0 || capacity > MAX_DESCRIPTOR_CAPACITY {
            return Err(RouterError::InvalidCapacity);
        }
        Ok(Self {
            host,
            slots: vec![DescriptorSlot::EMPTY; capacity],
            pending: None,
        })
    }

    /// Register a typed request and return its opaque one-shot descriptor.
    ///
    /// # Errors
    ///
    /// Refuses invalid typed requests or a full bounded table.
    pub fn register(
        &mut self,
        request: TypedIosRequest,
    ) -> Result<GuestOperationDescriptor, RouterError> {
        let prepared = PreparedOperation::prepare(request)?;
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.prepared.is_none() && slot.generation != 0)
            .ok_or(RouterError::TableFull)?;
        let descriptor = encode_descriptor(index, slot.generation);
        slot.prepared = Some(prepared);
        Ok(descriptor)
    }

    /// Borrow the native host, for app-owned inspection outside guest turns.
    #[must_use]
    pub const fn host(&self) -> &H {
        &self.host
    }

    /// Mutably borrow the native host outside guest turns.
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Consume the router and recover the native host.
    #[must_use]
    pub fn into_host(self) -> H {
        self.host
    }

    fn take(&mut self, descriptor: GuestOperationDescriptor) -> Option<PreparedOperation> {
        let (index, generation) = decode_descriptor(descriptor, self.slots.len())?;
        let slot = &mut self.slots[index];
        if slot.generation != generation {
            return None;
        }
        let prepared = slot.prepared.take()?;
        slot.generation = next_generation(slot.generation);
        Some(prepared)
    }
}

impl<H: IosNativeHost> IosNativeBridge for IosGuestRouter<H> {
    fn sample_platform_facts(&mut self) -> IosPlatformFacts {
        self.host.sample_platform_facts()
    }

    fn take_operation_request(
        &mut self,
        scope: IosScope,
        descriptor: i64,
    ) -> Option<IosOperationRequest> {
        self.pending = None;
        let descriptor = GuestOperationDescriptor(descriptor);
        let prepared = self.take(descriptor)?;
        if prepared.operation().scope != scope {
            return None;
        }
        let operation = prepared.operation();
        self.pending = Some(PendingOperation {
            descriptor,
            prepared,
        });
        Some(operation)
    }

    fn now_ns(&mut self) -> u64 {
        self.host.now_ns()
    }

    fn invoke(
        &mut self,
        descriptor: i64,
        request: IosOperationRequest,
    ) -> Result<i64, DispatchFailure> {
        let Some(pending) = self.pending.take() else {
            return Err(DispatchFailure {
                code: NATIVE_BRIDGE_STATE_FAILURE,
            });
        };
        if pending.descriptor.raw() != descriptor || pending.prepared.operation() != request {
            return Err(DispatchFailure {
                code: NATIVE_BRIDGE_STATE_FAILURE,
            });
        }
        let value = match pending.prepared {
            PreparedOperation::Sensor(request, _) => {
                validate_sensor_result(request, self.host.capture_sensor(request)?)?.delivered
            }
            PreparedOperation::Metal(request, _) => {
                validate_metal_result(request, self.host.execute_metal(request)?)?.measured_gpu_ns
            }
            PreparedOperation::CoreMl(request, _) => {
                validate_coreml_result(self.host.infer_coreml(request)?)?.output_elements
            }
        };
        i64::try_from(value).map_err(|_| DispatchFailure {
            code: NATIVE_RESULT_OUT_OF_RANGE,
        })
    }

    fn finish_operation(&mut self, descriptor: i64) {
        if self
            .pending
            .is_some_and(|pending| pending.descriptor.raw() == descriptor)
        {
            self.pending = None;
        }
    }
}

fn encode_descriptor(index: usize, generation: u32) -> GuestOperationDescriptor {
    debug_assert!(generation > 0 && generation <= MAX_DESCRIPTOR_GENERATION);
    let slot = u64::try_from(index + 1).expect("bounded descriptor index");
    let raw = (u64::from(generation) << 32) | slot;
    GuestOperationDescriptor(i64::try_from(raw).expect("positive descriptor encoding"))
}

fn decode_descriptor(
    descriptor: GuestOperationDescriptor,
    capacity: usize,
) -> Option<(usize, u32)> {
    let raw = u64::try_from(descriptor.raw()).ok()?;
    let generation = u32::try_from(raw >> 32).ok()?;
    let one_based = usize::try_from(raw & u64::from(u32::MAX)).ok()?;
    if generation == 0
        || generation > MAX_DESCRIPTOR_GENERATION
        || one_based == 0
        || one_based > capacity
    {
        return None;
    }
    Some((one_based - 1, generation))
}

const fn next_generation(generation: u32) -> u32 {
    if generation == MAX_DESCRIPTOR_GENERATION {
        // Retire the slot instead of wrapping and making an ancient
        // descriptor valid again after enough uses.
        0
    } else {
        generation + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_sensors_ios::SensorKind;

    struct NoopHost;

    fn camera() -> TypedIosRequest {
        TypedIosRequest::Sensor(SensorRequest {
            kind: SensorKind::Camera,
            resource_digest: [0; 32],
            max_samples: 4,
            rate_hz: 30,
            duration_ms: 100,
        })
    }

    #[test]
    fn descriptors_are_bounded_one_shot_and_generational() {
        let mut router = IosGuestRouter::new(NoopHost, 1).unwrap();
        let first = router.register(camera()).unwrap();
        assert_eq!(router.register(camera()), Err(RouterError::TableFull));
        assert!(router.take(first).is_some());
        assert!(router.take(first).is_none());

        let second = router.register(camera()).unwrap();
        assert_ne!(first, second);
        assert!(router.take(first).is_none());
        assert!(router.take(second).is_some());
    }

    #[test]
    fn invalid_typed_requests_never_enter_the_table() {
        let mut router = IosGuestRouter::new(NoopHost, 1).unwrap();
        let invalid = TypedIosRequest::Sensor(SensorRequest {
            kind: SensorKind::Ble,
            resource_digest: [0; 32],
            max_samples: 1,
            rate_hz: 1,
            duration_ms: 1,
        });
        assert_eq!(
            router.register(invalid),
            Err(RouterError::Sensor(
                SensorRequestError::InvalidResourceDigest
            ))
        );
        assert!(router.register(camera()).is_ok());
    }

    #[test]
    fn exhausted_generation_retires_instead_of_revalidating_an_old_descriptor() {
        let mut router = IosGuestRouter::new(NoopHost, 1).unwrap();
        router.slots[0].generation = MAX_DESCRIPTOR_GENERATION;
        let terminal = router.register(camera()).unwrap();
        assert!(router.take(terminal).is_some());
        assert!(router.take(terminal).is_none());
        assert_eq!(router.register(camera()), Err(RouterError::TableFull));
    }
}
