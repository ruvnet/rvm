//! A real, interpreter-only WebAssembly execution boundary for hosted RVM.
//!
//! `rvm-wasm` owns portable module validation and agent lifecycle, but does
//! not execute guest instructions. This crate closes that specific hosted
//! gap with `wasmi`: no JIT, no WASI ambient authority, a single typed import,
//! fuel metering, and hard linear-memory/table/instance limits. Those
//! properties make it suitable for stock iOS embedding, subject to App Store
//! policy and physical-device validation by the embedding application.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::doc_markdown)]

use core::fmt;
use wasmi::{
    Caller, Config, EnforcedLimits, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

/// Absolute module-size ceiling accepted by this hosted interpreter.
pub const MAX_HOSTED_MODULE_BYTES: usize = 16 * 1024 * 1024;

/// Absolute fuel ceiling accepted for one hosted invocation.
pub const MAX_HOSTED_FUEL: u64 = 1_000_000_000;

/// Absolute linear-memory ceiling accepted for one hosted invocation.
pub const MAX_HOSTED_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// Absolute guest-table count accepted for one hosted invocation.
pub const MAX_HOSTED_TABLES: usize = 32;

/// Absolute total element count accepted for each guest table.
pub const MAX_HOSTED_TABLE_ELEMENTS: u32 = 65_536;

/// Absolute host-call allowance accepted for one hosted invocation.
pub const MAX_HOSTED_HOST_CALLS: u64 = 65_536;

/// Stable hosted-interpreter implementation and guest-import ABI identifier.
///
/// Evidence layers hash this value so a verifier can distinguish executions
/// produced by a different RVM hosted runtime contract.
pub const HOSTED_WASM_RUNTIME_ID: &str = concat!(
    "rvm-wasm-hosted/",
    env!("CARGO_PKG_VERSION"),
    ";engine=wasmi;abi=rvm.request.v2"
);

/// The value returned to a guest after it exceeds its host-call allowance.
/// No host operation is performed for that or later calls.
pub const HOST_CALL_LIMIT_RESULT: i64 = i64::MIN;

/// Host-side implementation of the only import exposed to a guest:
/// `rvm.request(scope: i32, arg0: i64, arg1: i64) -> i64`.
///
/// The scope is an application-defined numeric right. HostedIOS maps it to a
/// signer-bound capability before invoking native camera, sensor, model, or
/// GPU code.
pub trait HostRequestHandler {
    /// Handle one already-routed guest request and return its numeric result.
    fn request(&mut self, scope: u32, arg0: i64, arg1: i64) -> i64;
}

/// Fail-closed resource envelope for one guest invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedWasmLimits {
    /// Maximum encoded WASM module bytes admitted before parsing/translation.
    pub module_bytes: usize,
    /// Maximum interpreter fuel for compilation-independent execution.
    pub fuel: u64,
    /// Maximum bytes in each guest linear memory.
    pub memory_bytes: usize,
    /// Maximum number of guest tables.
    pub tables: usize,
    /// Maximum total elements allocated by any guest table.
    pub table_elements: u32,
    /// Maximum number of guest memories.
    pub memories: usize,
    /// Maximum calls through `rvm.request`; later calls return a refusal code.
    pub host_calls: u64,
}

impl HostedWasmLimits {
    /// Conservative default for a short edge-agent turn.
    pub const DEFAULT: Self = Self {
        module_bytes: 1024 * 1024,
        fuel: 1_000_000,
        memory_bytes: 16 * 1024 * 1024,
        tables: 4,
        table_elements: 4_096,
        memories: 1,
        host_calls: 256,
    };

    fn valid(self) -> bool {
        (8..=MAX_HOSTED_MODULE_BYTES).contains(&self.module_bytes)
            && (1..=MAX_HOSTED_FUEL).contains(&self.fuel)
            && (64 * 1024..=MAX_HOSTED_MEMORY_BYTES).contains(&self.memory_bytes)
            && (1..=MAX_HOSTED_TABLES).contains(&self.tables)
            && (1..=MAX_HOSTED_TABLE_ELEMENTS).contains(&self.table_elements)
            && self.memories == 1
            && (1..=MAX_HOSTED_HOST_CALLS).contains(&self.host_calls)
    }
}

impl Default for HostedWasmLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Evidence returned after a guest entrypoint completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionReceipt {
    /// Guest return value from the configured `() -> i64` entrypoint.
    pub result: i64,
    /// Interpreter fuel consumed during instantiation, start, and entrypoint.
    pub fuel_consumed: u64,
    /// Number of import calls attempted, including calls refused by the cap.
    pub host_calls_attempted: u64,
    /// Number of import calls forwarded to the host handler.
    pub host_calls_dispatched: u64,
}

/// Bounded diagnostics retained when hosted execution is refused.
///
/// Counters are zero when refusal occurs before the interpreter store exists.
/// Once the store exists, they reflect the best available fuel and host-call
/// accounting at the refusal point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedExecutionFailure {
    /// Stable refusal category.
    pub error: HostedWasmError,
    /// Interpreter fuel consumed before refusal, when accounting remained available.
    pub fuel_consumed: u64,
    /// Guest import calls attempted before refusal.
    pub host_calls_attempted: u64,
    /// Guest import calls forwarded to the host before refusal.
    pub host_calls_dispatched: u64,
}

/// A hosted guest refusal. Details are intentionally bounded and do not retain
/// attacker-controlled engine error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedWasmError {
    /// One or more resource limits were zero or smaller than one WASM page.
    InvalidLimits,
    /// Module validation or translation failed.
    InvalidModule,
    /// Imports were missing, unknown, or had an incompatible type.
    LinkRefused,
    /// The start function trapped or exhausted its resource envelope.
    StartRefused,
    /// The requested exported entrypoint does not exist or is not `() -> i64`.
    InvalidEntrypoint,
    /// The entrypoint trapped, including fuel exhaustion.
    ExecutionRefused,
    /// Fuel accounting was unexpectedly unavailable.
    FuelUnavailable,
}

impl fmt::Display for HostedWasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid hosted WASM resource limits",
            Self::InvalidModule => "WASM module validation failed",
            Self::LinkRefused => "WASM imports were refused",
            Self::StartRefused => "WASM start function was refused",
            Self::InvalidEntrypoint => "WASM entrypoint is missing or incompatible",
            Self::ExecutionRefused => "WASM execution trapped or exhausted its budget",
            Self::FuelUnavailable => "WASM fuel accounting is unavailable",
        })
    }
}

struct HostState<'a, H> {
    handler: &'a mut H,
    limits: StoreLimits,
    host_call_limit: u64,
    attempted: u64,
    dispatched: u64,
}

/// Execute `entrypoint` from `module_bytes` inside the bounded interpreter.
///
/// The entrypoint must have type `() -> i64`. The borrowed handler remains
/// available to the embedding even when guest execution traps. No WASI imports
/// are installed; the only defined import is `rvm.request`.
///
/// # Errors
///
/// Refuses invalid limits, invalid modules, undeclared imports, incompatible
/// entrypoints, start traps, entrypoint traps, and fuel exhaustion.
pub fn execute<H: HostRequestHandler>(
    module_bytes: &[u8],
    entrypoint: &str,
    handler: &mut H,
    limits: HostedWasmLimits,
) -> Result<ExecutionReceipt, HostedWasmError> {
    execute_detailed(module_bytes, entrypoint, handler, limits).map_err(|failure| failure.error)
}

/// Execute a hosted guest while retaining bounded refusal diagnostics.
///
/// This is the evidence-oriented form of [`execute`]. It has the same
/// interpreter and authority boundary, but returns the best available fuel
/// and host-call counters when a start or entrypoint trap occurs.
///
/// # Errors
///
/// Refuses invalid limits, invalid modules, undeclared imports, incompatible
/// entrypoints, start traps, entrypoint traps, and fuel exhaustion.
pub fn execute_detailed<H: HostRequestHandler>(
    module_bytes: &[u8],
    entrypoint: &str,
    handler: &mut H,
    limits: HostedWasmLimits,
) -> Result<ExecutionReceipt, HostedExecutionFailure> {
    if !limits.valid() {
        return Err(failure_without_store(HostedWasmError::InvalidLimits));
    }
    if module_bytes.len() > limits.module_bytes {
        return Err(failure_without_store(HostedWasmError::InvalidModule));
    }

    let mut config = Config::default();
    config
        .consume_fuel(true)
        .enforced_limits(EnforcedLimits::strict());
    let engine = Engine::new(&config);
    let module = Module::new(&engine, module_bytes)
        .map_err(|_| failure_without_store(HostedWasmError::InvalidModule))?;
    let store_limits = StoreLimitsBuilder::new()
        .memory_size(limits.memory_bytes)
        .tables(limits.tables)
        .table_elements(limits.table_elements)
        .memories(limits.memories)
        .instances(1)
        .trap_on_grow_failure(true)
        .build();
    let state = HostState {
        handler,
        limits: store_limits,
        host_call_limit: limits.host_calls,
        attempted: 0,
        dispatched: 0,
    };
    let mut store = Store::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel)
        .map_err(|_| failure_without_store(HostedWasmError::FuelUnavailable))?;

    let mut linker = Linker::new(&engine);
    linker
        .func_wrap(
            "rvm",
            "request",
            |mut caller: Caller<'_, HostState<'_, H>>, scope: i32, arg0: i64, arg1: i64| {
                let state = caller.data_mut();
                state.attempted = state.attempted.saturating_add(1);
                if state.dispatched >= state.host_call_limit {
                    return HOST_CALL_LIMIT_RESULT;
                }
                state.dispatched = state.dispatched.saturating_add(1);
                state
                    .handler
                    .request(u32::try_from(scope).unwrap_or(u32::MAX), arg0, arg1)
            },
        )
        .map_err(|_| failure_from_store(&store, limits, HostedWasmError::LinkRefused))?;

    let pre_instance = linker
        .instantiate(&mut store, &module)
        .map_err(|_| failure_from_store(&store, limits, HostedWasmError::LinkRefused))?;
    let instance = pre_instance
        .start(&mut store)
        .map_err(|_| failure_from_store(&store, limits, HostedWasmError::StartRefused))?;
    let run = instance
        .get_typed_func::<(), i64>(&store, entrypoint)
        .map_err(|_| failure_from_store(&store, limits, HostedWasmError::InvalidEntrypoint))?;
    let result = run
        .call(&mut store, ())
        .map_err(|_| failure_from_store(&store, limits, HostedWasmError::ExecutionRefused))?;
    let remaining = store
        .get_fuel()
        .map_err(|_| failure_from_store(&store, limits, HostedWasmError::FuelUnavailable))?;
    Ok(ExecutionReceipt {
        result,
        fuel_consumed: limits.fuel.saturating_sub(remaining),
        host_calls_attempted: store.data().attempted,
        host_calls_dispatched: store.data().dispatched,
    })
}

const fn failure_without_store(error: HostedWasmError) -> HostedExecutionFailure {
    HostedExecutionFailure {
        error,
        fuel_consumed: 0,
        host_calls_attempted: 0,
        host_calls_dispatched: 0,
    }
}

fn failure_from_store<H>(
    store: &Store<HostState<'_, H>>,
    limits: HostedWasmLimits,
    error: HostedWasmError,
) -> HostedExecutionFailure {
    HostedExecutionFailure {
        error,
        fuel_consumed: store
            .get_fuel()
            .ok()
            .map_or(0, |remaining| limits.fuel.saturating_sub(remaining)),
        host_calls_attempted: store.data().attempted,
        host_calls_dispatched: store.data().dispatched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default, PartialEq, Eq)]
    struct RecordingHandler {
        calls: Vec<(u32, i64, i64)>,
    }

    impl HostRequestHandler for RecordingHandler {
        fn request(&mut self, scope: u32, arg0: i64, arg1: i64) -> i64 {
            self.calls.push((scope, arg0, arg1));
            arg0.saturating_add(arg1)
        }
    }

    fn wasm(wat_source: &str) -> Vec<u8> {
        wat::parse_str(wat_source).unwrap()
    }

    #[test]
    fn executes_real_guest_code_and_routes_the_only_import() {
        let module = wasm(
            r#"(module
                (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
                (func (export "run") (result i64)
                    (call $request (i32.const 7) (i64.const 20) (i64.const 22))))"#,
        );
        let mut handler = RecordingHandler::default();
        let receipt = execute(&module, "run", &mut handler, HostedWasmLimits::default()).unwrap();

        assert_eq!(receipt.result, 42);
        assert!(receipt.fuel_consumed > 0);
        assert_eq!(receipt.host_calls_dispatched, 1);
        assert_eq!(handler.calls, [(7, 20, 22)]);
    }

    #[test]
    fn unknown_ambient_imports_are_refused() {
        let module = wasm(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write" (func $write))
                (func (export "run") (result i64) (i64.const 0)))"#,
        );
        let mut handler = RecordingHandler::default();
        assert_eq!(
            execute(&module, "run", &mut handler, HostedWasmLimits::default()),
            Err(HostedWasmError::LinkRefused)
        );
    }

    #[test]
    fn an_infinite_loop_exhausts_fuel() {
        let module = wasm(
            r#"(module
                (func (export "run") (result i64)
                    (loop $forever (br $forever))
                    (i64.const 0)))"#,
        );
        let limits = HostedWasmLimits {
            fuel: 100,
            ..HostedWasmLimits::default()
        };
        let mut handler = RecordingHandler::default();
        assert_eq!(
            execute(&module, "run", &mut handler, limits),
            Err(HostedWasmError::ExecutionRefused)
        );
    }

    #[test]
    fn memory_above_the_envelope_is_refused_before_entry() {
        let module = wasm(
            r#"(module
                (memory 2)
                (func (export "run") (result i64) (i64.const 0)))"#,
        );
        let limits = HostedWasmLimits {
            memory_bytes: 64 * 1024,
            ..HostedWasmLimits::default()
        };
        let mut handler = RecordingHandler::default();
        assert!(matches!(
            execute(&module, "run", &mut handler, limits),
            Err(HostedWasmError::LinkRefused | HostedWasmError::StartRefused)
        ));
    }

    #[test]
    fn module_bytes_are_bounded_before_translation() {
        let limits = HostedWasmLimits {
            module_bytes: 8,
            ..HostedWasmLimits::default()
        };
        let mut handler = RecordingHandler::default();
        assert_eq!(
            execute(&[0; 9], "run", &mut handler, limits),
            Err(HostedWasmError::InvalidModule)
        );
        let invalid = HostedWasmLimits {
            module_bytes: MAX_HOSTED_MODULE_BYTES + 1,
            ..HostedWasmLimits::default()
        };
        let mut handler = RecordingHandler::default();
        assert_eq!(
            execute(b"\0asm\x01\0\0\0", "run", &mut handler, invalid),
            Err(HostedWasmError::InvalidLimits)
        );
    }

    #[test]
    fn every_configurable_resource_has_an_absolute_ceiling() {
        let valid_module = b"\0asm\x01\0\0\0";
        let invalid_limits = [
            HostedWasmLimits {
                fuel: MAX_HOSTED_FUEL + 1,
                ..HostedWasmLimits::default()
            },
            HostedWasmLimits {
                memory_bytes: MAX_HOSTED_MEMORY_BYTES + 1,
                ..HostedWasmLimits::default()
            },
            HostedWasmLimits {
                tables: MAX_HOSTED_TABLES + 1,
                ..HostedWasmLimits::default()
            },
            HostedWasmLimits {
                table_elements: MAX_HOSTED_TABLE_ELEMENTS + 1,
                ..HostedWasmLimits::default()
            },
            HostedWasmLimits {
                host_calls: MAX_HOSTED_HOST_CALLS + 1,
                ..HostedWasmLimits::default()
            },
        ];

        for limits in invalid_limits {
            let mut handler = RecordingHandler::default();
            assert_eq!(
                execute(valid_module, "run", &mut handler, limits),
                Err(HostedWasmError::InvalidLimits)
            );
        }
    }

    #[test]
    fn host_call_cap_refuses_without_dispatching_more_native_work() {
        let module = wasm(
            r#"(module
                (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
                (func (export "run") (result i64)
                    (drop (call $request (i32.const 1) (i64.const 1) (i64.const 1)))
                    (call $request (i32.const 2) (i64.const 2) (i64.const 2))))"#,
        );
        let limits = HostedWasmLimits {
            host_calls: 1,
            ..HostedWasmLimits::default()
        };
        let mut handler = RecordingHandler::default();
        let receipt = execute(&module, "run", &mut handler, limits).unwrap();
        assert_eq!(receipt.result, HOST_CALL_LIMIT_RESULT);
        assert_eq!(receipt.host_calls_attempted, 2);
        assert_eq!(receipt.host_calls_dispatched, 1);
        assert_eq!(handler.calls.len(), 1);
    }

    #[test]
    fn table_elements_are_bounded_before_entry() {
        let module = wasm(
            r#"(module
                (table 5 funcref)
                (func (export "run") (result i64) (i64.const 0)))"#,
        );
        let limits = HostedWasmLimits {
            table_elements: 4,
            ..HostedWasmLimits::default()
        };
        let mut handler = RecordingHandler::default();
        assert!(matches!(
            execute(&module, "run", &mut handler, limits),
            Err(HostedWasmError::LinkRefused | HostedWasmError::StartRefused)
        ));
    }

    #[test]
    fn host_state_remains_available_after_a_guest_trap() {
        let module = wasm(
            r#"(module
                (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
                (func (export "run") (result i64)
                    (drop (call $request (i32.const 7) (i64.const 20) (i64.const 22)))
                    unreachable))"#,
        );
        let mut handler = RecordingHandler::default();
        assert_eq!(
            execute(&module, "run", &mut handler, HostedWasmLimits::default()),
            Err(HostedWasmError::ExecutionRefused)
        );
        assert_eq!(handler.calls, [(7, 20, 22)]);
    }

    #[test]
    fn detailed_refusal_retains_post_dispatch_counters() {
        let module = wasm(
            r#"(module
                (import "rvm" "request" (func $request (param i32 i64 i64) (result i64)))
                (func (export "run") (result i64)
                    (drop (call $request (i32.const 7) (i64.const 20) (i64.const 22)))
                    unreachable))"#,
        );
        let mut handler = RecordingHandler::default();
        let failure = execute_detailed(&module, "run", &mut handler, HostedWasmLimits::default())
            .unwrap_err();

        assert_eq!(failure.error, HostedWasmError::ExecutionRefused);
        assert!(failure.fuel_consumed > 0);
        assert_eq!(failure.host_calls_attempted, 1);
        assert_eq!(failure.host_calls_dispatched, 1);
        assert!(HOSTED_WASM_RUNTIME_ID.contains("abi=rvm.request.v2"));
    }
}
