# ADR-159: HostedIOS Governed Edge Runtime

**Status**: Accepted (Rust software contract); native iOS integration and physical-device evidence pending
**Date**: 2026-08-28
**Authors**: RVM Contributors
**Supersedes**: None
**Related**: ADR-134 (Witness Schema), ADR-144 (GPU Compute), ADR-155
(RVF Execution Contract), RuVector Apple ADR-340 (Adaptive Apple Execution)

---

## Context

An iPhone can contribute camera frames, ARKit depth, motion, Bluetooth results,
Metal compute, and Core ML inference to a local spatial pipeline. Stock iOS,
however, remains the hardware and security authority. An App Store process does
not control stage-2 translation, an IOMMU, GPU scheduling, Neural Engine
placement, measured boot, physical device leases, hard real-time scheduling, or
background lifetime.

Reusing the word `Partition` for this environment would therefore overstate the
isolation RVM provides. At the same time, leaving every Apple-framework call in
application code would make a signed RVF's declared rights advisory: a guest or
host path could reach a sensor without a common policy decision or receipt.

The existing `rvm-wasm` crate validates module structure and models agent
lifecycle, but it does not interpret guest instructions. The existing legacy
witness chain is also not sufficient as a content-complete HostedIOS operation
receipt. A hosted iOS target needs a real bounded interpreter, signer-bound
fine-grained policy, typed native boundaries, dynamic OS-permission checks, and
evidence that does not claim stronger isolation than iOS actually supplied.

## Decision

Add an explicit `HostedIOS` family implemented by these crates:

| Crate | Responsibility |
|---|---|
| `rvm-wasm-hosted` | Interpreter-only WASM execution, no WASI, one typed import, fuel and resource bounds |
| `rvm-host-ios` | Signer-bound policy, effective grants, dynamic iOS facts, governed dispatch, and keyed receipts |
| `rvm-ios-runtime` | Bounded one-shot generational descriptors and the aggregate typed guest-to-native router |
| `rvm-metal-ios` | Typed request contract for allowlisted precompiled Metal work |
| `rvm-coreml` | Typed request contract for allowlisted compiled Core ML models |
| `rvm-sensors-ios` | Typed request contracts for camera, ARKit LiDAR/depth, Core Motion, and BLE |

The native app owns AVFoundation, ARKit, Core Motion, Core Bluetooth, Metal,
Core ML, user prompts, entitlements, and application lifecycle. The Rust crates
own the additional application-level policy boundary. The app is part of the
trusted computing base and must not expose a bypass around these dispatchers.

```text
signed RVF
    |
verify executable + exact signed META identities
    |
canonical HostedIOS policy
    |
fuel/memory-bounded WASM guest -- only import --> rvm.request
    |
one-shot generational descriptor --> exact host-owned typed request
    |
artifact scope ∩ operator scope/resource ∩ current iOS facts ∩ budget
    |
intent receipt --> typed native adapter --> completion/failure receipt
    |
AVFoundation | ARKit | Core Motion | Core Bluetooth | Metal | Core ML
```

### 1. Honest isolation profiles

The runtime derives, rather than accepts, one of three profiles:

| Profile | Meaning |
|---|---|
| `hosted-ios/policy-shell` | Policy exists, but the app sandbox was not evidenced |
| `hosted-ios/app-sandbox+policy` | App sandbox plus policy, without a live guest interpreter |
| `hosted-ios/app-sandbox+wasm` | App sandbox plus a live bounded WASM interpreter |

No HostedIOS profile means an RVM hardware partition. The fixed
`HostedIosNonGuarantees::STOCK_IOS` value records that the profile does not
claim stage-2 MMU control, IOMMU control, a hardware partition, exclusive
physical devices, RVM GPU-context isolation, measured boot, exact Neural Engine
selection, hard real-time behavior, or background liveness.

### 2. Signer-bound policy

HostedIOS policy is parsed only from a `META` payload whose content hash and
Ed25519 signature passed verification against a caller-supplied trusted key.
`rvm-rvf` retains only the segment identifier, length, and SHA-256 of such
metadata. `VerifiedPackage` can then match the exact bytes without retaining
arbitrary metadata.

The selected `MANIFEST`, policy `META`, and executable WASM must resolve to the
same trusted signer. Separately, local operator policy must pin the SHA-256 of
the **complete RVF byte stream** approved in the application bundle. A
same-signer repackaging has a different identity and is refused. This exact
artifact pin is mandatory: it is the local authorization boundary and must not
be replaced with signer-only trust.

Operator policy also records `EmbeddedAppBundle` or `DevelopmentOnly` as the
artifact-origin class and hashes that assertion together with the allowed
scopes/resources, exact RVF identity, and budgets. An App Store host must use
`EmbeddedAppBundle`. Rust authenticates the host's origin assertion in every
receipt and execution seal, but cannot inspect the native bundle or its Apple
code signature; that check remains part of the native trusted computing base.

Version 1 policy is canonical UTF-8 with exactly three lines, in this order,
and no trailing newline:

```text
rvf.capabilities=sensor,gpu
rvf.ios-policy-version=1
rvf.ios-capabilities=camera.read,lidar.read,gpu.execute
```

Both comma lists must follow enum order and contain no duplicates or spaces.
The signed broad capability list must exactly equal the package's resolved
broad mapping. Every fine scope requires its broad class, and every broad class
requires at least one fine scope. `lidar.read` additionally requires
`camera.read`. This exact equality deliberately refuses a package if legacy
unsigned metadata attempts to add a broad capability.

This implementation verifies supported RVF v1 segment layouts, segment
content/signatures, the selected signed `MANIFEST`, and, when present, the
supported Forge Level-0 page's integrity, pointer, signature, and signer
binding. It does **not** claim to implement every semantic field or future
layout of the canonical RVF manifest ecosystem described by ADR-155. Canonical
packed-runtime and Forge-authored compatibility remains conditional on the
checked-in golden fixtures passing the targeted `rvm-rvf` tests. No portable
artifact claim is accepted from source inspection alone.

The Forge golden fixture proves the supported container and Level-0 wire shape,
not a turnkey HostedIOS agent. Current upstream RVForge output does not yet
provide a full segment-directory `MANIFEST` and its capability `META` is
unsigned. HostedIOS therefore cannot promote that metadata into `IosPolicy`.
Production authoring remains blocked on signer-bound canonical policy metadata
(or an equivalently reviewed signed-manifest policy contract) even though the
outer container shape verifies.

Version 1 scopes are:

```text
camera.read   lidar.read      imu.read       ble.scan
network.connect               gpu.execute    model.infer
memory.read   memory.write    clock.read
```

### 3. Effective grant and revocation

Every native operation is admitted only when all four gates pass:

1. the exact signed RVF policy declares the fine scope;
2. local operator policy enables the scope and, where required, the exact
   resource digest;
3. current native-host facts show that the framework, hardware, and OS
   authorization are available; and
4. requested per-call work and duration fit the operator envelope, and the
   per-session call budget has capacity.

Operator inputs are themselves bounded: at most 64 resource-digest entries,
32,768 calls per scope, `2^40` abstract units per call, 30 seconds requested
duration per call, and 65,536 receipt records per session. Smaller local limits
are expected for a product profile.

`NotDetermined` is not authorization. User-facing permission UI remains a
native-app action and the current operation is denied. Permission and thermal
facts can be replaced between calls, so revocation takes effect without
reloading the RVF. Thermal state is fail-closed for accelerator paths: serious
or worse refuses Metal; critical or unknown refuses Core ML.

Camera, LiDAR, and IMU also require the native host to assert both explicit
purpose-specific consent for the current sensor session and an active clear
visual or audible recording indicator. Missing assertions produce stable
witnessed denials before native invocation. Those booleans bind what the host
reported; they do not prove that a compliant UI was actually shown.

Resource digests are mandatory for BLE service allowlists, network endpoints,
Metal pipeline-and-schema identities, Core ML model-and-schema identities, and
logical memory regions. Receipts never store raw URLs, model names, frames,
sensor data, or tensors.

The generic v1 policy vocabulary reserves `network.connect`, `memory.read`,
`memory.write`, and `clock.read`, but the HostedIOS WASM router has **no typed
registration or invocation path** for them. `IosWasmHandler` accepts only
camera, LiDAR, IMU, BLE, Metal, and Core ML. A guest attempt to use a reserved
unsupported scope is consumed and witnessed as an invalid request without
native invocation. Networking for external RuView CSI, logical-memory access,
and a guest clock remain fail-closed until separate bounded typed adapters and
tests are accepted. The public low-level `GovernedIosRuntime::dispatch` API is
part of the trusted host surface; using it to invent an unreviewed network,
memory, or clock bridge is not a conforming HostedIOS integration.

### 4. Real hosted WASM execution

`rvm-wasm-hosted` uses the `wasmi` interpreter. It installs no WASI surface and
defines only:

```text
rvm.request(scope: i32, descriptor: i64, reserved: i64) -> i64
```

The module must be the exact signed executable accepted by `VerifiedPackage`.
The interpreter bounds encoded module bytes before translation, applies
`wasmi`'s strict structural compiler limits, and accepts only a nonzero envelope
within these absolute ceilings:

| Resource | Absolute ceiling |
|---|---:|
| encoded module | 16 MiB |
| fuel | 1,000,000,000 |
| bytes per linear memory | 256 MiB |
| tables | 32 |
| elements per table | 65,536 |
| memories | exactly 1 |
| instances | exactly 1 |
| forwarded host calls | 65,536 |

Unknown imports, invalid entrypoints, start traps, execution traps, exhausted
fuel, and any caller-supplied limit outside that envelope fail closed. Attempts
beyond the admitted host-call count receive the stable refusal value and are
not forwarded. Successful and refused executions retain bounded fuel and
host-call accounting when the interpreter exposes it.

`rvm-ios-runtime` supplies the conforming aggregate bridge. The host validates
and registers an exact typed sensor, Metal, or Core ML request in a fixed table
of at most 256 slots (64 by default), then passes the guest a positive opaque
descriptor containing a slot and 31-bit generation. The full resource digest,
units, duration, and typed options remain host-owned. A descriptor is consumed
before authorization, including on scope mismatch or denial; reuse and stale
generation fail. A slot is retired instead of wrapping its generation. The
guest must send the declared scope, the descriptor, and `reserved = 0`.

This is application-level WASM isolation. It does not make downloaded native
code safe and it does not create a hardware partition.

### 5. Typed Apple mappings

The adapters intentionally do not hold Apple framework objects. The native app
implements narrow callbacks after the Rust boundary validates and witnesses a
request.

| Scope | Native mapping | Additional constraints |
|---|---|---|
| `camera.read` | AVFoundation or ARKit host session | current camera authorization, bounded frames/rate/duration |
| `lidar.read` | ARKit scene depth/reconstruction | camera authorization plus device/API support |
| `imu.read` | Core Motion | current authorization/availability, bounded samples/rate/duration |
| `ble.scan` | Core Bluetooth | current authorization and exact service-allowlist digest |
| `gpu.execute` | Metal command queue | precompiled allowlisted pipeline/schema digest and bounded buffers/threadgroups |
| `model.infer` | compiled Core ML model | model/schema digest, bounded inputs/batch, requested compute-unit set |
| `network.connect` | none yet | reserved scope; no typed WASM route, fail closed |
| `memory.read` / `memory.write` | none yet | reserved scopes; no typed WASM route, fail closed |
| `clock.read` | none yet | reserved scope; no typed WASM route, fail closed |

A Core ML compute-unit setting is an allowed set, not evidence that an
inference ran on the Neural Engine. The native app must use Core ML Instruments
or equivalent physical-device evidence for placement claims. Stock iOS exposes
no public Wi-Fi CSI stream; RuView CSI must arrive from an external node through
a separately scoped network path after that typed adapter is implemented and
accepted.

Typed result validation is also bounded: a sensor cannot report more delivered
items than requested, Core ML output cannot exceed the absolute element limit,
and a nonzero Metal GPU-duration measurement cannot exceed the admitted
request. The governed runtime compares the native callback's reported
monotonic completion time with the admitted duration and converts a late
success into a witnessed native failure. These are **postconditions**. Rust
does not cancel or preempt an AVFoundation, ARKit, Core Motion, Core Bluetooth,
Metal, or Core ML operation. The native app must implement framework-appropriate
cancellation and deadlines; a callback may already have had an external effect
before a late result is rejected.

Relevant Apple contracts include
[media authorization](https://developer.apple.com/documentation/avfoundation/requesting-authorization-to-capture-and-save-media),
[ARKit scene depth](https://developer.apple.com/documentation/arkit/arframe/scenedepth),
[Core Motion](https://developer.apple.com/documentation/coremotion),
[Core Bluetooth authorization](https://developer.apple.com/documentation/corebluetooth/cbmanagerauthorization),
[local-network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy),
[Metal command queues](https://developer.apple.com/documentation/metal/mtlcommandqueue),
and [Core ML compute units](https://developer.apple.com/documentation/coreml/mlcomputeunits).

### 6. HostedIOS receipts

HostedIOS uses domain-separated HMAC-SHA256 operation receipts plus a version-2
guest-execution seal. The embedding app supplies a nonzero random 256-bit key
and session nonce; no default key is compiled. The receipt vector is bounded to
2--65,536 records and its complete capacity is reserved before a session starts.

Every operation record binds:

- sequence, monotonic operation ID, reported host timestamp,
  monotonic-clamped effective timestamp, previous MAC, and session nonce;
- complete RVF identity, canonical signed policy digest, complete operator
  policy digest, and host-asserted artifact-origin class;
- honestly derived isolation profile and digest of the complete host-supplied
  iOS fact set used for that decision;
- event, scope, stable reason, resource digest, requested work units, admitted
  duration, typed options, and stable result-detail code.

Authorization or schema refusal produces `Denied` without native invocation.
An allowed operation writes `Intent` before the native callback, then exactly
one matching `Completed` or `Failed` record with the same operation ID, scope,
resource, units, duration, and options. Event/reason pairings are checked.
Clock regression is retained through reported/effective timestamps and fails
closed where the native effect has not begun; a regression reported after an
effect cannot undo that effect.

The version-2 `AgentExecutionSeal` separately authenticates one complete guest
turn and chains to the preceding execution seal. It binds the invocation ID;
RVF, signed policy, and operator-policy identities; artifact-origin assertion;
session nonce; isolation profile; starting platform facts; reported/effective
start and end times; receipt count/head before the turn; exact module,
entrypoint, and hosted-runtime/ABI digests; module, fuel, memory, table,
table-element, memory-count, and host-call limits; terminal outcome/result;
fuel consumed; host calls attempted/dispatched; terminal receipt count/head;
and previous execution-seal MAC. It is produced for normal completion and
bounded interpreter refusal, and unsealed outcomes are not trusted.

Internal deletion, reordering, event mismatch, timestamp forgery, or content
mutation invalidates receipt verification. A `ReceiptSeal` or execution seal
binds the terminal count and head and therefore detects suffix truncation when
that authenticated seal is retained. HMAC does **not** prevent a holder of the
key from rewriting evidence, prove that native platform facts were true, or
detect replay of an older complete chain plus its valid old seal. Preventing
complete rollback requires a native monotonic counter or durable external
anchor.

The platform-fact digest is a commitment to what the trusted app asserted, not
Apple remote attestation. Receipts remain in memory. Cross-process evidence
requires the app to atomically persist/export the chain and seals using a
Keychain-protected per-install key plus a rollback-resistant anchor. Secure
Enclave-backed wrapping or signing is an optional native integration, not a
guarantee of these Rust crates.

### 7. Adaptive RuVector execution

Hardware adaptation is a separate planning layer above these capability gates.
It may choose among measured eligible CPU, Metal, and Core ML execution plans,
but it may not add an RVM capability or bypass operator, OS, thermal, or budget
checks. A device-and-runtime fingerprint scopes learned observations. Candidate
selection uses bounded exploration, hysteresis, failure cooldown, and a bounded
persistent snapshot; observations are latency, success, and a dimensionless
energy proxy unless the native app supplies separately measured energy.

The planner must describe Core ML choices as requested compute-unit policies,
not CPU/GPU/ANE proof. `ProcessInfo.thermalState`, Low Power Mode, MetricKit, and
physical-device profiling are native inputs. The proposed 20--40 percent
energy-delay lift is a **CLAIMED target**, not a result. No promotion occurs
until a fixed workload suite shows held-out lift without thermal or correctness
regression.

### 8. Distribution and App Store policy

An App Store build must admit only RVFs embedded and reviewed with the
application, set operator origin to `EmbeddedAppBundle`, and use the exact
whole-artifact identity pin. The Rust boundary authenticates that origin
assertion but cannot independently prove bundle membership. Any change to the
RVF bytes requires a new reviewed app build unless Apple has approved a
different distribution model.

Downloading an RVF that introduces or changes executable functionality may
conflict with [App Review Guideline 2.5.2](https://developer.apple.com/app-store/review/guidelines/).
Remote package acquisition must therefore be disabled unless the product has a
documented Apple-permitted model and legal/review approval. Signing and WASM
sandboxing do not independently make downloaded executable code App Store
compliant.

App Review Guideline 2.5.14 also requires explicit user consent and a clear
visual and/or audible indication while the app records, logs, or otherwise
makes a record of user activity, including camera and other user inputs. Native
RuView integration must provide an always-understandable capture/training
indicator and a user-controlled stop path; an RVF declaration or an iOS system
permission prompt is not a substitute for this product-level consent and
recording indication. The Rust crates do not implement that UI, so App Review
compliance remains a native-app acceptance gate. Their additional check is
limited to refusing camera/LiDAR/IMU when the re-sampled host facts do not
assert current consent and an active indicator.

## Evidence and Acceptance

Evidence labels are mandatory:

| Gate | Required result | Current evidence class |
|---|---|---|
| Signed-policy and artifact binding | unsigned metadata, broad-capability widening, signer mismatch, and same-signer replacement under a different whole-RVF identity are refused; operator policy and host-asserted origin are evidence-bound | **MEASURED deterministic software test**; bundle membership remains a native assertion |
| Canonical RVF shapes | checked-in packed runtime-v1 and Forge-authored Level-0 golden artifacts verify without weakening unknown-algorithm refusal | **MEASURED deterministic software test** on this branch; continuing CI gate, not a claim of all manifest semantics |
| Guest execution | real guest executes; WASI/unknown imports, out-of-envelope limits, excess host calls, and infinite loops refuse | **MEASURED deterministic software test** |
| Typed guest routing | exact BLE, Metal, and Core ML options survive signed-RVF/WASM routing; descriptors are bounded, one-shot, and generational | **MEASURED deterministic integration test** |
| Unsupported routes | guest network, memory, and clock requests cannot reach native code | **MEASURED deterministic integration test**; accepted typed adapters do not exist |
| Camera denial | undeclared and current-OS-denied requests never invoke native callback and emit a valid denial receipt | **MEASURED deterministic host-adapter test** |
| Consent/indicator gate | camera, LiDAR, and IMU refuse when re-sampled host facts lack explicit session consent or an active recording indicator | **MEASURED deterministic host-adapter test**; UI truth remains physical/native evidence |
| Metal admission | same RVF guest reaches an allowlisted typed Metal callback and emits intent/completion | **MEASURED deterministic host-adapter test**, not physical GPU evidence |
| Native postconditions | oversize sensor/Core ML results, over-duration Metal measurements, and late callback completion are refused and witnessed | **MEASURED deterministic software test**; no cancellation/preemption proof |
| Receipt integrity | mutation, internal deletion/reordering, invalid event pairs, and fact changes fail; retained seals bind terminal count/head and execution outcome | **MEASURED deterministic software test**; complete rollback still needs an external anchor |
| Apple compilation | HostedIOS crates compile for generic arm64 device and simulator Rust targets | **MEASURED cross-build**, not app linking or device execution |
| Targeted MSRV | the documented HostedIOS check/test subset runs under Rust 1.77.2 | **MEASURED targeted software gate**, not a workspace-wide MSRV claim |
| Physical iPhone | AVFoundation, ARKit, Motion, BLE, Metal, Core ML, Keychain, thermal, and lifecycle behavior | **not measured until an instrumented device run is captured** |
| Native app compliance | Swift/C bridge, permission UI, Guideline 2.5.14 consent/indicator, cancellation, Keychain persistence, and no bypass path | **not implemented by these Rust crates** |
| Portable artifact | exact RVF bytes produce matching policy/results on macOS and physical iOS | **not measured until native iOS bridge is exercised** |
| Adaptive efficiency | held-out mixed workload improves energy-delay efficiency by 20--40 percent without correctness or thermal regression | **CLAIMED target; not measured** |
| RuView calibration lift | held-out RF-only localization or coarse-pose metric improves at least 25 percent after phone-teacher calibration | **CLAIMED acceptance target; not measured** |

The CI `core-msrv` job deliberately has a targeted, not workspace-wide, Rust
1.77.2 contract. It checks `rvm-context` with all features and as `no_std` for
`aarch64-unknown-none`; checks `rvm-wasm-hosted`, `rvm-host-ios`,
`rvm-metal-ios`, `rvm-coreml`, `rvm-sensors-ios`, and `rvm-ios-runtime`; and
runs the `rvm-wasm-hosted`, `rvm-host-ios`, and `rvm-ios-runtime` tests. Other
workspace packages use the stable toolchain unless the workflow explicitly
adds them to the MSRV job. The Rust iOS target cross-build proves only that the
Rust crates compile for a generic target; it does not prove Swift/C linking,
framework behavior, App Store compliance, or iPhone execution.

Physical acceptance must archive the device/OS/app/RVF/model fingerprints,
permission states, room and sensor configuration, timestamps, thermal trace,
MetricKit/Instruments evidence, receipt head, evaluation split, baselines, and
raw metric summaries without committing private sensor data to this repository.

## Consequences

### Positive

1. A signed RVF has an enforceable fine-grained iOS policy rather than a broad
   descriptive label.
2. The only guest import is bounded and auditable; ambient WASI authority is
   absent.
3. Dynamic OS and thermal revocation happens at the same choke point as
   operator and artifact policy.
4. Receipts bind complete decision content and current host assertions while
   excluding raw personal and sensor data.
5. Apple acceleration can evolve behind typed host traits without confusing a
   requested compute policy with proven hardware placement.

### Negative

1. The native app remains trusted and can invalidate the evidence model if it
   exposes an alternate sensor, network, GPU, or model path.
2. This first implementation is a Rust package and native-host contract; a
   production app still needs Swift/C bindings and real Apple-framework
   implementations.
3. Receipts are not durable or remotely attested until the native application
   supplies those integrations.
4. Interpreter execution costs more than native/JIT execution, and App Store
   distribution constrains remotely acquired agents.
5. Exact ANE placement and physical-device energy remain empirically observed,
   not controlled by RVM.

## Rollout and Rollback

Rollout is fail-closed: first ship embedded read-only RVFs; then add native
camera/Motion/BLE adapters; then LiDAR; then Metal/Core ML; then persistent
receipts; finally enable learned plan selection only after benchmark gates.
RuView may consume the package only after its own integration tests prove there
is no direct native bypass.

Rollback disables HostedIOS agent admission and learned-plan selection, retains
sealed receipt heads and model/room provenance, and returns the app to its
existing fixed native pipeline. It must not silently reinterpret a HostedIOS
receipt as a bare-metal RVM witness or retain a learned plan after the device,
OS, app, model, room, or policy fingerprint changes.
