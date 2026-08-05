# ADR-155: RVF Execution Contract for RVForge Packages

**Status**: Accepted
**Date**: 2026-08-05
**Updated**: 2026-08-05 — runtime module bytes are matched against verified executable-segment identities before start or created-state restore (rvm#19).
**Authors**: Claude Code
**Supersedes**: None
**Related**: ADR-132 (Hypervisor Core), ADR-134 (Witness Schema), ADR-135 (Proof Verifier), ADR-140 (Agent Runtime Adapter), ADR-149 (RVF Integration), RuVector ADR-284 (RVF Execution Contract), RuVector ADR-285 (Hosted RVM Security Boundary), RuVector ADR-286 (Capability Schema Mapping), RuVector ADR-287 (WASM Component Model), RuVector ADR-291 (Runtime Compatibility and Version Negotiation)

---

## Context

RVForge (`@ruvector/rvforge` v0.1.0, RuVector PR #790) packages, verifies,
signs, and publishes one canonical `.rvf` artifact, and is designed to emit
signed installers for Windows, macOS, Linux, the browser, and RVM appliances —
v0.1.0 ships the packaging, verification, registry, and provenance layers, with
native installer generation and hosted builds as the next phase. Its central
claim is that the artifact a publisher signs is the artifact every user runs, on
every platform. That claim is only true if the runtimes underneath behave
identically — a signed RVF that yields different results on the desktop Reader
than on a bare-metal appliance is not one portable agent, it is five agents that
happen to share a filename.

This ADR records the contract RVM commits to. It is **Accepted as a decision**;
the implementation in this repository begins with the `rvm-rvf` loader
(verification, capability mapping, witness emission) and does not yet include
the execution backends (`rvm-host`, `rvm-launch`, `rvm-ffi`, `rvm-node`) that a
complete quarantined runtime requires.

RVM is the execution side of that claim. ADR-149 already established RVF as the
universal container format for RVM's own artifacts (boot images, dormant memory
checkpoints, witness archives, GPU kernels). What ADR-149 did not specify is the
inverse direction: how RVM consumes a *third-party* RVF that arrives from a
publisher through Forge, carrying its own capability policy, its own model
segments, and its own identity that RVM must preserve rather than mint.

RVM already provides the primitives this needs — partitions, capability tables,
64-byte hash-chained witnesses, three-tier proof gates, measured boot, and a
seven-state WASM agent lifecycle. The missing pieces are the loader that binds
an external RVF to those primitives, the mapping from RVF capability policy into
`rvm-cap` rights, and the version contract that lets Forge know in advance which
combinations RVM will actually accept.

RuVector ADR-284 defines this contract from the format side. This ADR is its
RVM-side counterpart: it commits RVM to the contract and specifies how the
existing crates implement it.

### Problem Statement

1. **No loader for externally-authored RVFs**: `rvm-boot` and `rvm-memory`
   consume RVF containers that RVM itself produced. Nothing owns the boundary
   between a publisher-signed RVF and the machine.
2. **Inspection and execution are not separated**: any path where "reading" an
   RVF can become "running" an RVF turns every scanner, validator, and
   `rvm inspect` invocation into an execution surface for untrusted third-party
   code.
3. **RVF capability policy has no route into `rvm-cap`**: "the RVF declares what
   the agent may do" and "RVM enforces what the agent may do" are currently two
   unconnected claims, and the space between them is where undeclared access
   lives.
4. **`rvm-wasm` caps modules at 1 MB**: `MAX_MODULE_SIZE` in
   `crates/rvm-wasm/src/lib.rs` is a compile-time constant, far below a
   practical agent runtime that bundles an interpreter, tool adapters, and
   interface code. A publisher cannot raise it for a legitimately large
   component and an operator cannot lower it for a hostile tenant.
5. **No version binding between a package and the runtime inside it**: a `.exe`
   or `.deb` does not inherently record which RVM it embeds, which capability
   policy it was built against, or which state and witness schemas it can read.
6. **Hosted mode has no isolation-claim discipline**: RVM running as an ordinary
   desktop process provides OS isolation plus WASM, which is not partition
   isolation, and must not be described as though it were.

---

## Decision

RVM adopts the RVF execution contract. **The same signed RVF runs unchanged
across every RVM backend with identical capability, witness, state, and
lifecycle semantics.** The backends are:

```text
RVM bare metal
RVM hosted mode
RVM WASM mode
Browser WASM
Desktop RVF Reader
```

A backend that cannot provide those semantics is not a conforming backend, and
Forge must not emit a package targeting it.

### 1. `rvm-rvf`: the Format/Machine Boundary

A new crate, `rvm-rvf`, owns everything between the RVF file and RVM's kernel
objects. It is the only crate that parses publisher-supplied RVF structure.

| Responsibility | Detail |
|---|---|
| Manifest reading | Parse the root manifest via `rvf-manifest`; no execution, no instantiation |
| Signature and hash verification | Verify through `rvf-crypto`, cross-checked against `rvm-proof`'s `WitnessSigner` trust anchors (ADR-142, ADR-149) |
| Segment resolution | Resolve runtime, model, memory, policy, and acceleration segments by manifest reference |
| Loading | Hand verified segments to `rvm-memory`, `rvm-wasm`, and `rvm-policy` |
| Version rejection | Refuse RVFs declaring schema versions this build does not implement |
| Capability mapping | Translate RVF policy declarations into `rvm-cap` rights (section 3) |
| Identity preservation | Carry the canonical `rvfIdentity` unchanged; RVM never re-mints it |

`rvm-rvf` sits alongside the existing `rvm-cap`, `rvm-witness`, `rvm-wasm`, and
`rvm-security` crates and depends on all four.

### 2. Loading Rules

These apply to every backend and to every tool that opens an RVF, including
inspection and packaging tooling:

1. **Verify the root manifest before allocating executable memory.** Allocation
   follows verification; it never precedes it.
2. **Verify every referenced segment before loading it.** Root-manifest validity
   is not transitive trust for segment contents. Each segment is verified
   independently against its manifest-declared hash.
3. **Reject unsigned executable segments by default.** A model or data segment
   may be policy-permitted unsigned; an executable one may not.
   Before start or a created-state restore, the supplied module bytes must
   match the length and SHA-256 identity of an executable segment retained by
   the passing verification report. A mismatch is witnessed and refused
   before adapter admission or agent creation.
4. **Never execute RVF content during inspection or packaging.** `rvm inspect`
   and `rvm verify` are first-class operations distinct from `rvm run` precisely
   so that pointing a scanner at a hostile artifact is safe. This is the runtime
   half of Forge's "build workers never execute the submitted RVF" invariant.
5. **Produce a witness record for every verification result**, success and
   failure alike. A rejected RVF is an auditable event, not a silent error.
6. **Refuse execution when the RVF requires unsupported capabilities.**
   Degrading to a partial capability set is not permitted (section 3).
7. Support progressive loading for large model segments, encrypted segments, and
   architecture-specific acceleration segments.

Rules 1, 2, and 5 are already implemented on the RuVector side in
`rvf-forge-core` (RuVector ADR-284) and consumed by the desktop Reader; this ADR
commits RVM's loader to the identical behavior so the two sides of the contract
agree.

### 3. Capability Mapping into `rvm-cap`

RVF capability policy maps directly into `rvm-cap` rights. The mapping is
**total and default-deny** across fifteen classes:

```text
Memory · Filesystem · Network · Model · MCP · Process · Clock · Randomness
GPU · Sensor · Display · Audio · Clipboard · Persistent state
Inter agent messaging
```

**Default deny.** Nothing is granted unless the RVF policy declares it. An
absent declaration is a denial, not an unspecified case to be resolved by host
defaults. The WASM runtime's baseline is no filesystem, network, environment,
clock, randomness, GPU, or device access; the capability mapping selectively
re-opens individual rights against that closed baseline.

**The `rvm-security` gate remains the only privileged path.** Every external
operation passes through the existing three-stage sequence:

```text
Capability check → Proof verification → Witness recording → Operation
```

No backend, host adapter, acceleration segment, or convenience API may reach an
external resource by another route. The ordering is load-bearing: the operation
is last and the witness record precedes it, so a granted operation is auditable
even if it subsequently fails.

**Requests and denials are both witnessed.** A denial is evidence — it is how
"undeclared access was attempted and refused" becomes provable rather than
asserted. Denial records use the existing 64-byte `WitnessRecord` shape (ADR-134)
with a capability-denial `ActionKind`.

**Refusal, not degradation.** If a backend cannot provide a declared capability
class, the outcome is a witnessed refusal at load time, never a silent start
with a reduced set. An agent that quietly runs without a capability it declared
as required is indistinguishable, from the outside, from an agent that is
working. Forge applies the same rule ahead of time by consulting the
compatibility matrix (section 6).

Class-level notes that bind to existing RVM subsystems:

| Class | RVM binding |
|---|---|
| Memory | `rvm-memory` quotas; one component may never read another's linear memory |
| Filesystem / Network | Declared paths and destinations only; host adapters supply the enforcement mechanism |
| Model | Bounded by the signed maximum-model-size policy (section 4) |
| MCP | A distinct authority, never implied by a network grant |
| Clock / Randomness | Deniable by default; deterministic virtual clock and seeded randomness modes underpin identical evaluation hashes |
| GPU | Explicit declaration only; routes through `rvm-gpu`'s existing capability and `DmaBudget` checks (ADR-144, ADR-151) |
| Persistent state | Deltas bound to the base RVF identity; unrelated lineage rejected |
| Inter agent messaging | A declared capability, not an ambient property of sharing a runtime |

This is the RVM-side counterpart of RuVector ADR-286, whose schema side (the
default-deny `CapabilityManifest`, vague-scope rejection, and Reader capability
card) has already landed.

### 4. Size Limits Move to Signed Policy

Maximum model, runtime, memory, and state sizes are enforced through **signed
policy**, not compile-time constants, and the policy hash is part of the
artifact's verifiable identity (section 5). When policy omits a limit, the
runtime applies a conservative built-in default rather than an unbounded one; an
RVF that needs more must say so in signed policy.

`rvm-wasm`'s existing `MAX_MODULE_SIZE` (1 MB, `crates/rvm-wasm/src/lib.rs:53`)
**remains in place as an executor backstop** for this ADR. It is the floor that
holds while streaming validation is built, not the mechanism the contract
depends on. Replacing it with incremental validation from the RVF segment reader
— so that a large component neither forces a proportional buffer allocation nor
is rejected by a constant no publisher can raise — is future work tracked under
RuVector ADR-287. Until that lands, RVM's conforming WASM profile is bounded by
the backstop, and Forge's compatibility matrix must not advertise component
sizes RVM cannot yet accept.

### 5. The Embedded Contract

Every Forge-generated package embeds a machine-readable runtime contract, and
`rvm-rvf` reads it at load:

```json
{
  "rvfIdentity": "sha256 value",
  "rvmVersion": "semantic version",
  "rvmCommit": "source revision",
  "runtimeProfile": "wasm",
  "capabilityPolicyHash": "sha256 value",
  "stateSchemaVersion": 1,
  "witnessSchemaVersion": 1
}
```

| Field | Meaning for RVM |
|---|---|
| `rvfIdentity` | SHA-256 of the canonical RVF; identical across every package from one build, and preserved unchanged by `rvm-rvf` |
| `rvmVersion` / `rvmCommit` | The exact runtime version and source revision embedded; both required, because a semantic version alone does not identify a build |
| `runtimeProfile` | The runtime family this package was validated for; RVM may select a runtime at or below it, never above |
| `capabilityPolicyHash` | SHA-256 of the capability policy; makes the granted set part of the artifact's identity rather than a host-side configuration |
| `stateSchemaVersion` | The state delta and checkpoint schema this runtime reads and writes |
| `witnessSchemaVersion` | The witness record schema this runtime emits |

Load-time checks run in this order, and a failure at any step produces a witness
record and refuses execution:

1. Root manifest signature and hash verify.
2. Declared `stateSchemaVersion` and `witnessSchemaVersion` are supported.
3. `capabilityPolicyHash` matches the policy the package was built against.
4. Required capability classes are all implementable on this host.
5. Every referenced segment verifies before it is loaded.

Build-time gating (Forge) and load-time rejection (RVM) are **independent
defenses**. Neither may be skipped because the other exists: packages outlive
matrix revisions, and an installed package must still refuse an incompatible
RVF.

### 6. The Published Compatibility Matrix

RVM publishes a versioned, hash-addressed compatibility matrix enumerating the
validated combinations of `rvmVersion`, `runtimeProfile`, `stateSchemaVersion`,
`witnessSchemaVersion`, and target platform. Forge consults it and rejects
absent combinations at build-manifest generation time, before upload and before
a worker is allocated — a stable machine-readable error naming the offending
field and the nearest supported combination. Forge does not approximate,
downgrade, or substitute a runtime to make an unsupported request succeed.

The repo copy lives at `docs/rvforge-compatibility-matrix.json`; the canonical
copy is in RuVector at `docs/research/rvf-forge/compatibility-matrix.json`. The
build provenance record names the matrix revision that admitted a build, so a
past admission decision can be reconstructed.

The current matrix marks `rvm-native` (bare-metal partition isolation, via the
seven-phase measured boot of `rvm-boot`) and `linux-microvm` as **planned**, and
`rvmVersionMin` as null pending `rvm-rvf` shipping a versioned execution
contract. Landing this ADR's implementation is what populates those fields.

### 7. Hosted-Mode Isolation-Claim Honesty

RVM running as an ordinary desktop process provides **operating-system isolation
plus WASM**. It provides namespaces, cgroups, seccomp, and network namespaces on
Linux; Job Objects and restricted tokens on Windows; App Sandbox, hardened
runtime, and scoped entitlements on macOS.

It does **not** provide partition memory isolation, device leases, measured
boot, or the hardware-backed trust that bare-metal RVM provides. The
compatibility matrix records this distinction structurally: the hosted profile's
`isolationClaim` is `os-sandbox+wasm`, and `rvm-native`'s is `partition`.

**Hosted mode must never be described, in documentation, UI, or package
metadata, as bare-metal isolation.** This is RuVector ADR-285's rule and it is
load-bearing here for a second reason: the same ADR forbids native extensions
from loading into the RVF Reader process, because in-process native code could
reach resources without passing the `rvm-security` gate at all, which would make
every capability decision in section 3 advisory rather than enforced. Native
extensions require a separate sandbox or an RVM partition.

### 8. Acceptance

A release conforms only when one signed RVF:

1. Runs unchanged on hosted Linux, Windows, macOS, QEMU, and bare-metal RVM.
2. Produces identical deterministic evaluation hashes.
3. Cannot access undeclared files, networks, memory, devices, or agents.
4. Suspends on one backend and resumes on another.
5. Preserves its base RVF identity.
6. Reconstructs state from checkpoint plus witness deltas.
7. Rejects modified runtime, policy, model, and state segments.
8. Produces a complete cryptographically verifiable witness chain, including
   records for capabilities that were denied.

---

## Consequences

### Positive

- Portability becomes a testable property rather than a marketing claim:
  criterion 4 (suspend on one backend, resume on another) either works or it
  does not.
- Inspection tooling can be pointed at hostile artifacts safely, which is what
  lets Forge scan submitted packages without executing their payload.
- "Undeclared capabilities remain inaccessible" becomes enforceable at a single
  auditable choke point — the existing `rvm-security` gate — instead of being
  redistributed across five backends.
- Binding `capabilityPolicyHash` to the artifact identity means a grant cannot be
  widened without changing the artifact.
- RVM gains a distribution channel: an agent built by any publisher reaches
  appliances and desktops through one signed pipeline.

### Negative

- Identical semantics across five backends is a demanding contract; each new
  backend costs conformance work, not just a port.
- Verify-before-allocate and per-segment verification add startup latency that
  must fit inside the Reader's 500 ms pre-model-load budget.
- Fifteen capability classes is a large surface to enforce consistently, and
  each backend must implement all of them or refuse.
- Default-deny means publishers declare capabilities explicitly, which is more
  work than an implicit-grant model and will produce early friction.
- Refusing rather than degrading turns capability mismatches into hard failures
  at install or launch time — a worse user experience than a partial run, and
  the correct trade.
- Two independent gates (build-time and load-time) duplicate some checking cost.

### Risks

- The 1 MB `MAX_MODULE_SIZE` backstop constrains what RVM can honestly advertise
  in the compatibility matrix until streaming validation lands; a matrix entry
  written optimistically would ship installers that fail on first run.
- Policy-controlled limits move a class of failures from compile time to
  deployment time, so policy-authoring errors become an operational risk.
- The compatibility matrix must be maintained, validated, and published on every
  RVM release; a stale matrix gates Forge availability.
- Preserving `rvfIdentity` unchanged means any RVM-side normalization of a
  loaded RVF is a contract violation, which constrains future loader
  optimizations.

---

## References

- `crates/rvm-wasm/src/lib.rs:53` -- `MAX_MODULE_SIZE`, the 1 MB executor backstop
- `crates/rvm-cap/` -- capability tables and the seven rights
- `crates/rvm-security/` -- capability check → proof verification → witness recording → operation
- `crates/rvm-witness/` -- 64-byte hash-chained verification and denial records
- `crates/rvm-boot/` -- seven-phase measured boot used by bare-metal RVM outputs
- `docs/RVFORGE-INTEGRATION.md` -- repo-level integration map
- `docs/rvforge-compatibility-matrix.json` -- published matrix (repo copy)
- ADR-134 -- Witness schema and 64-byte record format
- ADR-142 -- TEE-backed cryptographic verification, `WitnessSigner`
- ADR-149 -- RVF as RVM's universal container format (the inbound direction)
- RuVector ADR-284 -- RVF execution contract (format-side counterpart)
- RuVector ADR-285 -- Hosted RVM security boundary, isolation-claim honesty
- RuVector ADR-286 -- RVF capability schema mapping into `rvm-cap`
- RuVector ADR-287 -- WASM Component Model, streaming validation (future work)
- RuVector ADR-289 -- Desktop host adapters (`rvm-host`, `rvm-launch`, `rvm-ffi`, `rvm-node`)
- RuVector ADR-291 -- Runtime compatibility and version negotiation
