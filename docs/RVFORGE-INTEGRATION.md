# RVForge Integration Map

RVM is the intended execution backend for
[RVForge](https://github.com/ruvnet/RuVector), the toolchain that packages,
verifies, signs, and publishes one canonical `.rvf` agent artifact. This
document maps the two repositories' responsibilities and names the contract
artifacts that hold them together.

See [ADR-155](adr/ADR-155-rvf-execution-contract.md) for the decision record.

## What RVForge Is Today

RVForge v0.1.0 takes one signed `.rvf` and produces verified **staged bundles**
per target, a signed release in a content-addressed registry, provenance
records, and hash-chained witness receipts:

```
agent.rvf  →  staged bundle per target  +  signed release (registry)
              software inventory           transparency-log entry
              SHA-256 checksums            witness receipts
```

Native installer generation (`.exe` / `.msi` / `.dmg` / `.deb` / `.AppImage`)
requires the Tauri packaging layer and is the next phase on the RuVector side;
when that toolchain is absent the CLI labels its output `staged` and claims no
installer. `Agent.rvm.img` and the other bare-metal outputs are roadmap.

The claim that makes this worth building is that the artifact a publisher signs
is the artifact every user runs — same identity, same declared capabilities,
same witness chain, on every platform. RVM is where that claim is either kept or
broken.

| | |
|---|---|
| **npm package** | `@ruvector/rvforge@0.1.0` |
| **Source** | RuVector PR #790 (merged, `cbf9f6d7b`) |
| **Overview** | [RVForge gist](https://gist.github.com/ruvnet/d08d9c00e140f570fb896256dc7cb1f7) |
| **Canonical input** | one signed `.rvf` |
| **Outputs today** | verified staged bundles, signed registry releases, provenance + witness receipts |
| **Outputs next phase** | native signed installers per platform, hosted build fleet |

## Division of Responsibility

The boundary is deliberately sharp: RuVector owns everything that produces and
distributes the artifact, RVM owns everything that executes it.

| Concern | Owner |
|---|---|
| `rvforge` CLI (`validate`, `build`, `submit`, `verify`) | RuVector |
| Packaging into `.exe` / `.msi` / `.dmg` / `.deb` / `.AppImage` | RuVector |
| Signing, notarization, build provenance, trust boundary | RuVector |
| Agent store / registry and its trust model | RuVector |
| Desktop RVF Reader | RuVector |
| Canonical compatibility matrix | RuVector (RVM publishes the validated combinations it feeds) |
| **RVF loading and verification on the machine** | **RVM** |
| **Capability enforcement, witness emission, proof gating** | **RVM** |
| **Execution backends: bare metal, hosted, WASM, browser** | **RVM** |
| **State deltas, checkpoints, suspend/resume/migrate** | **RVM** |

Neither side trusts the other's gate. Forge rejects unsupported combinations at
build-manifest time; RVM independently rejects incompatible RVFs at load. A
package outlives the matrix revision that admitted it, so both gates are
required.

## RVM Crates That Participate

| Crate | Status | Role |
|---|---|---|
| `rvm-rvf` | **new** | The format/machine boundary: manifest reading, signature and hash verification, segment resolution, version rejection, capability mapping, identity preservation |
| `rvm-cap` | existing | Capability tables and the seven rights; receives the mapped RVF policy |
| `rvm-witness` | existing | 64-byte hash-chained records for every verification result, capability grant, and capability denial |
| `rvm-wasm` | existing | WASM guest runtime; carries `MAX_MODULE_SIZE` as the executor backstop until streaming validation lands |
| `rvm-security` | existing | The three-stage gate — capability check → proof verification → witness recording → operation — and the only privileged path |
| `rvm-proof` | existing | P1/P2/P3 verification and `WitnessSigner` trust anchors cross-checked against `rvf-crypto` |
| `rvm-boot` | existing | Seven-phase measured boot used by the bare-metal and appliance outputs |
| `rvm-gpu` | existing | GPU capability class routes through its existing capability and `DmaBudget` checks |

`rvm-rvf` depends on `rvm-cap`, `rvm-witness`, `rvm-wasm`, and `rvm-security`,
and on RuVector's `rvf-manifest` and `rvf-crypto` through the `ruvector/`
submodule.

## The Contract Artifacts

Three artifacts carry the agreement between the repositories.

### 1. The embedded runtime contract

Every Forge-generated package embeds this, covered by the package signature and
readable by `forge verify` without executing the payload:

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

`rvm-rvf` reads it at load and refuses execution when the declared schema
versions are unsupported, when `capabilityPolicyHash` does not match the policy
the package was built against, or when a required capability class is not
implementable on the host.

### 2. The capability policy

Fifteen classes, default-deny, mapped total into `rvm-cap` rights:

```text
Memory · Filesystem · Network · Model · MCP · Process · Clock · Randomness
GPU · Sensor · Display · Audio · Clipboard · Persistent state
Inter agent messaging
```

An absent declaration is a denial, not an unspecified case for the host to
resolve. When a backend cannot provide a declared class, RVM refuses execution
and witnesses the refusal rather than starting with a reduced set.

### 3. The compatibility matrix

`docs/rvforge-compatibility-matrix.json` (repo copy; canonical copy lives in
RuVector at `docs/research/rvf-forge/compatibility-matrix.json`). Forge consults
it and rejects absent combinations before allocating a build worker.

| Runtime profile | Isolation claim | Status |
|---|---|---|
| `wasm` | `wasm-sandbox` | supported |
| `os-isolation+wasm` | `os-sandbox+wasm` | supported |
| `linux-microvm` | `microvm` | planned |
| `rvm-native` | `partition` | planned — blocked on `rvm-rvf` / `rvm-host` landing here |

Selection order is strongest-compatible-first (`rvm-native`,
`os-isolation+wasm`, `wasm`, `linux-microvm`), changeable only by signed policy.
A package may select a runtime at or below the profile it was built for, never
above it.

**Isolation-claim honesty.** Hosted RVM provides OS isolation plus WASM. It does
not provide partition memory isolation, device leases, or measured boot, and it
must never be described as bare-metal isolation in documentation, UI, or package
metadata. The matrix records the distinction structurally in `isolationClaim`.

## Loading Rules

Every backend, and every tool that opens an RVF:

1. Verify the root manifest **before** allocating executable memory.
2. Verify every referenced segment before loading it — root-manifest validity is
   not transitive trust.
3. Reject unsigned executable segments by default.
4. **Never execute RVF content during inspection or packaging.** `rvm inspect`
   and `rvm verify` are distinct operations from `rvm run` precisely so that
   pointing a scanner at a hostile artifact is safe.
5. Emit a witness record for every verification result, success and failure
   alike.
6. Refuse execution when the RVF requires unsupported capabilities.

## Roadmap on the RVM Side

| Item | Reference | Notes |
|---|---|---|
| `rvm-rvf` | ADR-155 | The loader; in progress on `feat/rvforge-integration` |
| Streaming WASM validation | RuVector ADR-287 | Replaces `MAX_MODULE_SIZE` with incremental validation under signed policy; Component Model and WIT import reconciliation land with it |
| `rvm-host` | RuVector ADR-289 | Per-OS adapters: Windows, macOS, Linux, browser, QEMU, bare metal |
| `rvm-launch` | RuVector ADR-289 | `inspect`, `verify`, `run`, `suspend`, `resume`, `checkpoint`, `witness`, `terminate` |
| `rvm-ffi` | RuVector ADR-289 | Stable C interface for Tauri and other native hosts |
| `rvm-node` | RuVector ADR-289 | Node bindings consumed by `@ruvector/rvforge` |
| `rvm-policy` | RuVector ADR-284 | Signed size and capability policy enforcement |
| `rvm-state` | RuVector ADR-288 | Immutable base plus encrypted delta segments, checkpoint reconstruction |
| Populate `rvmVersionMin` | RuVector ADR-291 | Currently null; set when `rvm-rvf` ships a versioned execution contract |
| Bare-metal outputs | RuVector ADR-293 | `Agent.rvm.img`, `Agent.rvm.efi`, `Agent.appliance.bundle` via the seven-phase measured boot |

## Cross-Repo ADR Index

| RuVector ADR | Topic | RVM counterpart |
|---|---|---|
| ADR-283 | RVForge canonical installer pipeline | — |
| ADR-284 | RVF execution contract | **ADR-155** |
| ADR-285 | Hosted RVM security boundary | ADR-155 §7 |
| ADR-286 | RVF capability schema mapping | ADR-155 §3 |
| ADR-287 | WASM Component Model integration | ADR-155 §4 (future work) |
| ADR-288 | Immutable base and state delta lifecycle | `rvm-state` (roadmap) |
| ADR-289 | Desktop host adapters | `rvm-host` / `rvm-launch` / `rvm-ffi` / `rvm-node` (roadmap) |
| ADR-291 | Runtime compatibility and version negotiation | ADR-155 §5–6 |
| ADR-293 | RVM installer and appliance formats | Bare-metal outputs (roadmap) |

RuVector ADRs live at `ruvector/docs/adr/` via the submodule.

## Quick Access

```bash
# Read the RVM-side decision record
cat docs/adr/ADR-155-rvf-execution-contract.md

# Read the compatibility matrix
cat docs/rvforge-compatibility-matrix.json

# Read the RuVector-side counterparts (submodule)
cat ruvector/docs/adr/ADR-284-rvf-execution-contract.md
cat ruvector/docs/adr/ADR-286-rvf-capability-schema-mapping.md

# The executor backstop this contract still relies on
grep -n MAX_MODULE_SIZE crates/rvm-wasm/src/lib.rs
```

## Related

- [ADR-149](adr/ADR-149-rvf-integration.md) — RVF as RVM's own container format
  (boot images, dormant memory, witness archives). ADR-155 covers the inverse
  direction: third-party RVFs arriving through Forge.
- [RuVector Integration Map](RUVECTOR-INTEGRATION.md) — the broader RuVector
  ecosystem and the 22-crate RVF package family.
