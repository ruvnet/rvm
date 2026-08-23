# @ruvnet/rvm-context-wasm

The RVM `ruv://` context namespace compiled to WebAssembly from the Rust
[`rvm-context`](https://github.com/ruvnet/rvm/tree/main/crates/rvm-context) crate, with
TypeScript declarations.

Full namespace documentation: <https://ruvnet.github.io/rvm/ruv-context/>

## Read this first: the wasm module is its own authority

This package hosts a **complete governed context runtime** — its own capability table,
grant table, witness ring, and deterministic logical clock. That has consequences you
must understand before using the runtime layer.

Every capability it issues is an **index and a generation into its own live table**. A
capability handle is not signed, not serializable, and **not portable**. A handle minted
by a Rust-side service is just two integers that would index a different table here.
There is no "verify a capability issued elsewhere" API, because that is not
implementable: the module either owns its authority or it authorizes nothing.

A decision this module renders **binds only to the scope table the host provisioned into
it**. It is a faithful, deterministic policy simulator — correct for shadow-mode
evaluation — and it is **not evidence about a separate Rust-side authority** unless that
authority provisioned the same scopes. Anyone promoting this to enforcement must
provision the grant table from the same authority that issues real capabilities.

Two further limits, stated plainly rather than buried:

- **Root provisioning runs as the hypervisor.** The core crate refuses root capability
  creation unless the caller is `PartitionId::HYPERVISOR`. `issueRoot` performs it *as*
  the hypervisor, which is the concrete form of "its own authority". Treat it as host
  setup, not as something a partition may do. Everything below a root is subject to the
  ordinary governed checks.
- **Receipt signatures are a keyed MAC, not a public signature.** Receipts are signed
  with HMAC-SHA256, which is symmetric, so verifying one requires the same key that
  signed it. A caller able to check a receipt is equally able to forge one. Receipt
  verification here is an integrity check against corruption — it is **not** third-party
  verifiable evidence. The keyless checks (`verifyWitnessChain`, `witnessDigests`) are
  the ones that survive a trust boundary.

**The naming layer needs none of this.** `RuvUri` and `ContextScope` are pure and stand
completely alone — see below.

## What a `ruv://` URI looks like

```
ruv://context.example/acme/agent/researcher/memory/projects/atlas?rev=sha256:<64 hex>&view=overview
      └─ authority ─┘ └tenant┘ └kind┘ └subject┘ └collection┘ └── path ──┘ └── optional query ──┘
```

Every name has exactly one accepted spelling. Anything else is rejected rather than
normalized, so policy scopes, witness records, signatures, and caches cannot disagree
about URI equivalence.

## Install

```sh
npm install @ruvnet/rvm-context-wasm
```

## Usage

```js
const { RuvUri, RuvUriBuilder, ruvUriError } = require("@ruvnet/rvm-context-wasm");

const uri = RuvUri.parse(
  "ruv://context.example/acme/agent/researcher/memory/projects/atlas"
);

uri.authority;   // "context.example"
uri.tenant;      // "acme"
uri.subjectKind; // "agent"
uri.subjectId;   // "researcher"
uri.collection;  // "memory"
uri.path;        // ["projects", "atlas"]
uri.revision;    // undefined  (a mutable alias)
uri.view;        // undefined
uri.isPinned;    // false
uri.toString();  // the canonical spelling, byte for byte
```

An ES module build for browsers and bundlers is published at the `/web` subpath:

```js
import init, { RuvUri } from "@ruvnet/rvm-context-wasm/web";
await init();
```

### Building a URI

The builder validates each component as you supply it, so you never concatenate strings:

```js
const uri = new RuvUriBuilder("context.example", "acme", "team", "core", "resources")
  .segment("Specs")
  .segment("API_v1")
  .revision("sha256:" + "00".repeat(32))
  .view("overview")
  .build();
```

Every builder method returns a *new* builder, so a partially built value can be reused
across branches safely.

### Handling rejection

Invalid input throws a real `Error` whose `code` is the exact rejection reason, so you
can branch on the cause instead of matching message text:

```js
try {
  RuvUri.parse("ruv://context.example/ACME/agent/researcher/memory");
} catch (error) {
  error.name;    // "RuvUriError"
  error.code;    // "InvalidTenant"
  error.message; // "invalid canonical tenant slug"
}
```

For validation flows where throwing is inconvenient, `ruvUriError` reports the same code
without throwing, and `isRuvUri` returns a boolean:

```js
ruvUriError("ruv://context.example/acme/agent/researcher/memory"); // undefined
ruvUriError("ruv://context.example/acme/agent/researcher/memory/"); // "TrailingSlash"
```

Rejection codes include `InvalidScheme`, `InvalidAuthority`, `InvalidTenant`,
`InvalidSubjectKind`, `InvalidSubjectId`, `InvalidCollection`, `MissingComponent`,
`EmptyPathSegment`, `TrailingSlash`, `DotSegment`, `InvalidPathSegment`,
`PercentEncodingNotAllowed`, `FragmentNotAllowed`, `CredentialsNotAllowed`,
`PortNotAllowed`, `InvalidRevision`, `InvalidView`, `UnknownQueryKey`,
`DuplicateQueryKey`, `QueryOrder`, `UriTooLong`, `PathTooLong`, `TooManyPathSegments`,
and `NonAscii`.

### Scopes

`ContextScope` compares regions of the namespace. A scope is derived from a URI plus the
progressive views it discloses:

```js
const { ContextScope, ViewMask } = require("@ruvnet/rvm-context-wasm");

const parent = ContextScope.fromUri(RuvUri.parse(base + "/projects"), ViewMask.all());
const child = ContextScope.fromUri(RuvUri.parse(base + "/projects/atlas"), ViewMask.all());

parent.containsScope(child); // true
child.containsScope(parent); // false
```

This is a comparison of **names**, not an authorization decision. See the boundary
section below.

### Context profiles

`ContextProfile` decodes and re-encodes the deterministic progressive-view record that
maps `abstract`, `overview`, and `content` representations to RVF segments:

```js
const profile = ContextProfile.decode(bytes);
profile.views.map((v) => v.view);        // ["abstract", "overview", "content"]
profile.view("content").segmentId;        // 10n
profile.view("abstract").provenance.model; // "sha256:..."
```

## What this package does NOT do

**Holding a parsed URI grants nothing.** A `ruv://` URI is a name, not a token. Parsing
one successfully tells you the name is well formed; it tells you nothing about whether
anyone may read, write, or execute what it names.

Deliberately **not** exposed:

- **Any way to verify or import a capability issued by another process.** See above: a
  handle is a local table index, so this cannot be built.
- **`default_signer`, `with_default_key`, `derive_witness_key`, and `dev_measurement`.**
  A well-known or derivable default signing key is indistinguishable from no key at all.
  The host supplies the 32-byte key or nothing is signed.
- **`VerifiedContextProfile.from_rvf`**, which binds a profile to a verified RVF
  identity. It needs full RVF container bytes and trusted publisher keys — a
  key-management concern that belongs to the host.

### Fixed capacities

The core types hold their tables inline, so this module compiles in fixed capacities
rather than the core defaults. `ContextRuntime.capacities` reports them:

| Table | Slots |
| --- | --- |
| Capabilities | 64 |
| Scope grants | 64 |
| Witness ring | 1024 |
| Resolver objects | 64 |
| Resolver aliases | 64 |

The core witness default is 262,144 records, which as an inline array would reserve
about 16 MiB inside the module. The ring is sized down here, and the capacity is part of
this package's published contract.

## API surface

| Export | Purpose |
| --- | --- |
| `RuvUri.parse(text)` | Parse a canonical URI, or throw `RuvUriError`. |
| `uri.authority` / `.tenant` / `.subjectKind` / `.subjectId` / `.collection` / `.path` | Structured components. |
| `uri.revision` / `.view` / `.isPinned` | Optional query state. |
| `uri.toString()` | The one canonical spelling. |
| `uri.withRevision(rev)` / `.withView(view)` | Derive a pinned or view-selected copy. |
| `uri.equals(other)` | Structural equality. |
| `new RuvUriBuilder(authority, tenant, subjectKind, subjectId, collection)` | Validated construction. |
| `.segment(s)` / `.revision(r)` / `.view(v)` / `.build()` | Builder steps, each returning a new builder. |
| `ruvUriError(text)` / `isRuvUri(text)` | Non-throwing validation. |
| `ViewMask.all()` / `.manifest()` / `.view(name)` / `.fromBits(bits)` | Progressive-view masks. |
| `mask.bits` / `.union(m)` / `.allows(name)` / `.contains(m)` | Mask arithmetic. |
| `ContextScope.fromUri(uri, mask)` | Derive a namespace region. |
| `scope.containsScope(child)` | Name containment, not authorization. |
| `ContextProfile.decode(bytes)` / `.toBytes()` / `.views` / `.view(name)` | Profile codec. |
| `contractVersion()` | The `ruv://` contract version this binding implements. |


### Governed runtime

Read the authority caveat at the top before using any of these.

| Export | Purpose |
| --- | --- |
| `new ContextRuntime(actorId)` | A runtime bound to an actor, with a deterministic logical clock. |
| `runtime.issueRoot(scope, rights, owner)` | Host provisioning; runs as the hypervisor. |
| `runtime.delegate(handle, childScope, rights, owner)` | Narrower delegation; refuses escalation. |
| `runtime.revoke(handle)` | Revoke a lineage, returning how many capabilities fell. |
| `runtime.resolve / read / verify / put / list / tree / history / search` | Governed operations. |
| `runtime.compareAndSwapAlias / forget` | Alias mutation with compare-and-swap. |
| `runtime.authorizeExecute(handle, uri)` | An execution permit carrying no readable bytes. |
| `runtime.grant / revokeGoverned` | Delegation and revocation through the witnessed path. |
| `runtime.sealEpoch(handle, uri, key, commitments)` | Seal an epoch into a signed receipt. |
| `runtime.witnessSequence` / `.witnessChainHash` / `.witnessRecordCount` | Witness log state. |
| `runtime.verifyWitnessChain()` | Keyless hash-chain integrity check over its own log. |
| `runtime.witnessDigests()` | Keyless per-record SHA-256 digests, concatenated. |
| `ContextRuntime.capacities` | The compiled-in slot counts. |
| `Rights.forOperation(name)` / `.forOperations(names)` / `.fromNames(names)` | Rights sets. |
| `new EpochCommitments(namespaceRoot, rvfIdentity, policyHash, detailRoot)` | The four 32-byte epoch roots. |

Each governed result carries `witnessSequence`, the sequence at which the decision was
recorded.

### Receipt verification

| Export | Purpose |
| --- | --- |
| `SignedReceipt.decode(bytes)` / `.toBytes()` | Canonical receipt encoding. |
| `receipt.receiptId` / `.signerId` / `.signature` | Identity fields. |
| `receipt.epochId` / `.firstSequence` / `.lastSequence` / `.recordCount` | Epoch coverage. |
| `receipt.witnessRoot` / `.namespaceRoot` / `.policyHash` / `.previousReceipt` | Commitments. |
| `receipt.verifySignature(key)` | Keyed MAC check. Not third-party verifiable. |
| `receipt.verifyGenesis(key)` | MAC check plus a well-formed genesis check. |
| `receipt.verifySuccessor(previous, key)` | MAC check on both plus the continuity link. |

TypeScript declarations are generated by `wasm-bindgen` and ship with the package.

## Building from source

```sh
node crates/rvm-context-wasm/scripts/build-npm.mjs
node crates/rvm-context-wasm/tests/smoke.mjs
```

Requires the `wasm32-unknown-unknown` target and `wasm-pack`.

The Rust-side binding tests run on the real wasm target under Node:

```sh
wasm-pack test --node crates/rvm-context-wasm
```

## License

MIT OR Apache-2.0, matching the RVM workspace.
