# @ruvnet/rvm-context

TypeScript and JavaScript bindings for the RVM `ruv://` context namespace, compiled to
WebAssembly from the Rust [`rvm-context`](https://github.com/ruvnet/rvm/tree/main/crates/rvm-context)
crate.

This is the **naming and validation layer**. It parses, validates, constructs, and
canonically formats `ruv://` URIs using the exact same code the RVM kernel uses, so a
JavaScript tool and the kernel can never disagree about what a name means.

Full namespace documentation: <https://ruvnet.github.io/rvm/ruv-context/>

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
npm install @ruvnet/rvm-context
```

## Usage

```js
const { RuvUri, RuvUriBuilder, ruvUriError } = require("@ruvnet/rvm-context");

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
import init, { RuvUri } from "@ruvnet/rvm-context/web";
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
const { ContextScope, ViewMask } = require("@ruvnet/rvm-context");

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

- **The governed runtime** (`ContextRuntime`, `ExecutionPermit`) and **the resolver**
  (`ContextResolver`, `MemoryResolver`). These require an authenticated partition
  identity, a context clock, and live storage. A JavaScript-side actor supplying those
  would be precisely the forgery the design prevents.
- **Capability issuance, delegation, and revocation** (`ContextAuthority`,
  `ContextGrantTable`, `AuthorizedRequest`). Authorization decisions belong to the
  kernel, which alone can bind a capability to a scope and commit the decision to the
  witness trail.
- **Receipt sealing** (`ContextEpochReceipt` and friends), which mints signed witness
  records.
- **`VerifiedContextProfile.from_rvf`**, which binds a profile to a verified RVF
  identity. It needs full RVF container bytes and a set of trusted Ed25519 publisher
  keys — a key-management concern that belongs to the host, not to a naming library.

`ContextScope.containsScope` is included because it is pure name arithmetic, and because
a JavaScript caller who needs it would otherwise hand-roll a prefix match that drifts
from the kernel's. Reusing the real implementation is safer than reimplementing it. It
still is not an access check: only the kernel decides what a capability permits.

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
