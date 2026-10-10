# Constellation metadata as native RVM context

`manifest.ruv` is an inert discovery document for the public ruvnet constellation.
The schema and public catalog live in https://github.com/ruvnet/ruvnet. A manifest
describes capabilities and source evidence; it grants no permission and does not
register a service, enroll a machine or execute anything.

The native logical identity uses the existing RVM URI grammar:

```text
ruv://ruvnet/constellation/service/rvm/resources/manifest.ruv
```

The authority is a logical namespace component. This string does not assert a
live resolver or ownership trust binding. An authorized deployment must define
its resolver, trust roots, policy and persistence separately.

## Existing compiler integration

The `rvm-context-service` crate exposes `compile_discovery_manifest`:

```rust
use rvm_context_service::compile_discovery_manifest;

// First validate the complete manifest against the pinned nexus schema.
let artifact = compile_discovery_manifest(manifest_bytes)?;
let name = artifact.uri();
let content_sha256 = artifact.content_digest();
let rvf_sha256 = artifact.artifact().identity();
let rvf_bytes = artifact.artifact().rvf();
```

The adapter checks a bounded 1 MiB metadata projection: schema version, public
visibility declaration, repository identity, native URI scope and both discovery
safety flags. It is not a complete JSON Schema validator and intentionally
preserves other metadata without interpreting it. The native URI parser rejects
ambiguous names, including dot or underscore in the subject identifier. GitHub
repository names map to lowercase subjects with dots and underscores replaced
by hyphens; the nexus rejects collisions.

The adapter calls the existing `RvfContextCompiler` with
`ContextCompileRequest::data`. The exact original JSON bytes become the content
view. The content digest and whole RVF identity are separate; changing JSON
formatting changes both identities. No executable segment is emitted. The
compiler verifies the resulting context profile before returning it.

The URI stays unpinned in the discovery document. If a deployment registers the
artifact, a `rev` selector must use the whole RVF identity, not the JSON digest.
Registration and grants require independent authorization and are outside this
adapter. A public visibility declaration is untrusted publisher metadata and
does not replace a disclosure review. Private manifests are refused here.

## Verification

```bash
git submodule update --init --depth 1 ruvector
cargo test -p rvm-context-service constellation --locked
```

Tests cover exact-byte RVF roundtrip and deterministic identity, formatting
changes, native URI failures, private input rejection, missing or unsafe flags,
duplicate guard fields, unsupported versions and input limits. The normal
workspace CI includes these tests. Availability of Rust, the pinned submodule
and dependencies is required; a source review is not a successful native run.

The context contracts retain their upstream ADR status. This discovery adapter
does not claim production anonymity, distributed consensus or authenticated
network resolution.
