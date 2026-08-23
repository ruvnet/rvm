#!/usr/bin/env node
// Node smoke test for the built @ruvnet/rvm-context-wasm package.
//
// Packs and installs the package into a temporary directory, then imports it by
// its published name so the exports map and files list are exercised the same
// way a consumer would exercise them.
//
// Usage: node crates/rvm-context-wasm/tests/smoke.mjs
//        (run scripts/build-npm.mjs first)

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const crateDir = dirname(dirname(fileURLToPath(import.meta.url)));
const pkgDir = join(crateDir, "pkg");

if (!existsSync(join(pkgDir, "package.json"))) {
  console.error("pkg/ not found — run scripts/build-npm.mjs first");
  process.exit(1);
}

const stage = mkdtempSync(join(tmpdir(), "rvm-context-smoke-"));
process.on("exit", () => rmSync(stage, { recursive: true, force: true }));

console.log("packing and installing the built package...");
execFileSync("npm", ["pack", "--pack-destination", stage, "--silent"], {
  cwd: pkgDir,
  stdio: "inherit",
});
const tarball = readdirSync(stage).find((file) => file.endsWith(".tgz"));
assert.ok(tarball, "npm pack produced a tarball");

writeFileSync(
  join(stage, "package.json"),
  JSON.stringify({ name: "smoke-host", version: "1.0.0", private: true }) + "\n"
);
execFileSync(
  "npm",
  ["install", join(stage, tarball), "--no-audit", "--no-fund", "--silent"],
  { cwd: stage, stdio: "inherit" }
);

const require = createRequire(join(stage, "index.js"));
const rvm = require("@ruvnet/rvm-context-wasm");
const {
  RuvUri,
  RuvUriBuilder,
  ViewMask,
  ContextScope,
  ContextRuntime,
  EpochCommitments,
  Rights,
  ruvUriError,
  isRuvUri,
  contractVersion,
} = rvm;

let passed = 0;
const failures = [];

function test(name, body) {
  try {
    body();
    passed += 1;
    console.log(`  ok  ${name}`);
  } catch (error) {
    failures.push({ name, error });
    console.log(`  FAIL ${name}\n       ${error.message}`);
  }
}

const BASE = "ruv://context.example/acme/agent/researcher/memory";
const ZERO_REV = `sha256:${"0".repeat(64)}`;

console.log("\nrunning smoke tests against the installed package");

test("a canonical URI parses into the right components", () => {
  const uri = RuvUri.parse(`${BASE}/projects/atlas`);
  assert.equal(uri.authority, "context.example");
  assert.equal(uri.tenant, "acme");
  assert.equal(uri.subjectKind, "agent");
  assert.equal(uri.subjectId, "researcher");
  assert.equal(uri.collection, "memory");
  assert.deepEqual(uri.path, ["projects", "atlas"]);
  assert.equal(uri.revision, undefined);
  assert.equal(uri.view, undefined);
  assert.equal(uri.isPinned, false);
});

test("a pinned URI exposes its revision and view", () => {
  const uri = RuvUri.parse(`${BASE}?rev=${ZERO_REV}&view=overview`);
  assert.equal(uri.revision, ZERO_REV);
  assert.equal(uri.view, "overview");
  assert.equal(uri.isPinned, true);
});

test("path segments keep their case", () => {
  const uri = RuvUri.parse("ruv://context.example/acme/team/core/resources/Specs/API_v1");
  assert.deepEqual(uri.path, ["Specs", "API_v1"]);
});

// Each rejection class, using the real cases.
const rejections = [
  ["uppercase tenant", "ruv://context.example/ACME/agent/researcher/memory", "InvalidTenant"],
  ["trailing slash", `${BASE}/`, "TrailingSlash"],
  ["dot-dot segment", `${BASE}/../secrets`, "DotSegment"],
  ["empty segment", "ruv://context.example/acme/agent/researcher//memory", "EmptyPathSegment"],
  ["percent encoding", `${BASE}/a%2Fb`, "PercentEncodingNotAllowed"],
  ["fragment", `${BASE}#section`, "FragmentNotAllowed"],
  [
    "credentials in authority",
    "ruv://user:pw@context.example/acme/agent/researcher/memory",
    "CredentialsNotAllowed",
  ],
  ["port in authority", "ruv://context.example:8443/acme/agent/researcher/memory", "PortNotAllowed"],
];

for (const [label, input, expectedCode] of rejections) {
  test(`rejects ${label} with code ${expectedCode}`, () => {
    assert.throws(
      () => RuvUri.parse(input),
      (error) => {
        assert.ok(error instanceof Error, "throws a real Error");
        assert.equal(error.name, "RuvUriError");
        assert.equal(error.code, expectedCode);
        assert.ok(error.message.length > 0, "carries a message");
        return true;
      },
      `${input} should have been rejected`
    );
    assert.equal(ruvUriError(input), expectedCode, "non-throwing probe agrees");
    assert.equal(isRuvUri(input), false);
  });
}

test("round trip: parse then format is byte identical", () => {
  const cases = [
    BASE,
    `${BASE}/projects/atlas`,
    "ruv://context.example/acme/user/alice/skills/deploy",
    "ruv://a.b.c/t/service/api/resources/A/b-c/d.e/f_g/h~i",
    `${BASE}?rev=${ZERO_REV}`,
    `${BASE}?view=content`,
    `${BASE}?rev=${ZERO_REV}&view=abstract`,
  ];
  for (const text of cases) {
    const once = RuvUri.parse(text).toString();
    assert.equal(once, text, `round trip changed ${text}`);
    assert.equal(RuvUri.parse(once).toString(), once, "second round trip is stable");
  }
});

test("valid URIs report no error", () => {
  assert.equal(ruvUriError(BASE), undefined);
  assert.equal(isRuvUri(BASE), true);
});

test("the builder produces the canonical spelling", () => {
  const uri = new RuvUriBuilder("context.example", "acme", "team", "core", "resources")
    .segment("Specs")
    .segment("API_v1")
    .revision(ZERO_REV)
    .view("overview")
    .build();
  assert.equal(
    uri.toString(),
    `ruv://context.example/acme/team/core/resources/Specs/API_v1?rev=${ZERO_REV}&view=overview`
  );
});

test("the builder names the component that failed", () => {
  assert.throws(
    () => new RuvUriBuilder("context.example", "ACME", "agent", "a", "memory"),
    (error) => error.code === "InvalidTenant"
  );
  assert.throws(
    () => new RuvUriBuilder("context.example", "acme", "robot", "a", "memory"),
    (error) => error.code === "InvalidSubjectKind"
  );
  assert.throws(
    () => new RuvUriBuilder("context.example", "acme", "agent", "a", "memory").segment(".."),
    (error) => error.code === "DotSegment"
  );
});

test("a builder value is reusable across branches", () => {
  const base = new RuvUriBuilder("context.example", "acme", "agent", "researcher", "memory");
  assert.equal(base.segment("alpha").build().toString(), `${BASE}/alpha`);
  assert.equal(base.segment("beta").build().toString(), `${BASE}/beta`);
});

test("withRevision and withView extend a parsed URI", () => {
  const uri = RuvUri.parse(BASE);
  const pinned = uri.withRevision(ZERO_REV);
  assert.equal(pinned.toString(), `${BASE}?rev=${ZERO_REV}`);
  assert.equal(pinned.withView("content").toString(), `${BASE}?rev=${ZERO_REV}&view=content`);
  assert.equal(uri.isPinned, false, "the original is unchanged");
});

test("equals compares structurally", () => {
  assert.equal(RuvUri.parse(BASE).equals(RuvUri.parse(BASE)), true);
  assert.equal(RuvUri.parse(BASE).equals(RuvUri.parse(`${BASE}/x`)), false);
});

test("view masks compose", () => {
  const all = ViewMask.all();
  const content = ViewMask.view("content");
  assert.equal(all.contains(content), true);
  assert.equal(content.contains(all), false);
  assert.equal(all.allows("abstract"), true);
  assert.equal(content.allows("abstract"), false);
  assert.equal(ViewMask.fromBits(all.bits).bits, all.bits);
  assert.throws(() => ViewMask.fromBits(0), (error) => error.code === "InvalidViewMask");
  assert.throws(() => ViewMask.fromBits(0x10), (error) => error.code === "InvalidViewMask");
});

test("scope containment follows the path prefix", () => {
  const parent = ContextScope.fromUri(RuvUri.parse(`${BASE}/projects`), ViewMask.all());
  const child = ContextScope.fromUri(RuvUri.parse(`${BASE}/projects/atlas`), ViewMask.all());
  const other = ContextScope.fromUri(RuvUri.parse(`${BASE}/archive`), ViewMask.all());
  assert.equal(parent.containsScope(child), true);
  assert.equal(child.containsScope(parent), false);
  assert.equal(parent.containsScope(other), false);
  assert.deepEqual(parent.pathPrefix, ["projects"]);
  assert.equal(parent.subjectKind, "agent");
});

test("the contract version is exposed", () => {
  assert.equal(contractVersion(), 1);
});

test("TypeScript declarations and the web build ship with the package", () => {
  // The exports map deliberately does not expose arbitrary subpaths, so locate
  // the install through its package.json rather than resolving files directly.
  const installed = dirname(require.resolve("@ruvnet/rvm-context-wasm/package.json"));
  const manifest = require("@ruvnet/rvm-context-wasm/package.json");

  assert.equal(manifest.name, "@ruvnet/rvm-context-wasm");
  assert.equal(manifest.license, "MIT OR Apache-2.0");
  assert.ok(existsSync(join(installed, manifest.types)), "the .d.ts is installed");
  assert.ok(existsSync(join(installed, manifest.main)), "the entry point is installed");
  assert.ok(
    existsSync(join(installed, "rvm_context_wasm_bg.wasm")),
    "the wasm binary is installed"
  );
  assert.ok(
    existsSync(join(installed, "web", "rvm_context_wasm.js")),
    "the web build is installed"
  );
  assert.ok(existsSync(join(installed, "README.md")), "the README is installed");
});

// ---------------------------------------------------------------------------
// Governed runtime, as a consumer would drive it.
// ---------------------------------------------------------------------------

function rootedRuntime(scopeUri, operations) {
  const runtime = new ContextRuntime(7);
  const scope = ContextScope.fromUri(RuvUri.parse(scopeUri), ViewMask.all());
  const handle = runtime.issueRoot(scope, Rights.forOperations(operations), 7);
  return { runtime, handle };
}

test("the runtime provisions a root capability and reports its actor", () => {
  const { runtime, handle } = rootedRuntime(BASE, ["resolve", "read"]);
  assert.equal(runtime.actor, 7);
  assert.ok(Number.isInteger(handle.index));
  // Published as a static readonly Uint32Array of the compiled-in slot counts.
  assert.deepEqual(Array.from(ContextRuntime.capacities), [64, 64, 1024, 64, 64]);
});

test("a cross-tenant reach is refused", () => {
  const { runtime, handle } = rootedRuntime(BASE, ["resolve", "read"]);
  const other = RuvUri.parse("ruv://context.example/other/agent/researcher/memory");
  assert.throws(
    () => runtime.resolve(handle, other),
    (error) => {
      assert.equal(error.name, "ContextError");
      assert.equal(error.code, "AccessDenied");
      return true;
    }
  );
});

test("a reach diverging at the LAST prefix segment is refused", () => {
  // The violating segment is deliberately last: a containment check inside a
  // short-circuiting loop would pass position 1 and still be wrong here.
  const { runtime, handle } = rootedRuntime(`${BASE}/a/b/c`, ["resolve"]);
  for (const bad of [`${BASE}/a/b/X`, `${BASE}/a/X/c`, `${BASE}/X/b/c`, `${BASE}/a/b`]) {
    assert.throws(
      () => runtime.resolve(handle, RuvUri.parse(bad)),
      (error) => error.code === "AccessDenied",
      `${bad} should have been refused`
    );
  }
});

test("scope containment answers the shadow-mode question with no capability", () => {
  const scope = ContextScope.fromUri(RuvUri.parse(`${BASE}/a/b/c`), ViewMask.all());
  assert.equal(scope.containsUri(RuvUri.parse(`${BASE}/a/b/c/d`)), true);
  assert.equal(scope.containsUri(RuvUri.parse(`${BASE}/a/b/X`)), false);
  assert.equal(
    scope.containsUri(RuvUri.parse("ruv://context.example/other/agent/researcher/memory/a/b/c")),
    false
  );
});

test("rights are enforced per operation", () => {
  const { runtime, handle } = rootedRuntime(BASE, ["resolve"]);
  const pinned = RuvUri.parse(`${BASE}?rev=${ZERO_REV}`);
  assert.throws(
    () => runtime.put(handle, pinned, new Uint8Array(8)),
    (error) => error.code === "AccessDenied"
  );
});

test("delegation cannot widen the parent scope", () => {
  const { runtime, handle } = rootedRuntime(`${BASE}/a/b`, ["resolve", "grant"]);
  const wider = ContextScope.fromUri(RuvUri.parse(`${BASE}/a`), ViewMask.all());
  assert.throws(
    () => runtime.delegate(handle, wider, Rights.forOperation("resolve"), 7),
    (error) => error.code === "ScopeEscalation"
  );
  const narrower = ContextScope.fromUri(RuvUri.parse(`${BASE}/a/b/c`), ViewMask.all());
  const child = runtime.delegate(handle, narrower, Rights.forOperation("resolve"), 7);
  assert.ok(Number.isInteger(child.index));
});

test("a revoked handle stops working", () => {
  const { runtime, handle } = rootedRuntime(BASE, ["resolve"]);
  assert.ok(runtime.revoke(handle) >= 1);
  assert.throws(
    () => runtime.resolve(handle, RuvUri.parse(BASE)),
    (error) => error.code === "AccessDenied"
  );
});

test("decisions advance the witness log and the chain verifies", () => {
  const { runtime, handle } = rootedRuntime(BASE, ["resolve", "read"]);
  const before = runtime.witnessSequence;
  try {
    runtime.resolve(handle, RuvUri.parse("ruv://context.example/other/agent/researcher/memory"));
  } catch {
    // refused on purpose; the witness record is the point
  }
  const after = runtime.witnessSequence;
  assert.ok(after > before, `witness sequence did not advance: ${before} -> ${after}`);
  assert.equal(runtime.verifyWitnessChain(), Number(after));
  assert.equal(runtime.witnessDigests().length, runtime.witnessRecordCount * 32);
});

test("the logical clock makes sessions byte-reproducible", () => {
  const run = () => {
    const { runtime, handle } = rootedRuntime(BASE, ["resolve"]);
    try {
      runtime.resolve(handle, RuvUri.parse("ruv://context.example/other/agent/researcher/memory"));
    } catch {
      // refused on purpose
    }
    return Buffer.from(runtime.witnessDigests()).toString("hex");
  };
  const first = run();
  assert.equal(first, run(), "identical sessions produced different witness digests");
  assert.ok(first.length > 0, "the session recorded nothing");
});

test("receipt sealing requires a host-supplied 32-byte key", () => {
  const { runtime, handle } = rootedRuntime(BASE, ["resolve", "sealReceipt"]);
  const target = RuvUri.parse(BASE);
  const roots = new Uint8Array(32);
  const commitments = new EpochCommitments(roots, roots, roots, roots);
  assert.throws(
    () => runtime.sealEpoch(handle, target, new Uint8Array(8), commitments),
    (error) => error.code === "InvalidKeyLength"
  );
  assert.throws(
    () => new EpochCommitments(roots, new Uint8Array(31), roots, roots),
    (error) => error.code === "InvalidDigestLength"
  );
});

test("rights map to the operations that need them", () => {
  assert.equal(Rights.forOperation("read").bits, 0x01);
  assert.equal(Rights.forOperation("put").bits, 0x02);
  assert.equal(Rights.forOperation("execute").bits, 0x10);
  assert.deepEqual(Rights.fromNames(["read", "prove"]).names, ["read", "prove"]);
  assert.throws(
    () => Rights.fromNames(["admin"]),
    (error) => error.code === "UnknownRight"
  );
});

test("an out-of-range partition id is refused", () => {
  assert.throws(
    () => new ContextRuntime(4096),
    (error) => error.code === "InvalidPartitionId"
  );
});

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  process.exitCode = 1;
}
