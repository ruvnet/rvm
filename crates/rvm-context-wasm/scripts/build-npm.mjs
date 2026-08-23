#!/usr/bin/env node
// Builds the @ruvnet/rvm-context-wasm npm package from the rvm-context-wasm crate.
//
// wasm-pack derives the npm package name from the crate name, so this script
// runs both target builds and then rewrites the generated manifest into the
// scoped package with its CommonJS (Node) and ESM (web) entry points.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const crateDir = dirname(dirname(fileURLToPath(import.meta.url)));
const pkgDir = join(crateDir, "pkg");
const webStageDir = join(crateDir, "pkg-web");
const webDir = join(pkgDir, "web");

const PACKAGE_NAME = "@ruvnet/rvm-context-wasm";
const ENTRY = "rvm_context_wasm";

function wasmPack(target, outDir) {
  console.log(`building ${target} -> ${outDir}`);
  execFileSync(
    "wasm-pack",
    ["build", crateDir, "--release", "--target", target, "--out-dir", outDir, "--out-name", ENTRY],
    { stdio: "inherit" }
  );
}

rmSync(pkgDir, { recursive: true, force: true });
rmSync(webStageDir, { recursive: true, force: true });

// The nodejs build is the package root; the web build lands under ./web.
wasmPack("nodejs", pkgDir);
wasmPack("web", webStageDir);
renameSync(webStageDir, webDir);

// wasm-pack drops a .gitignore that would exclude the whole package from npm
// tooling that respects it; the repo ignores pkg/ centrally instead.
for (const stray of [join(pkgDir, ".gitignore"), join(webDir, ".gitignore")]) {
  rmSync(stray, { force: true });
}

const manifestPath = join(pkgDir, "package.json");
const generated = JSON.parse(readFileSync(manifestPath, "utf8"));
const webManifest = JSON.parse(readFileSync(join(webDir, "package.json"), "utf8"));

const files = [
  ...new Set([
    ...(generated.files ?? []),
    ...(webManifest.files ?? []).map((file) => `web/${file}`),
    "web/package.json",
  ]),
].sort();

const manifest = {
  name: PACKAGE_NAME,
  version: generated.version,
  description:
    "The RVM ruv:// context namespace compiled to WebAssembly: canonical URI parsing, scope arithmetic, a self-contained governed runtime, and witness verification",
  license: generated.license,
  repository: { type: "git", url: "git+https://github.com/ruvnet/rvm.git" },
  homepage: "https://ruvnet.github.io/rvm/ruv-context/",
  bugs: { url: "https://github.com/ruvnet/rvm/issues" },
  keywords: ["ruv", "rvm", "uri", "context", "wasm", "webassembly", "namespace"],
  main: `${ENTRY}.js`,
  types: `${ENTRY}.d.ts`,
  exports: {
    ".": {
      types: `./${ENTRY}.d.ts`,
      default: `./${ENTRY}.js`,
    },
    "./web": {
      types: `./web/${ENTRY}.d.ts`,
      default: `./web/${ENTRY}.js`,
    },
    "./package.json": "./package.json",
  },
  files,
  sideEffects: generated.sideEffects ?? false,
};

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

// The nested manifest would otherwise advertise the unscoped crate name.
writeFileSync(
  join(webDir, "package.json"),
  `${JSON.stringify({ type: "module", sideEffects: webManifest.sideEffects ?? false }, null, 2)}\n`
);

for (const required of [`${ENTRY}.js`, `${ENTRY}.d.ts`, `${ENTRY}_bg.wasm`]) {
  if (!existsSync(join(pkgDir, required))) {
    throw new Error(`expected ${required} in the built package`);
  }
}

console.log(`\n${PACKAGE_NAME}@${manifest.version} built at ${pkgDir}`);
