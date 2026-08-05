#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
adr="$repo_root/docs/adr/ADR-155-rvf-execution-contract.md"
matrix="$repo_root/docs/rvforge-compatibility-matrix.json"

test -f "$adr"
test -f "$matrix"
jq -e '
  .schemaVersion == 1 and
  .runtimeProfiles["os-isolation+wasm"].status == "planned" and
  .runtimeProfiles["rvm-native"].status == "planned" and
  .rvm.rvmVersionMin == null
' "$matrix" >/dev/null

for criterion in 1 2 3 4 5 6 7 8; do
  grep -Eq "^\\| ${criterion} \\|" "$adr"
done

grep -Fq 'Current implementation status' "$adr"
grep -Fq 'ruvnet/rvm/issues/24' "$adr"
grep -Fq 'ruvnet/rvm/issues/25' "$adr"
