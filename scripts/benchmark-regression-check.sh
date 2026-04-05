#!/usr/bin/env bash
# benchmark-regression-check.sh — Compare benchmark results against baseline
#
# Usage: ./scripts/benchmark-regression-check.sh <criterion-target-dir>
# Exit codes:
#   0 — No regressions (all within 5% tolerance)
#   1 — Regression detected (>5% slower than baseline)
#   2 — Error or missing data
#
# State: scripts/benchmark-baseline.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_FILE="${SCRIPT_DIR}/benchmark-baseline.json"
REPORT_FILE="${SCRIPT_DIR}/benchmark-report.json"
CRITERION_DIR="${1:-target/criterion}"
THRESHOLD_PERCENT=5

# Extract benchmark estimates from Criterion output
extract_benchmarks() {
    local dir="$1"
    echo "{"

    local first=true
    for est_file in "${dir}"/*/new/estimates.json; do
        [[ -f "${est_file}" ]] || continue
        local bench_name
        bench_name=$(basename "$(dirname "$(dirname "${est_file}")")")

        # Extract point_estimate from slope (or mean if no slope)
        local estimate
        estimate=$(grep -o '"point_estimate":[0-9.e+-]*' "${est_file}" | head -1 | cut -d: -f2)
        [[ -z "${estimate}" ]] && continue

        if [[ "${first}" != "true" ]]; then echo ","; fi
        first=false
        printf '  "%s": {"point_estimate": %s}' "${bench_name}" "${estimate}"
    done

    echo ""
    echo "}"
}

# Compare two benchmark files
compare_benchmarks() {
    local baseline="$1"
    local current="$2"

    python3 -c "
import json, sys

baseline = json.load(open('${baseline}'))
current = json.load(open('${current}'))
threshold = ${THRESHOLD_PERCENT}
regressions = []
results = {}

for name, curr_data in current.items():
    curr_val = curr_data['point_estimate']
    if name in baseline:
        base_val = baseline[name]['point_estimate']
        if base_val > 0:
            change_pct = ((curr_val - base_val) / base_val) * 100
        else:
            change_pct = 0
        status = 'REGRESSION' if change_pct > threshold else 'OK'
        if status == 'REGRESSION':
            regressions.append(name)
        results[name] = {
            'baseline_ns': base_val,
            'current_ns': curr_val,
            'change_pct': round(change_pct, 2),
            'status': status
        }
    else:
        results[name] = {
            'baseline_ns': None,
            'current_ns': curr_val,
            'change_pct': 0,
            'status': 'NEW'
        }

# Print report
for name, r in sorted(results.items()):
    sym = 'PASS' if r['status'] in ('OK', 'NEW') else 'FAIL'
    print(f\"[{sym}] {name}: {r['change_pct']:+.1f}% ({r['status']})\")

if regressions:
    print(f\"\nFATAL: {len(regressions)} benchmark(s) regressed by >{threshold}%:\")
    for r in regressions:
        print(f'  - {r}')
    sys.exit(1)
else:
    print(f\"\nAll benchmarks within {threshold}% tolerance.\")
    sys.exit(0)
" 2>&1
}

main() {
    echo "=== Benchmark Regression Check ==="
    echo "Threshold: ${THRESHOLD_PERCENT}%"
    echo ""

    # Extract current benchmarks
    if [[ ! -d "${CRITERION_DIR}" ]]; then
        echo "ERROR: Criterion output directory not found: ${CRITERION_DIR}" >&2
        exit 2
    fi

    echo "Extracting current benchmark results..."
    extract_benchmarks "${CRITERION_DIR}" > "${REPORT_FILE}"

    # Check if baseline exists
    if [[ ! -f "${BASELINE_FILE}" ]]; then
        echo "No baseline found. Creating initial baseline."
        cp "${REPORT_FILE}" "${BASELINE_FILE}"
        echo "Baseline created. All benchmarks pass (first run)."
        exit 0
    fi

    # Compare
    echo "Comparing against baseline..."
    echo ""
    compare_benchmarks "${BASELINE_FILE}" "${REPORT_FILE}"
}

main "$@"
