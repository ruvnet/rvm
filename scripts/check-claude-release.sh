#!/usr/bin/env bash
# check-claude-release.sh — Detect new Claude Code releases from npm registry
#
# Usage: ./scripts/check-claude-release.sh
# Exit codes:
#   0 — New version detected (version written to stdout)
#   1 — No new version (up to date)
#   2 — Error (network, parse, etc.)
#
# State file: scripts/last-known-claude-version.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/last-known-claude-version.txt"
PACKAGE="@anthropic-ai/claude-code"

# Fetch latest version from npm registry
fetch_latest_version() {
    local response
    response=$(curl -sf --max-time 15 "https://registry.npmjs.org/${PACKAGE}/latest" 2>/dev/null) || {
        echo "ERROR: Failed to fetch from npm registry" >&2
        return 1
    }

    # Extract version field — pure bash, no jq dependency
    local version
    version=$(echo "${response}" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [[ -z "${version}" ]]; then
        echo "ERROR: Could not parse version from registry response" >&2
        return 1
    fi

    echo "${version}"
}

# Read last known version from state file
read_last_known() {
    if [[ -f "${STATE_FILE}" ]]; then
        cat "${STATE_FILE}" | tr -d '[:space:]'
    else
        echo "none"
    fi
}

# Main
main() {
    local latest last_known

    latest=$(fetch_latest_version) || exit 2
    last_known=$(read_last_known)

    if [[ "${latest}" == "${last_known}" ]]; then
        echo "Up to date: ${latest}" >&2
        exit 1
    fi

    echo "New version detected: ${latest} (was: ${last_known})" >&2
    echo "${latest}"
    exit 0
}

main "$@"
