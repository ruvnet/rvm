#!/usr/bin/env bash
# analyze-discoveries.sh — Use Claude API (Sonnet 4.6) to analyze changes
#                          between Claude Code versions via rudevolution data
#
# Usage: ./scripts/analyze-discoveries.sh <new-version> <previous-version>
# Requires: ANTHROPIC_API_KEY environment variable
#
# Outputs: Markdown-formatted analysis of new discoveries and major changes

set -euo pipefail

NEW_VERSION="${1:-unknown}"
PREV_VERSION="${2:-unknown}"

# Check for API key
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "No ANTHROPIC_API_KEY set. Skipping AI analysis."
    exit 0
fi

# Gather available rudevolution data
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
RUDEV_DIR="${REPO_ROOT}/rudevolution"

# Collect version data if available
CONTEXT=""
if [[ -d "${RUDEV_DIR}/dashboard/public/data" ]]; then
    # Find the most recent decompilation data
    for dir in "${RUDEV_DIR}/dashboard/public/data/v"*; do
        if [[ -d "${dir}" ]]; then
            MANIFEST="${dir}/manifest.json"
            if [[ -f "${MANIFEST}" ]]; then
                CONTEXT="${CONTEXT}

=== Version data from $(basename "${dir}") ===
$(head -100 "${MANIFEST}" 2>/dev/null || echo "No manifest")"
            fi
        fi
    done
fi

# Collect pattern data
PATTERNS_FILE="${RUDEV_DIR}/data/claude-code-patterns.json"
if [[ -f "${PATTERNS_FILE}" ]]; then
    PATTERN_COUNT=$(grep -c '"pattern"' "${PATTERNS_FILE}" 2>/dev/null || echo "unknown")
    CONTEXT="${CONTEXT}

=== Pattern corpus ===
Total patterns: ${PATTERN_COUNT}"
fi

# Check for research docs
RESEARCH_DIR="${RUDEV_DIR}/docs/research/claude-code-rvsource"
if [[ -d "${RESEARCH_DIR}" ]]; then
    # Get latest research index
    INDEX_FILE="${RESEARCH_DIR}/00-index.md"
    if [[ -f "${INDEX_FILE}" ]]; then
        CONTEXT="${CONTEXT}

=== Research index (latest analysis) ===
$(head -80 "${INDEX_FILE}" 2>/dev/null || echo "No index")"
    fi
fi

# Check npm for current package info
NPM_INFO=$(curl -sf --max-time 10 "https://registry.npmjs.org/@anthropic-ai/claude-code/${NEW_VERSION}" 2>/dev/null | head -c 2000 || echo "{}")

# Build the prompt
PROMPT="You are analyzing changes between Claude Code v${PREV_VERSION} and v${NEW_VERSION}.

Based on the following data from the rudevolution decompiler project, identify:

1. **New Features & Capabilities** — What's new in v${NEW_VERSION} that wasn't in v${PREV_VERSION}?
2. **Breaking Changes** — Any API changes, removed features, or behavioral differences?
3. **Security-Relevant Changes** — New permissions, authentication, or trust model updates?
4. **Architecture Changes** — New modules, refactored systems, or structural shifts?
5. **Impact on RVM** — How might these changes affect RVM's integration?

Keep your response under 2000 characters. Use bullet points. Be specific about what changed.

Available data:

npm package info for v${NEW_VERSION}:
${NPM_INFO:0:1500}

rudevolution analysis data:
${CONTEXT:0:3000}"

# Call Claude API (Sonnet 4.6)
RESPONSE=$(curl -sf --max-time 60 \
    -H "x-api-key: ${ANTHROPIC_API_KEY}" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    "https://api.anthropic.com/v1/messages" \
    -d "{
        \"model\": \"claude-sonnet-4-6-20250514\",
        \"max_tokens\": 1024,
        \"messages\": [{
            \"role\": \"user\",
            \"content\": $(echo "${PROMPT}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
        }]
    }" 2>/dev/null) || {
    echo "Claude API call failed. Continuing without AI analysis."
    exit 0
}

# Extract text from response
ANALYSIS=$(echo "${RESPONSE}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for block in data.get('content', []):
        if block.get('type') == 'text':
            print(block['text'])
except Exception as e:
    print(f'Failed to parse API response: {e}')
" 2>/dev/null) || {
    echo "Failed to parse Claude API response."
    exit 0
}

echo "${ANALYSIS}"
