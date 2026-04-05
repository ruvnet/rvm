# ADR-143: Nightly Verified Release Pipeline

**Status:** Accepted
**Date:** 2026-04-05
**Authors:** RuVector Contributors
**Supersedes:** None

## Context

RVM integrates with the Claude Code ecosystem via the rudevolution submodule,
which tracks Claude Code CLI releases by decompiling and analyzing each version.
When Anthropic publishes a new Claude Code release, RVM must:

1. Detect the new release automatically
2. Verify RVM still passes all tests and benchmarks (no regressions)
3. Publish a verified nightly release with detailed notes
4. Never publish a broken release

Currently, releases are manual. There is no automated pipeline to detect
upstream changes, validate compatibility, or publish verified builds.

## Decision

Implement a **nightly verified release pipeline** using GitHub Actions that:

### Detection Phase
- Runs nightly at 03:00 UTC via cron schedule
- Queries npm registry for `@anthropic-ai/claude-code` latest version
- Compares against last known version stored in `scripts/last-known-claude-version.txt`
- Exits early (no-op) if no new version is detected
- Can also be triggered manually via `workflow_dispatch`

### Verification Phase (Gate: ALL must pass)
- **Unit Tests:** `cargo test --workspace --lib` (797+ tests, 0 failures required)
- **Integration Tests:** `cargo test -p rvm-tests` (cross-crate scenarios)
- **Clippy:** `cargo clippy --workspace -- -D warnings` (0 warnings)
- **Bare-Metal Build:** `cargo check --target aarch64-unknown-none -p rvm-hal --no-default-features`
- **Benchmarks:** `cargo bench -p rvm-benches` with regression detection
  - Parse Criterion JSON output
  - Flag if any benchmark regresses by >5% vs. baseline
  - Store baseline in `scripts/benchmark-baseline.json`
- **Security Audit:** `cargo audit` for known vulnerabilities
- **rudevolution Submodule:** Update to latest, verify it builds

### Benchmark Regression Detection
- After benchmarks complete, compare against stored baseline
- If ANY benchmark regresses >5% from baseline, the pipeline FAILS
- Baselines are updated only on successful releases
- Regression report is included in release notes if within tolerance

### Release Phase (only if verification passes)
- Bump patch version in workspace Cargo.toml
- Tag with `vX.Y.Z-nightly.YYYYMMDD`
- Generate detailed release notes including:
  - Claude Code version that triggered the release
  - Full test results (pass counts per crate)
  - Benchmark results vs. baseline (with delta percentages)
  - rudevolution analysis highlights (new features/changes detected)
  - Security audit status
- Publish GitHub release with artifacts:
  - Test report (JSON)
  - Benchmark report (JSON + HTML)
  - Changelog

### AI-Assisted Analysis (Optional, Sonnet 4.6)
- When a new Claude Code version is detected, use Claude API (Sonnet 4.6)
  to analyze the diff between versions via rudevolution
- Generate human-readable summary of what changed
- Include in release notes under "Upstream Changes" section
- Requires `ANTHROPIC_API_KEY` secret in GitHub Actions

### Security Constraints
- **No secrets in logs:** All API keys and tokens are GitHub Secrets
- **No force pushes:** Pipeline creates new commits, never amends
- **Audit gate:** `cargo audit` must pass (no known CVEs in deps)
- **Pinned actions:** All GitHub Actions use SHA-pinned versions
- **Read-only by default:** Only the release step gets write permissions
- **Submodule integrity:** rudevolution is pinned to a specific commit,
  updated only when verification passes

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Nightly Cron (03:00 UTC)               │
└──────────────────────────┬──────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │ Check npm   │
                    │ registry    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐  No new version
                    │ New version?├──────────────────► Exit (no-op)
                    └──────┬──────┘
                           │ Yes
                    ┌──────▼──────┐
                    │ Update      │
                    │ submodule   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼───┐ ┌──────▼──────┐
       │ cargo test   │ │clippy│ │ cargo audit │
       │ (797+ tests) │ │      │ │             │
       └──────┬──────┘ └──┬───┘ └──────┬──────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼──────┐
                    │ cargo bench │
                    │ + regression│
                    │   check     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Bare-metal  │
                    │ build check │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐  ANY failure
                    │ All passed? ├──────────────────► Fail + Alert
                    └──────┬──────┘
                           │ Yes
                    ┌──────▼──────┐
                    │ AI Analysis │ (optional, Sonnet 4.6)
                    │ via Claude  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Tag + Build │
                    │ + Release   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Publish     │
                    │ GitHub      │
                    │ Release     │
                    └─────────────┘
```

## Failure Modes

| Failure | Behavior | Recovery |
|---------|----------|---------|
| npm registry unreachable | Skip nightly, retry next day | Automatic |
| Test failure | Block release, open issue | Manual fix required |
| Benchmark regression >5% | Block release, report regression | Investigate + update baseline |
| `cargo audit` finds CVE | Block release, open issue | Update dep or add ignore |
| Submodule update fails | Block release, use previous pin | Manual intervention |
| Claude API unavailable | Release without AI analysis | Automatic fallback |
| GitHub API rate limit | Retry with backoff | Automatic |

## Consequences

### Positive
- Every published release is verified (797+ tests, benchmarks, security)
- Upstream Claude Code changes are detected within 24 hours
- Benchmark regressions are caught before release
- Detailed release notes provide full audit trail
- AI-assisted analysis surfaces meaningful changes

### Negative
- GitHub Actions minutes consumed nightly (~10-15 min per run)
- Anthropic API costs for Sonnet 4.6 analysis (~$0.01-0.05 per run)
- Benchmark flakiness could cause false-positive failures (mitigated by 5% threshold)

### Neutral
- Nightly tag format (`vX.Y.Z-nightly.YYYYMMDD`) distinguishes from stable releases
- Submodule pin requires explicit update (intentional friction for safety)

## Implementation

- **Workflow:** `.github/workflows/nightly.yml`
- **Scripts:** `scripts/check-claude-release.sh`, `scripts/generate-release-notes.sh`
- **State:** `scripts/last-known-claude-version.txt`, `scripts/benchmark-baseline.json`
- **Secrets:** `ANTHROPIC_API_KEY` (optional), `GITHUB_TOKEN` (automatic)

## References

- ADR-132: RVM top-level architecture
- ADR-135: Three-tier proof system
- ADR-142: TEE-backed cryptographic verification
- rudevolution: https://github.com/ruvnet/rudevolution
