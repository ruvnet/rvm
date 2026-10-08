# ADR-159: Semantic host policy and Strands interoperability

Status: Implemented opt-in broker and integration guide; platform containment validation pending
Date: 2026-10-08

## Problem

RVF verification establishes artifact integrity. RVM capabilities establish
execution authority. Neither by itself expresses rich predicates over shell,
Python, MCP, filesystem and network effects. A host capability declaration must
not be confused with applying OS confinement.

## Decision

Add `rvm_host::semantic` without changing the existing runtime selection ladder
or automatically enabling a new execution route. The host supplies structured,
resolved actions, trusted identity/time, live revocation-aware authority, a
policy engine, durable evidence storage and a private executor. The broker
orders authority, policy reservation, receipt persistence, then dispatch. An
explicit forbid dominates permits. Missing policy, revoked authority, clock
regression and audit failure deny execution. Full receipts bind the artifact,
instance, action and policy identity. They are evidence for a host sink, not
already signed RVF WITNESS segments.

Provide exact-action reference rules, a bounded sliding-window attempt quota,
and content-revision-bound test prerequisites. Policy identity must cover all
rules and quota configuration. A trusted executor records test success only
from observed completion; content changes invalidate it by changing revision.
The quota charges attempts, not API cost. Monetary limits need authoritative
pricing and transactional reservations in a host policy engine.

The native reference policies are in-memory. They do not claim Dogwood language
compatibility or durable quotas. Shared budgets across workers require shared
transactional state; restarts must not reset a still-live budget window.

## Strands support

The vendor guide supplies reusable Python Strands tools for the existing RVM
HTTPS context gateway: search, read and verify. Credentials stay in host client
configuration, redirects are refused, certificate validation stays enabled,
and writes are absent. Server-side capability scope remains authoritative.
This is tool/context interoperability, not a Strands session manager.

An optional `run_box.py` launcher invokes the operator-installed Strands Box
with its documented argv. It pins binary, configuration and policy SHA-256,
requires an explicit agent command, and refuses unsupported operating systems.
The supported upstream release documents macOS Seatbelt. There is no silent
fallback, automatic download, or claim of RVM hardware isolation. It does not
launch verified RVF executables or automatically wire the Rust broker into
Box's Dogwood engine. Keep all trusted inputs and parent directories outside
agent write grants; hashing does not prevent concurrent filesystem replacement.
Box remains responsible for interpreting configuration and applying confinement.

## Inspiration and provenance

Architecture concepts: separate containment from semantic policy; mediate at
protocol/language boundaries; default deny; temporal prerequisites; quota
reservation; private durable history; honest isolation claims.

Sources inspected on 2026-10-08:

* https://strandsagents.com/blog/strands-box-the-big-picture/
* https://strandsagents.com/docs/user-guide/box/
* https://github.com/strands-agents/box at `2c874eaf412cff6e73a2182da74cc31e95fb554f`
* https://strandsagents.com/docs/integrations/get-featured/

Box's repository LICENSE is Apache-2.0. No Box or Dogwood implementation source
was copied or vendored. RVM additions use the repository's existing license.

## Acceptance and boundaries

Rust tests must prove that every denial path invokes zero downstream effects,
that the 61st attempt is refused for a 60-attempt window, that changing revision
invalidates a test prerequisite, and that audit failure cannot execute.
Python tests use the actual Strands SDK decorator and a local TLS contract
server; they validate requests, credentials, redirects and registration.
They do not establish the deployed RVM server's security or macOS containment.
Before production containment claims, run Box on macOS and adversarially attempt
raw process/network/file escape, MCP bypass and access to policy/private state.
Record exact binary hashes and observed outcomes. For multiple tenants, use an
independent per-session VM boundary as upstream recommends.
