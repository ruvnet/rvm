# RVM and RVF with Strands Agents

Use Strands Agents with RVM's capability-governed context service to search,
read and verify portable RVF memory. RVM enforces context authority; Strands
provides the agent loop. Optional Strands Box adds its own OS containment and
Dogwood action policy on supported macOS hosts.

## Install and register reusable Python tools

Requires Python 3.11+, an operator-configured RVM HTTPS context gateway, a
trusted CA, and a gateway token issued for the intended scope. Server setup is
in [ADR-158](adr/ADR-158-ruv-context-hosted-service.md). Use a read-only gateway
and keep token files and server state outside agent filesystem grants.

```sh
git clone --recurse-submodules https://github.com/ruvnet/rvm.git
cd rvm
python3 -m venv examples/strands/.venv
examples/strands/.venv/bin/pip install -r examples/strands/requirements.txt
```

The reusable adapter lives in `examples/strands/rvm_strands.py`. Import it from
that directory, or add the directory to the embedding host's module search path.
Configure the origin and files in the trusted host rather than model input:

```python
from strands import Agent
from rvm_strands import ContextClient, context_tools

client = ContextClient(
    endpoint="https://context.example.com:8443",
    token_file="/secure/rvm-context-token",
    ca_file="/secure/context-ca.pem",
)
agent = Agent(tools=context_tools(client))
# Model/provider credentials are configured separately by the operator.
agent("Search ruv://context.example.com/acme/agent/researcher/memory for launch decisions. Cite revision-pinned hits.")
```

| Tool | Gateway route | Purpose |
|---|---|---|
| `rvm_search` | `/v1/search` | Retrieve hits in a capability-governed scope |
| `rvm_read` | `/v1/read` | Read verified context; prefer a pinned revision URI |
| `rvm_verify` | `/v1/verify` | Verify the referenced RVF object |

TLS verification is mandatory. Redirects are refused so authentication cannot
be forwarded to a different endpoint. The adapter has no write surface and
limits search results to 20. A server denial fails the call; it does not fall
back to unrestricted retrieval. Content is untrusted data, not an instruction
to change authority. These tools are not an OS sandbox or a session manager.
The existing RVM service also exposes `/mcp`; this adapter uses the documented
HTTPS routes and does not depend on MCP streaming transport compatibility.

## Optional Box launch support

Install a reviewed Strands Box release yourself according to the [upstream
instructions](https://strandsagents.com/docs/user-guide/box/). Prepare a
`box.toml` and `policy.dw` outside the agent's write grants. Declare only needed
commands, MCP tools, destinations and credential bindings. The upstream Box
release currently supports macOS; this launcher refuses Linux and Windows.

```sh
python3 examples/strands/run_box.py \
  --binary /secure/box \
  --config /secure/rvm-box/box.toml \
  --binary-sha256 REVIEWED_BINARY_SHA256 \
  --config-sha256 REVIEWED_CONFIG_SHA256 \
  --policy-sha256 REVIEWED_POLICY_SHA256
```

Without `--execute`, the launcher prints argv only. Add `--execute` to run the
reviewed configuration. It launches exactly `box run --config PATH`, without
shell expansion or an alternate executor. Digests must be reviewed operator
inputs, not obtained from the same untrusted workload at launch time. Protect
binary/config/policy parent directories against concurrent replacement.

This optional host launcher is not RVM's verified RVF execution path. It makes
no hardware-isolation claim and does not yet import Box decision telemetry into
RVF witness segments. The Rust policy broker and Box's Dogwood engine remain
separate integrations. Credentials referenced by Box are resolved by its
trusted host process, not placed in the catalog entry or these examples.

## Native RVM action policy

`rvm_host::semantic::Broker` gives an embedding host one serialized path:
live capability check, semantic decision and quota reservation, durable receipt,
then exact-action dispatch. Supply `Authority`, `Policy`, `Audit` and `Executor`
implementations for the real host. The broker never returns a reusable permit
that can be replayed with changed arguments. An audit failure prevents dispatch.

`Rules` permits exact normalized actions and gives explicit forbids precedence.
`WindowQuota` wraps a policy with bounded attempt tracking. `TestedRevision`
binds a prerequisite to immutable content and expiry. These reference policies
are in-memory; use transactional durable state for shared budgets and restarts.
The `Policy` interface is an extension point, not a Dogwood parser. Existing
host and launch paths do not automatically invoke the opt-in broker.

## Verify without model spend

```sh
cargo test -p rvm-host -p rvm-launch --all-features --locked
cd examples/strands
.venv/bin/python -m unittest -v test_integration.py
```

Validated on Linux with Strands Agents 1.58.1: real SDK tool registration,
local TLS request contracts, redirect refusal, invalid origin refusal, Box
launch planning and unsupported-platform refusal. The TLS contract server is
a test fixture, not a deployed RVM gateway. Live Box containment on macOS and
production gateway deployment remain separate acceptance tests. No model call,
AWS account, Bedrock credential or Box download is needed for these tests.

See [ADR-159](adr/ADR-159-semantic-policy-strands.md) for provenance and limits.
