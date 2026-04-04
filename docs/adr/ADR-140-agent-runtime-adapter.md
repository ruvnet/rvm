# ADR-140: Agent Runtime Adapter — WASM Agents in Coherence Domains

**Status**: Proposed
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-133 (Partition Object Model), ADR-139 (Appliance Deployment Model)

---

## Context

ADR-132 describes RVM as simultaneously a hypervisor, a graph engine, and an agent runtime (DC-5). The hypervisor (kernel) and coherence engine are specified in ADR-132 and its follow-on ADRs. This ADR specifies the third system: the agent runtime adapter that hosts WASM-based agent workloads inside coherence domains.

### Problem Statement

1. **Partitions need executable workloads**: ADR-132 defines partitions as coherence domain containers, but a partition without a runtime is an empty box. The agent runtime adapter fills these boxes with executable WASM modules.
2. **Agents need double sandboxing**: A single isolation boundary is insufficient for multi-tenant edge computing. Agents must be sandboxed at both the capability level (kernel-enforced partition boundaries) and the memory level (WASM linear memory). Neither boundary alone is sufficient.
3. **Agent communication must feed the coherence graph**: The coherence engine derives its value from observing inter-partition communication patterns. Agent IPC must be routed through CommEdges so that every message updates the graph and informs mincut decisions.
4. **Migration must be transparent to agents**: When the coherence engine decides to move an agent to a different partition (or a different core, or a different node), the agent must not need to know. Its state, memory, and communication endpoints must transfer seamlessly.
5. **WASM in bare-metal context is validated**: Microsoft's Hyperlight project (March 2025) demonstrated `wasmtime` compiled as a `no_std` module running inside a bare-metal hypervisor. This proves the technical viability of WASM agents in a hypervisor without a host OS.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| wasmtime | Production WASM runtime with Cranelift JIT; `no_std` capable | Primary runtime candidate; validated by Hyperlight |
| Microsoft Hyperlight (March 2025) | `wasmtime` as `no_std` module inside a bare-metal hypervisor | Direct proof of concept for WASM-in-hypervisor |
| WAMR (WebAssembly Micro Runtime) | Lightweight WASM interpreter for embedded (<100KB) | Alternative for extremely constrained partitions |
| WASI Preview 2 / Component Model | Typed interface composition for WASM modules | Informs typed IPC via CommEdges |
| Lunatic | Erlang-like actor system built on WASM | Actor model for agent isolation and communication patterns |
| Fermyon Spin | WASM microservice framework with capability-based security | Demonstrates capability-gated WASM execution at scale |

---

## Decision

### Core Design: WASM Modules Inside Partitions

Agents run as WebAssembly modules inside RVM partitions. Each agent is double-sandboxed:

```
┌─────────────────────────────────────────────────┐
│ RVM Kernel (EL2 / VMX root)                   │
│   Capability table, witness log, scheduler      │
│                                                  │
│  ┌────────────────────┐  ┌────────────────────┐ │
│  │ Partition P1        │  │ Partition P2        │ │
│  │ (stage-2 page table)│  │ (stage-2 page table)│ │
│  │                     │  │                     │ │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │ │
│  │  │ WASM Agent A  │  │  │  │ WASM Agent C  │  │ │
│  │  │ (linear mem)  │  │  │  │ (linear mem)  │  │ │
│  │  └───────────────┘  │  │  └───────────────┘  │ │
│  │  ┌───────────────┐  │  │                     │ │
│  │  │ WASM Agent B  │  │  │                     │ │
│  │  │ (linear mem)  │  │  │                     │ │
│  │  └───────────────┘  │  │                     │ │
│  └─────────┬───────────┘  └─────────┬───────────┘ │
│            │      CommEdge          │             │
│            └────────────────────────┘             │
└─────────────────────────────────────────────────┘
```

**Sandbox 1 — Partition boundary**: Enforced by stage-2 page tables and the capability system. A partition cannot access memory, devices, or communication channels that it does not hold capabilities for. This is the kernel-level boundary.

**Sandbox 2 — WASM linear memory**: Each WASM module has its own linear memory space. Even within a shared partition (where tightly-coupled agents A and B co-reside), agent A cannot access agent B's linear memory. The WASM runtime enforces this at the instruction level.

### Agent-to-Partition Mapping

Each agent maps to exactly one partition. The mapping rules are:

| Scenario | Mapping | Rationale |
|----------|---------|-----------|
| Independent agent | 1 agent : 1 partition | Full isolation, separate coherence score |
| Tightly-coupled agents | N agents : 1 partition | High coherence score between them; co-location avoids cross-partition IPC overhead |
| Agent migration | Agent moves between partitions | Coherence engine detects misplacement via mincut |

The coherence engine (ADR-132, Layer 2) continuously evaluates whether the current agent-to-partition mapping is optimal. If agent B in partition P1 communicates more heavily with agent C in partition P2 than with agent A in P1, the mincut algorithm detects this and triggers migration of B to P2 (or creation of a new partition).

### WASM Runtime Selection

| Runtime | Build Mode | Size | Compilation | Use Case |
|---------|-----------|------|-------------|----------|
| **wasmtime** (`no_std`) | AOT via Cranelift | ~2 MB | Ahead-of-time or JIT | Primary runtime for Appliance |
| **WAMR** (interpreter) | Interpreter | ~100 KB | None (interprets bytecode) | Fallback for memory-constrained partitions |

**Primary choice: wasmtime compiled as `no_std` module.**

Rationale:
- Microsoft Hyperlight (March 2025) validated this exact approach: wasmtime running inside a bare-metal hypervisor without a host OS
- Cranelift AOT compilation produces native code, eliminating interpretation overhead
- `no_std` build avoids libc dependency, compatible with RVM's bare-metal environment
- Larger binary size (2 MB) is acceptable on Appliance-class hardware (1-32 GB RAM)

WAMR is retained as a fallback for partitions with extreme memory constraints or for the Seed platform (future ADR).

### Agent Lifecycle

```
               ┌──────────────┐
               │ Initializing │ ◄── WASM module loaded, capabilities granted
               └──────┬───────┘
                      │
                      v
               ┌──────────────┐
          ┌───►│   Running    │◄────────────────────────────┐
          │    └──────┬───────┘                              │
          │           │                                      │
          │    ┌──────┴───────┐         ┌───────────────┐    │
          │    │  Suspended   │         │  Migrating    │    │
          │    │  (I/O wait   │────────►│  (from → to)  │────┘
          │    │   or yield)  │         └───────────────┘
          │    └──────┬───────┘
          │           │
          │    ┌──────┴───────┐
          │    │  Hibernated  │ ◄── state compressed to Dormant tier
          │    └──────┬───────┘
          │           │
          │    ┌──────┴────────────┐
          └────┤  Reconstructing   │ ◄── state restored from Dormant/Cold tier
               └──────┬────────────┘
                      │
               ┌──────┴───────┐
               │  Terminated  │ ◄── cleanup complete, capabilities revoked
               └──────────────┘
```

| State | Description | Memory Tier | Schedulable |
|-------|-------------|-------------|-------------|
| **Initializing** | WASM module loading, capability setup, CommEdge creation | Hot | No |
| **Running** | Actively executing within partition | Hot | Yes |
| **Suspended** | Waiting on I/O, CommEdge recv, or explicit yield | Hot/Warm | No (resumes on event) |
| **Migrating** | State serialized, transferring to target partition | Hot (source) -> Hot (target) | No |
| **Hibernated** | State compressed, partition may be reclaimed | Dormant | No |
| **Reconstructing** | State decompressing from Dormant or Cold tier | Dormant -> Hot | No |
| **Terminated** | Cleanup complete, all resources released | None | No |

### Host Functions: WASM-to-Kernel Interface

WASM agents interact with the kernel through host functions. Every host function maps to a RVM syscall and is capability-checked before execution.

| Host Function | Syscall | Required Capability | Description |
|--------------|---------|-------------------|-------------|
| `send(edge_id, data)` | `queue_send` | WRITE on CommEdge | Send a message to another agent |
| `recv(edge_id, buf)` | `queue_recv` | READ on CommEdge | Receive a message from a CommEdge |
| `notify(edge_id, mask)` | `notify_signal` | WRITE on NotificationWord | Signal a notification bit |
| `wait(edge_id, mask)` | `notify_wait` | READ on NotificationWord | Wait for notification |
| `request_shared_region(size, policy)` | `region_create` | WRITE on partition | Allocate a shared memory region |
| `map_shared(region_id)` | `region_map` | READ on region | Map a shared region into agent's view |
| `vector_get(store, key, buf)` | `vecstore_get` | READ on VectorStore | Read a vector from kernel vector store |
| `vector_put(store, key, data)` | `vecstore_put` | WRITE + PROVE on VectorStore | Write a vector with proof |
| `spawn_agent(config)` | `partition_create` + `task_create` | EXECUTE + PROVE on partition | Spawn a child agent |
| `hibernate()` | `task_hibernate` | HIBERNATE on partition | Request hibernation |
| `yield_now()` | `sched_yield` | (none) | Yield execution to scheduler |

**No ambient authority**: An agent that does not hold a capability for a given resource cannot invoke the corresponding host function. The WASM runtime traps the call, and the kernel returns `CapabilityDenied` without executing the operation. A witness record is emitted for the denied access.

### Agent Communication: Typed Messages via CommEdges

All agent-to-agent communication goes through CommEdges (architecture doc, Section 3.5). This is not optional — there is no shared memory backdoor, no global namespace, no side channel.

**Message flow:**

```
Agent A                    Kernel                     Agent B
   │                         │                          │
   │ send(edge_42, payload)  │                          │
   │────────────────────────►│                          │
   │                         │ 1. Capability check      │
   │                         │ 2. Schema validation     │
   │                         │ 3. Enqueue in CommEdge   │
   │                         │ 4. Update edge weight    │
   │                         │ 5. Emit witness          │
   │                         │────────────────────────► │
   │                         │ recv(edge_42, buf)        │
   │                         │                          │
```

**Schema validation**: CommEdges carry a schema hash. When an agent sends a message, the kernel validates that the message conforms to the declared schema before enqueuing. This prevents confused-deputy attacks where Agent A sends a malformed message that causes Agent B to misbehave. The schema is declared at CommEdge creation time and cannot be changed.

**Zero-copy optimization**: For large payloads, agents use `request_shared_region` and `map_shared` to establish a shared memory region, then send a `ZeroCopyDescriptor` over the CommEdge instead of the data itself. The receiver reads directly from the shared region. The shared region is mapped read-only in the receiver's stage-2 page table.

### Agent Identity: Badge-Based

Agent identity is kernel-assigned and unforgeable:

```rust
/// Agent badge: unforgeable identity assigned by the kernel at spawn time.
///
/// The badge is embedded in every capability derived for this agent.
/// It cannot be self-asserted, copied, or forged. The kernel verifies
/// the badge on every syscall by checking the calling partition's
/// capability table.
pub struct AgentBadge {
    /// Monotonically increasing ID, never reused
    id: u64,
    /// Partition this agent belongs to
    partition: PartitionId,
    /// Hash of the WASM module that was loaded
    module_hash: [u8; 32],
    /// Spawn timestamp (for ordering and witness correlation)
    spawned_at_ns: u64,
}
```

An agent cannot claim to be a different agent. Every message sent over a CommEdge carries the sender's badge, verified by the kernel. This eliminates identity spoofing in multi-agent systems.

### Migration Protocol

When the coherence engine determines that an agent should move to a different partition, the following protocol executes:

```
Migration Protocol (Agent X: Partition P1 → Partition P2):

1. SUSPEND      Set agent X state to Migrating{from: P1, to: P2}
                Emit witness: MIGRATION_START(agent=X, from=P1, to=P2)

2. SERIALIZE    Capture WASM linear memory (pages)
                Capture WASM execution state (stack, globals, table)
                Capture agent-owned region references
                Total serialized state = linear_memory + exec_state + region_list

3. TRANSFER     Allocate equivalent resources in P2
                Copy serialized state to P2 memory
                (If cross-node: encrypt, send over network, decrypt)

4. RECONNECT    For each CommEdge connected to agent X:
                  Update endpoint from P1 to P2
                  Update coherence graph edge
                  Emit witness: EDGE_RELOCATED(edge=E, from=P1, to=P2)

5. GRAPH        Update coherence graph:
                  Remove agent X node from P1 subgraph
                  Add agent X node to P2 subgraph
                  Recompute mincut for both P1 and P2

6. RESTORE      Instantiate WASM runtime in P2 with transferred state
                Set agent X state to Running
                Emit witness: MIGRATION_COMPLETE(agent=X, partition=P2)

7. CLEANUP      Release agent X resources in P1
                If P1 is now empty, mark for reclamation
```

**Invariant**: At no point during migration are messages to agent X lost. CommEdges buffer messages during migration. The agent resumes in P2 and drains any buffered messages.

### Hibernation and Reconstruction

Agents can be hibernated (state compressed to Dormant tier) and reconstructed on demand:

**Hibernation**:
1. Suspend agent execution
2. Compress WASM linear memory + execution state using LZ4
3. Store compressed state in Dormant tier memory region
4. Record reconstruction receipt in the witness log (hash of compressed state + location pointer)
5. Release Hot-tier memory occupied by the agent
6. Set agent state to Hibernated

**Reconstruction**:
1. Locate compressed state via reconstruction receipt
2. Decompress state from Dormant (or Cold, if evicted to storage) tier
3. Allocate Hot-tier memory for the agent
4. Restore WASM runtime with decompressed state
5. Reconnect CommEdges (endpoints may have moved during hibernation)
6. Resume execution from the exact instruction where hibernation occurred
7. Emit witness: AGENT_RECONSTRUCTED

### Resource Limits

Per-partition resource quotas prevent DoS by any single agent:

| Resource | Quota Mechanism | Default Limit | Enforcement |
|----------|----------------|---------------|-------------|
| CPU time | Time quantum per scheduler epoch | 10ms per epoch | Preempted by scheduler |
| Memory | WASM linear memory page limit | 256 pages (16 MB) | `memory.grow` returns -1 beyond limit |
| IPC rate | Message count per epoch | 1000 messages/epoch | `send` returns `RateLimited` |
| Device access | Lease duration and DMA budget | Per-device policy | Lease expiry, DMA budget exhaustion |
| Agent spawning | Spawn count limit | 4 children per agent | `spawn_agent` returns `SpawnLimitReached` |

Quota violations are witnessed. Repeated violations can trigger automatic hibernation of the offending agent.

### Agent Spawning: Capability-Gated

Only partitions with EXECUTE + PROVE rights can spawn new agents:

```
Spawn Protocol:
1. Parent agent calls spawn_agent(config)
2. Kernel checks: parent holds Capability(partition, EXECUTE | PROVE)
3. Kernel validates WASM module (signature check via ruvix-boot attestation)
4. Kernel creates new partition (or assigns to parent's partition if tightly-coupled)
5. Kernel derives child capabilities from parent's capability tree (rights can only narrow)
6. Kernel creates CommEdge between parent and child
7. Kernel instantiates WASM runtime, loads module, begins execution
8. Witness: AGENT_SPAWNED(parent=P, child=C, module_hash=H)
```

**Capability narrowing**: A parent can only grant capabilities it holds. A child agent can never have more authority than its parent. This forms a delegation tree rooted at the boot partition.

### RuVector Integration

Agent communication patterns are the primary input to the coherence engine:

| Agent Activity | Coherence Graph Effect | Mincut Consequence |
|---------------|----------------------|-------------------|
| Agent A sends to Agent B frequently | CommEdge(A,B) weight increases | Mincut favors keeping A and B in same partition |
| Agent A stops communicating with Agent C | CommEdge(A,C) weight decays | Mincut may separate A and C into different partitions |
| Agent A spawns Agent D | New node D added to graph, edge(A,D) created | Mincut recomputed for parent partition |
| Agent A hibernated | Node A removed from active graph | Mincut recomputed; may trigger merge of remaining agents |
| Agent A migrated P1 -> P2 | Node A moves in graph, edges updated | Post-migration mincut validates improvement |

The coherence engine does not understand agent semantics. It observes communication patterns and derives placement decisions purely from graph structure. This separation (ADR-132, DC-5) ensures the coherence engine remains independent of the agent runtime.

---

## Phase Dependency

The agent runtime adapter is a **Phase 4 feature (M6)** in the ADR-132 milestone plan. It depends on:

| Dependency | Phase | What It Provides |
|-----------|-------|-----------------|
| Kernel boot + partition model | Phase 1 (M0-M1) | Partitions exist, capabilities enforced |
| Witness logging | Phase 2 (M2) | All agent actions are witnessed |
| Scheduler with coherence scoring | Phase 2-3 (M3) | Agents are scheduled based on coherence |
| Dynamic mincut | Phase 3 (M4) | Migration decisions driven by graph |
| Memory tiers | Phase 3 (M5) | Hibernation and reconstruction work |

The agent runtime does NOT depend on the coherence engine being present (ADR-132, DC-1). If the coherence engine is absent, agents still run — they just get static partition assignment instead of dynamic placement.

---

## Consequences

### Positive

- **Multi-agent edge computing on bare metal**: No host OS, no container runtime, no VM overhead. Agents run directly on the hypervisor with two layers of sandboxing.
- **Communication-driven placement**: Agent IPC patterns automatically feed the coherence graph, enabling the mincut algorithm to optimize placement without manual configuration.
- **Transparent migration**: Agents can be moved between partitions (and eventually between nodes) without code changes. The kernel handles all state transfer.
- **Unforgeable identity**: Badge-based identity eliminates agent impersonation. Combined with schema-validated IPC, this prevents confused-deputy attacks.
- **Hibernate and reconstruct**: Long-running agents can be suspended, compressed, stored, and revived without losing state. This enables efficient use of limited edge hardware.
- **Capability delegation tree**: The spawn model ensures that agent authority can only narrow, never escalate. The root partition defines the maximum authority in the system.

### Negative

- **WASM overhead vs. native partitions**: WASM execution is slower than native code. The JIT compilation (Cranelift) narrows the gap but does not eliminate it. Benchmarks at M6 must quantify this overhead. If overhead exceeds 2x for latency-critical workloads, native partition adapters remain available.
- **Migration latency**: Serializing WASM linear memory (up to 16 MB per agent) takes time. Migration of a fully-loaded agent may take 1-10ms depending on memory size and whether the transfer is local or cross-node. During migration, the agent is unavailable.
- **Schema rigidity**: CommEdge schemas are fixed at creation time. Changing a message format between two agents requires destroying and recreating the CommEdge. This is deliberate (prevents type confusion) but constrains protocol evolution.
- **No filesystem abstraction**: WASM agents have no filesystem. All persistent state goes through the kernel's region and witness APIs. Agents ported from Linux environments require adaptation.

### Risks

| Risk | Mitigation |
|------|-----------|
| wasmtime `no_std` build proves unstable | Fall back to WAMR interpreter; accept performance degradation |
| WASM memory overhead makes 64 partitions infeasible on 4 GB RAM | Reduce default partition budget; rely on hibernation to keep working set within memory |
| Migration causes CommEdge message loss | Buffer messages in CommEdge during migration; drain on reconnect; test under load at M6 |
| Schema validation overhead on IPC hot path | Cache schema check result per CommEdge; validate only on first message after edge creation or reconfiguration |
| Agent spawning creates unbounded partition growth | Enforce spawn count limits per agent; enforce global partition limit (64 max on Appliance) |

---

## References

- ADR-132: RVM Hypervisor Core
- ADR-133: Partition Object Model
- ADR-139: Appliance Deployment Model
- RVM Architecture Document, Section 9 (Agent Runtime Layer): `docs/research/ruvm/architecture.md`
- RVM GOAP Plan, Milestone M6 (Agent Runtime Adapter): `docs/research/ruvm/goap-plan.md`
- Microsoft Hyperlight. "Hyperlight: Virtual machine-based security for functions at host-native speed." March 2025.
- Bytecode Alliance. "wasmtime: A fast and secure runtime for WebAssembly." https://wasmtime.dev/
- WAMR. "WebAssembly Micro Runtime." https://github.com/bytecodealliance/wasm-micro-runtime
