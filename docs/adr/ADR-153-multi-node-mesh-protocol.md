# ADR-153: Multi-Node Mesh Protocol

**Status**: Draft
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-134 (Witness Schema), ADR-135 (Proof Verifier), ADR-142 (TEE-Backed Verification), ADR-144 (GPU Compute Support)

---

## Context

ADR-132 describes RVM as a standalone bare-metal hypervisor. The current design assumes a single-node deployment: one RVM instance owns one set of hardware resources, manages partitions locally, and maintains a single coherence graph and witness chain. However, the Appliance deployment model (ADR-139) envisions edge clusters where multiple RVM instances cooperate to provide a larger coherence domain spanning multiple physical machines.

This ADR captures the design space for multi-node RVM operation. It does not propose a specific protocol. Its purpose is to document requirements, identify sub-problems, evaluate candidate approaches, and establish evaluation criteria for future work.

### Problem Statement

1. **Partition migration across nodes**: A single-node RVM can migrate partitions between physical CPU slots (DC-7, 100ms budget). Cross-node migration adds network serialization, transfer latency, and state rebuild on the destination. The existing RVF container format (ADR-149) provides a serialization vehicle, but the protocol for coordinating the source, network, and destination is undefined.
2. **Cross-node coherence graph**: The coherence graph currently resides in a single `rvm-coherence` instance. In a multi-node mesh, inter-node communication edges (CommEdge) have different latency and bandwidth characteristics than intra-node edges. The graph must span nodes while reflecting the higher cost of cross-node communication.
3. **Distributed capability delegation**: Capabilities are currently validated by the local kernel's P1/P2/P3 verifier. Cross-node delegation requires either (a) a shared capability namespace with distributed revocation, or (b) per-node capability spaces with cross-node attestation.
4. **Witness chain federation**: Each node maintains its own hash-chained witness log. For a global audit trail, these per-node chains must be merged into a consistent, tamper-evident structure. This is a non-trivial distributed systems problem.

### Non-Goals of This ADR

- Specifying a concrete protocol (this is a design-space document)
- Defining wire formats or network packet layouts
- Committing to a specific consensus algorithm
- Setting implementation timelines

---

## Design Space

### Sub-Problem 1: Partition Migration Between Nodes

**Approach A: RVF Container Transfer**

Serialize the partition state into an RVF container (as used for cold-tier checkpoints), transfer the container over the network, and rebuild the partition on the destination node.

| Aspect | Details |
|--------|---------|
| Serialization | RVF manifest + memory regions + capability table + GPU context (if active) |
| Transfer | TCP/RDMA between nodes; size bounded by partition memory footprint |
| Rebuild | Destination node creates partition from RVF, maps memory, restores capabilities |
| Witness | Source emits `PartitionMigrate` (0x09) with target_node_id in aux field |
| Consistency | Source partition is suspended during transfer; no concurrent mutation |

**Approach B: Live Migration with Witness Replay**

Transfer a checkpoint plus the witness log delta since the checkpoint. The destination replays the delta to reconstruct current state.

| Aspect | Details |
|--------|---------|
| Checkpoint | Pre-existing cold-tier checkpoint of the partition |
| Delta | Witness records from checkpoint sequence to current sequence |
| Replay | Destination applies replay protocol (ADR-134 Section 7) to reconstruct state |
| Downtime | Minimal: only the final state synchronization requires suspension |
| Complexity | Requires that all witness records are sufficient for state reconstruction |

**Approach C: Incremental Page Transfer (Pre-copy)**

Transfer memory pages iteratively while the partition runs. Track dirty pages. Final round suspends the partition and transfers remaining dirty pages.

| Aspect | Details |
|--------|---------|
| Pre-copy rounds | Configurable (default: 3 rounds) |
| Dirty tracking | Stage-2 page table write-protect + fault handler marks dirty pages |
| Convergence | Migration converges when dirty page rate < transfer rate |
| Abort | If convergence not reached within budget, abort and keep partition on source |
| Overhead | Memory write-protect faults add latency during pre-copy |

**Evaluation Criteria**: Migration time (target: <500ms for a 16MB partition over 10Gbps network), downtime (target: <10ms), correctness (destination state must be byte-identical to source state at suspension point).

### Sub-Problem 2: Cross-Node Coherence Graph

The coherence graph must span multiple nodes. Inter-node CommEdge weights must reflect network latency and bandwidth, which are orders of magnitude worse than intra-node shared memory.

**Approach A: Gossip-Based Edge Weight Propagation**

Each node maintains a local view of the global graph. Nodes periodically exchange edge weight updates via a gossip protocol.

| Aspect | Details |
|--------|---------|
| Consistency | Eventual consistency; local views may differ by one gossip round |
| Latency | Gossip round: configurable (default: 100ms) |
| Bandwidth | O(E_cross) per gossip round, where E_cross = cross-node edge count |
| Partition decisions | Based on local view; may differ across nodes during convergence |

**Approach B: Centralized Graph Coordinator**

One node is elected as the graph coordinator. All edge weight updates are sent to the coordinator, which computes the global mincut and distributes partition assignments.

| Aspect | Details |
|--------|---------|
| Consistency | Strong consistency via single-writer |
| Single point of failure | Coordinator failure requires re-election |
| Latency | All mincut decisions have network round-trip to coordinator |
| Scalability | Coordinator becomes bottleneck at large cluster sizes |

**Approach C: Hierarchical Graph (Two-Level)**

Each node computes intra-node mincut locally. A separate inter-node graph captures node-to-node communication. A cluster-level mincut on the inter-node graph determines node-level partition placement.

| Aspect | Details |
|--------|---------|
| Consistency | Intra-node: local, strong. Inter-node: eventual via gossip |
| Scalability | Intra-node graph: up to 32 nodes (existing). Inter-node graph: up to N_nodes |
| Locality | Most decisions are local; cross-node decisions are rarer and coarser |
| Complexity | Two mincut computations per epoch instead of one |

**Evaluation Criteria**: Consistency guarantees, convergence time, bandwidth overhead, fault tolerance (what happens when a node fails mid-update).

### Sub-Problem 3: Distributed Capability Delegation

Capabilities currently live in a per-node capability table. Cross-node delegation requires extending the capability model.

**Approach A: Shared Capability Namespace**

All nodes share a single logical capability table, replicated via consensus.

| Aspect | Details |
|--------|---------|
| Namespace | Global: CapHandle is unique across all nodes |
| Revocation | Distributed: revoking a capability requires consensus across all nodes |
| Latency | Every capability operation requires network round-trip for consensus |
| Consistency | Strong (via Raft or similar) |

**Approach B: Per-Node Namespaces with Cross-Node Attestation**

Each node maintains its own capability table. Cross-node operations carry a signed attestation from the source node.

| Aspect | Details |
|--------|---------|
| Namespace | Local: CapHandle is node-scoped. Cross-node references include node_id |
| Revocation | Local: each node revokes its own capabilities. Cross-node stale detection via epoch + node attestation |
| Latency | Local operations are unchanged. Cross-node operations add attestation overhead |
| Trust | Relies on TEE-backed node attestation (ADR-142) for cross-node trust |

**Approach C: Delegated Capabilities with Network Tokens**

Capabilities can be delegated cross-node by minting a "network capability token" that includes the source node's signature and a bounded validity period.

| Aspect | Details |
|--------|---------|
| Token format | CapRights + object_id + source_node_id + expiry_ns + Ed25519 signature |
| Validation | Destination node verifies signature against source node's public key |
| Revocation | Expiry-based; no explicit cross-node revocation protocol |
| Delegation depth | Network delegation counts toward the depth-8 limit |

**Evaluation Criteria**: Latency impact on local operations (must remain <1us for P1), revocation propagation time, trust model compatibility with ADR-142 TEE infrastructure.

### Sub-Problem 4: Witness Chain Federation

Each node produces a linear hash-chained witness log (ADR-134). A multi-node deployment needs a global audit trail.

**Approach A: Merged Linear Chain**

A designated node collects witness records from all nodes and merges them into a single linear chain, ordered by timestamp.

| Aspect | Details |
|--------|---------|
| Ordering | Timestamp-based (requires synchronized clocks) |
| Single point of failure | Merge node failure halts global chain |
| Causality | May not preserve causal ordering across nodes |
| Simplicity | Simple; same verification as single-node chain |

**Approach B: Merkle DAG (Directed Acyclic Graph)**

Each node's chain is a branch. Cross-node events (migration, cross-node IPC) create merge points linking two branches.

| Aspect | Details |
|--------|---------|
| Structure | DAG of witness records; each record references its local predecessor and optionally a cross-node predecessor |
| Ordering | Partial order; causal ordering preserved by cross-references |
| No single point of failure | Each node maintains its own chain independently |
| Verification | Requires DAG traversal instead of linear chain walk |

**Approach C: Cross-Node Checkpoint Anchors**

Each node maintains its own independent chain. Periodically, all nodes produce a signed checkpoint summary. These summaries are collected into a "federation anchor" record that references all node chains at a specific sequence number.

| Aspect | Details |
|--------|---------|
| Independence | Nodes operate independently between anchors |
| Anchor frequency | Configurable (default: every 1000 epochs or 1 second) |
| Verification | Verify any node's chain independently; cross-node verification via anchor comparison |
| Offline tolerance | Nodes can be disconnected between anchors |

**Evaluation Criteria**: Tamper evidence (can a compromised node forge records without detection?), offline tolerance (can nodes operate independently during network partitions?), verification complexity, clock synchronization requirements.

---

## Network Partition Tolerance

A critical requirement for multi-node RVM is correct behavior during network partitions. When nodes cannot communicate:

1. **Each node operates autonomously**: Local partitions continue to run, local coherence graph is maintained, local witness chain continues.
2. **Cross-node edges are marked stale**: Inter-node CommEdge weights decay to zero after a configurable timeout (default: 10 seconds without gossip update).
3. **Cross-node migrations are suspended**: No partition migration is attempted while the target node is unreachable.
4. **Capabilities with cross-node attestation expire naturally**: Network capability tokens have bounded validity; expiry handles the partition case without explicit revocation.
5. **Witness chains diverge**: Each node's chain continues independently. Reconciliation occurs when connectivity is restored.
6. **Reconciliation on reconnect**: When connectivity is restored, nodes exchange witness chain summaries to detect the divergence point and resume cross-node operations.

The system must never enter a state where a network partition causes data loss, authority leakage, or witness chain corruption. The worst case is temporary degradation to independent single-node operation.

---

## Open Questions

| # | Question | Impact | Potential Resolution |
|---|----------|--------|---------------------|
| 1 | What clock synchronization precision is required for timestamp-based witness ordering? | High | NTP (~1ms), PTP (~1us), or logical clocks (Lamport/vector) |
| 2 | What is the maximum cluster size (number of nodes)? | Medium | Determines whether gossip or consensus is appropriate |
| 3 | Should cross-node mincut use a different algorithm than intra-node? | Medium | The hierarchical two-level approach avoids this question |
| 4 | How are GPU contexts handled during cross-node migration? | High | GPU context serialization is GPU-vendor-specific; may require context rebuild |
| 5 | What is the acceptable cross-node migration budget? | High | DC-7 says 100ms for local; cross-node likely needs 500ms-1s |
| 6 | Is Byzantine fault tolerance required? | High | If any node can be compromised, BFT consensus is needed; if all nodes are trusted, Raft suffices |

---

## Preliminary Recommendations

Based on the analysis above, the following approach is recommended for initial prototyping (not a final decision):

1. **Migration**: Approach A (RVF container transfer) for simplicity. Pre-copy (Approach C) is a future optimization.
2. **Coherence graph**: Approach C (hierarchical two-level) for scalability and locality.
3. **Capabilities**: Approach B (per-node namespaces with attestation) for minimal latency impact on local operations.
4. **Witness chain**: Approach C (cross-node checkpoint anchors) for offline tolerance and simplicity.

These recommendations will be refined into a concrete protocol specification when multi-node work begins (post-v1).

---

## References

- ADR-132: RVM Hypervisor Core (DC-7 migration budget, DC-12 logical partition limit)
- ADR-134: Witness Schema and Log Format (hash chain, replay protocol)
- ADR-135: Proof Verifier Design (capability model, P1/P2/P3 layers)
- ADR-142: TEE-Backed Cryptographic Verification (Ed25519, node attestation)
- ADR-144: GPU Compute Support (GPU context save/restore)
- Lamport, L. "Time, Clocks, and the Ordering of Events in a Distributed System." CACM, 1978.
- Ongaro, D. & Ousterhout, J. "In Search of an Understandable Consensus Algorithm (Raft)." USENIX ATC, 2014.
- Castro, M. & Liskov, B. "Practical Byzantine Fault Tolerance." OSDI, 1999.
