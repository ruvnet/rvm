# RVM State-of-the-Art Analysis: Bare-Metal Rust Hypervisors and Coherence-Native OS Design

**Date:** 2026-04-04
**Scope:** Research survey for the RVM microhypervisor project
**Constraint:** RVM does NOT depend on Linux or KVM

---

## Table of Contents

1. [Bare-Metal Rust OS/Hypervisor Projects](#1-bare-metal-rust-oshypervisor-projects)
2. [Capability-Based Systems](#2-capability-based-systems)
3. [Coherence Protocols](#3-coherence-protocols)
4. [Agent/Edge Computing Runtimes](#4-agentedge-computing-runtimes)
5. [Graph-Partitioned Scheduling](#5-graph-partitioned-scheduling)
6. [Existing RuVector Crates Relevant to Hypervisor Design](#6-existing-ruvector-crates-relevant-to-hypervisor-design)
7. [Synthesis: How Each Area Maps to RVM Design Decisions](#7-synthesis-how-each-area-maps-to-ruvix-design-decisions)
8. [References](#8-references)

---

## 1. Bare-Metal Rust OS/Hypervisor Projects

### 1.1 RustyHermit (Hermit OS)

**What it is:** A Rust-based lightweight unikernel targeting scalable and predictable runtime for high-performance and cloud computing. Originally a rewrite of HermitCore.

**Boot model:** RustyHermit supports two deployment modes: (a) running inside a VM via the uhyve hypervisor (which itself requires KVM), and (b) running bare-metal side-by-side with Linux in a multi-kernel configuration. The uhyve path depends on KVM; the multi-kernel path allows bare-metal but assumes a Linux host for the other kernel.

**Memory model:** Single address space unikernel model. The application and kernel share one address space with no process isolation boundary. Memory safety comes from Rust's ownership model rather than MMU page tables.

**Scheduling:** Cooperative scheduling within the single unikernel image. No preemptive multitasking between isolated components. The scheduler is optimized for throughput rather than isolation.

**RVM relevance:** RustyHermit demonstrates that a pure-Rust kernel can achieve competitive performance, but its unikernel design lacks the isolation model RVM requires. RVM's capability-gated multi-task model is fundamentally different. However, RustyHermit's approach to no_std Rust kernel bootstrapping and its minimal dependency chain are instructive for RVM's Phase B bare-metal port.

**Key lesson for RVM:** Unikernels trade isolation for performance. RVM takes the opposite stance -- isolation is non-negotiable, but it must be capability-based rather than process-based.

### 1.2 Theseus OS

**What it is:** A research OS written entirely in Rust exploring "intralingual design" -- closing the semantic gap between compiler and hardware by maximally leveraging language safety and affine types.

**Boot model:** Boots on bare-metal x86_64 hardware (tested on Intel NUC, Thinkpad) and in QEMU. No dependency on Linux or KVM for operation. Uses a custom bootloader.

**Memory model:** All code runs at Ring 0 in a single virtual address space, including user applications written in purely safe Rust. Protection comes from the Rust type system rather than hardware privilege levels. The OS can guarantee at compile time that a given application or kernel component cannot violate isolation between modules.

**Scheduling:** Component-granularity scheduling where OS modules can be dynamically loaded and unloaded at runtime. State management is the central innovation -- Theseus minimizes the states one component holds for another, enabling live evolution of running system components.

**RVM relevance:** Theseus's intralingual approach is the closest philosophical match to RVM. Both systems bet on Rust's type system as a primary isolation mechanism. However, Theseus runs everything at Ring 0, while RVM uses EL1/EL0 separation with hardware MMU enforcement as a defense-in-depth layer on top of type safety.

**Key lesson for RVM:** Language-level isolation can replace MMU-based isolation for trusted components, but hardware-enforced boundaries remain essential for untrusted WASM workloads. RVM's hybrid approach (type safety for kernel, MMU for user components) is well-positioned.

### 1.3 RedLeaf

**What it is:** An OS developed from scratch in Rust to explore the impact of language safety on OS organization. Published at OSDI 2020.

**Boot model:** Boots on bare-metal x86_64. No Linux dependency. Custom bootloader with UEFI support.

**Memory model:** Does not rely on hardware address spaces for isolation. Instead uses only type and memory safety of the Rust language. Introduces "language domains" as the unit of isolation -- a lightweight abstraction for information hiding and fault isolation. Domains can be dynamically loaded and cleanly terminated without affecting other domains.

**Scheduling:** Domain-aware scheduling where the unit of execution is a domain rather than a process. Domains communicate through shared heaps with ownership transfer semantics that leverage Rust's ownership model for zero-copy IPC.

**RVM relevance:** RedLeaf's domain model closely parallels RVM's capability-gated task model. Both systems achieve isolation without traditional process boundaries. RedLeaf's shared heap with ownership transfer is conceptually similar to RVM's queue-based IPC with zero-copy ring buffers. RedLeaf also achieves 10Gbps network driver performance matching DPDK, demonstrating that language-based isolation does not inherently sacrifice throughput.

**Key lesson for RVM:** Language domains with clean termination semantics map well to RVM's RVF component model. The ability to isolate and restart a crashed driver without system-wide impact is exactly what RVM needs for agent workloads.

### 1.4 Tock OS

**What it is:** A secure embedded OS for microcontrollers, written in Rust, designed for running multiple concurrent, mutually distrustful applications.

**Boot model:** Runs on bare-metal Cortex-M and RISC-V microcontrollers. No OS dependency. Direct hardware boot.

**Memory model:** Dual isolation strategy:
- **Capsules** (kernel components): Language-based isolation using safe Rust. Zero overhead. Capsules can only be written in safe Rust.
- **Processes** (applications): Hardware MPU isolation. The MPU limits which memory addresses a process can access; violations trap to the kernel.

**Scheduling:** Priority-based preemptive scheduling with per-process grant regions for safe kernel-user memory sharing. Tock 2.2 (January 2025) achieved compilation on stable Rust for the first time.

**RVM relevance:** Tock's dual isolation model (language for trusted, hardware for untrusted) is the same architectural pattern RVM employs. Tock's capsule model directly influenced RVM's approach to kernel extensions. The 2025 TickTock formal verification effort discovered five previously unknown MPU configuration bugs and two interrupt handling bugs that broke isolation -- a cautionary result for any system relying on MPU/MMU configuration correctness.

**Key lesson for RVM:** Formal verification of the MMU/MPU configuration code in ruvix-aarch64 should be a priority. The TickTock results demonstrate that even mature, well-tested isolation code can harbor subtle bugs.

### 1.5 Hubris (Oxide Computer)

**What it is:** A microkernel OS for deeply embedded systems, developed by Oxide Computer Company. Written entirely in Rust. Production-deployed in Oxide rack-mount server service controllers.

**Boot model:** Bare-metal on ARM Cortex-M microcontrollers. No OS dependency. Static binary with all tasks compiled together.

**Memory model:** Strictly static architecture. No dynamic memory allocation. No runtime task creation or destruction. The kernel is approximately 2000 lines of Rust. Memory regions are assigned at compile time via a build system configuration (TOML-based task descriptions).

**Scheduling:** Strictly synchronous IPC model. Preemptive priority-based scheduling. Tasks that crash can be restarted without affecting the rest of the system. No driver code runs in privileged mode.

**RVM relevance:** Hubris demonstrates that a production-quality Rust microkernel can be extremely small (~2000 lines) while providing real isolation. Its static, no-allocation design philosophy aligns with RVM's "fixed memory layout" constraint. Hubris's approach to compile-time task configuration is analogous to RVM's RVF manifest-driven resource declaration.

**Key lesson for RVM:** Static resource declaration at boot (from RVF manifest) is a proven pattern. Hubris's production track record at Oxide validates the Rust microkernel approach for real hardware.

### 1.6 Redox OS

**What it is:** A complete Unix-like microkernel OS written in Rust, targeting general-purpose desktop and server use.

**Boot model:** Boots on bare-metal x86_64 hardware. Custom bootloader with UEFI support. The 2025-2026 roadmap includes ARM and RISC-V support.

**Memory model:** Traditional microkernel with hardware address space isolation. Processes run in separate address spaces. The kernel handles memory management, scheduling, and IPC. Device drivers run in userspace.

**Scheduling:** Standard microkernel scheduling with userspace servers. Recent 2025 improvements yielded 500-700% file I/O performance gains. Self-hosting is a key roadmap goal.

**RVM relevance:** Redox proves that a full microkernel OS can be written in Rust and run on real hardware. Its "everything in Rust" approach validates the toolchain. However, Redox's Unix-like POSIX interface is exactly the abstraction mismatch that RVM is designed to avoid. Redox optimizes for human-process workloads; RVM optimizes for agent-vector-graph workloads.

**Key lesson for RVM:** Redox's experience with driver isolation in userspace and its bare-metal boot process are directly transferable. But RVM should not adopt POSIX semantics.

### 1.7 Hyperlight (Microsoft)

**What it is:** A micro-VM manager that creates ultra-lightweight VMs with no OS inside. Open-sourced in 2024-2025, now in the CNCF Sandbox.

**Boot model:** Creates VMs using hardware hypervisor support (Hyper-V on Windows, KVM on Linux, mshv on Azure). The VMs themselves contain no operating system -- just a linear memory slice and a CPU. VM creation takes 1-2ms, with warm-start latency of 0.9ms.

**Memory model:** Each micro-VM gets a flat linear memory region. No virtual devices, no filesystem, no OS. The Hyperlight Wasm guest compiles wasmtime as a no_std Rust module that runs directly inside the micro-VM.

**Scheduling:** Host-managed. The micro-VMs are extremely short-lived function executions. No internal scheduler needed.

**RVM relevance:** Hyperlight demonstrates the "WASM-in-a-VM-with-no-OS" pattern that is extremely relevant to RVM. The key insight is that wasmtime can be compiled as a no_std component and run without any operating system. RVM's approach of embedding a WASM runtime directly in the kernel aligns with this pattern, but RVM goes further by providing kernel-native vector/graph primitives that Hyperlight lacks.

**Key lesson for RVM:** Wasmtime's no_std mode is production-viable. The Hyperlight architecture validates the "no OS needed for WASM execution" thesis. RVM should study Hyperlight's wasmtime-platform.h abstraction layer for the Phase B bare-metal WASM port.

---

## 2. Capability-Based Systems

### 2.1 seL4's Capability Model

**Architecture:** seL4 is the gold standard for capability-based microkernels. It was the first OS kernel to receive a complete formal proof of functional correctness (8,700 lines of C verified from abstract specification down to binary). Every kernel resource is accessed through capabilities -- unforgeable tokens managed by the kernel.

**Capability structure:** seL4 capabilities encode: an object pointer (which kernel object), access rights (what operations are permitted), and a badge (extra metadata for IPC demultiplexing). Capabilities are stored in CNodes (capability nodes), which are themselves accessed through capabilities, forming a recursive namespace.

**Delegation and revocation:** Capabilities can be copied (with equal or lesser rights), moved between CNodes, and revoked. Revocation is recursive -- revoking a capability invalidates all capabilities derived from it.

**Rust bindings:** The sel4-sys crate provides Rust bindings for seL4 system calls. Antmicro and Google developed a version designed for maintainability. The seL4 Microkit framework supports Rust as a first-class language.

**RVM's adoption of seL4 concepts:**
- RVM's `ruvix-cap` crate implements seL4-style capabilities with `CapRights`, `CapHandle`, derivation trees, and epoch-based invalidation
- Maximum delegation depth of 8 (configurable) prevents unbounded chains
- Audit logging with depth-warning threshold at 4
- The `GRANT_ONCE` right provides non-transitive delegation (not in seL4)
- Unlike seL4's C implementation, RVM's capability manager is `#![forbid(unsafe_code)]`

**Gap analysis:** seL4's formal verification is its strongest asset. RVM currently lacks formal proofs for its capability manager. The Tock/TickTock experience (five bugs found through verification) suggests formal verification of `ruvix-cap` should be prioritized.

### 2.2 CHERI Hardware Capabilities

**Architecture:** CHERI (Capability Hardware Enhanced RISC Instructions) extends processor ISAs with hardware-enforced capabilities. Rather than relying solely on page tables for memory protection, CHERI encodes bounds and permissions directly in pointer representations. Pointers become fat capabilities that carry their own access metadata.

**ARM Morello:** Arm's Morello evaluation platform implemented CHERI extensions on an Armv8.2-A processor. Performance evaluation on 20 C/C++ applications showed overheads ranging from negligible to 1.65x, with the highest costs in pointer-intensive workloads. However, as of 2025, Arm has stepped back from active Morello development, pushing CHERI adoption toward smaller embedded processors.

**Verified temporal safety:** A 2025 paper at CPP presented a formal CHERI C memory model for verified temporal safety, demonstrating that CHERI can enforce not just spatial safety (bounds) but also temporal safety (use-after-free prevention).

**RVM relevance:** CHERI's capability-per-pointer model is more fine-grained than RVM's capability-per-object model. If future AArch64 processors include CHERI extensions, RVM could leverage them for sub-region protection within capability boundaries. In the near term, RVM achieves similar goals through Rust's ownership system (compile-time) and MMU page tables (runtime).

**Key lesson for RVM:** CHERI demonstrates that hardware capabilities are feasible but face adoption challenges. RVM's software-capability approach (ruvix-cap) is the right near-term strategy, with CHERI as a future hardware acceleration path. The `ruvix-hal` HAL trait layer already allows for pluggable MMU implementations, which could be extended to CHERI capabilities.

### 2.3 Barrelfish Multikernel

**Architecture:** Barrelfish runs a separate small kernel ("CPU driver") on each core. Kernels share no memory. All inter-core communication is explicit message passing. The rationale: hardware cache coherence protocols are difficult to scale beyond ~80 cores, so Barrelfish makes communication explicit rather than relying on shared-memory illusions.

**Capability model:** Barrelfish uses a capability system where the CPU driver maintains capabilities, executes syscalls on capabilities, and schedules dispatchers. Dispatchers are the unit of scheduling -- an application spanning multiple cores has a dispatcher per core, and dispatchers never migrate.

**System knowledge base:** At boot, Barrelfish probes hardware to measure inter-core communication performance, stores results in a small database (SKB), and runs an optimizer to select communication patterns.

**RVM relevance:** Barrelfish's per-core kernel model directly informs RVM's future Phase C (SMP) design. The `ruvix-smp` crate already provides CPU topology management, per-CPU state tracking, IPI messaging (Reschedule, TlbFlush, FunctionCall), and lock-free atomic state transitions -- all aligned with the multikernel philosophy.

**Key lesson for RVM:** For multi-core RVM, the Barrelfish model suggests: (1) run a scheduler instance per core rather than a single shared scheduler, (2) use explicit message passing between per-core schedulers, (3) probe inter-core latency at boot and store in a performance database that the coherence-aware scheduler can consult.

---

## 3. Coherence Protocols

### 3.1 Hardware Cache Coherence: MOESI and MESIF

**MESI (Modified, Exclusive, Shared, Invalid):** The baseline snooping protocol. Each cache line exists in one of four states. Write operations invalidate all other copies (write-invalidate). Simple but generates high bus traffic on writes to shared data.

**MOESI (adds Owned):** AMD's extension. The Owned state allows a modified, shared line to serve reads directly from the owning cache rather than writing back to memory first. This reduces write-back traffic at the cost of more complex state transitions.

**MESIF (adds Forward):** Intel's extension. The Forward state designates exactly one cache as the responder for shared-line requests, eliminating redundant responses when multiple caches hold the same shared line. Optimized for read-heavy sharing patterns.

**Scalability limits:** All snooping protocols face fundamental scalability issues beyond ~32-64 cores because every cache must observe every bus transaction. This motivates the shift to directory-based protocols at higher core counts.

### 3.2 Directory-Based Coherence

**Architecture:** Instead of broadcasting on a bus, directory protocols maintain a centralized (or distributed) directory tracking which caches hold each line. Only the relevant caches receive invalidation messages. Traffic scales with the number of sharers rather than the number of cores.

**Overhead:** Directory entries consume storage (bit-vector per cache line per core). For N cores with M cache lines, the directory requires O(N * M) bits. Various compression techniques (limited pointer directories, coarse directories) reduce this at the cost of precision.

**Relevance to RVM:** Directory-based coherence is the hardware mechanism that enables many-core scaling. RVM's SMP design should account for NUMA effects and directory-based coherence latencies when making scheduling decisions.

### 3.3 Software Coherence Protocols

**Overview:** Software coherence replaces hardware snooping/directory mechanisms with explicit software-managed cache operations. The OS or runtime issues explicit cache flush/invalidate instructions at synchronization points.

**Examples:**
- Linux's explicit DMA coherence management (`dma_map_single` with cache maintenance)
- Barrelfish's message-based coherence (no shared memory, explicit transfers)
- GPU compute models (explicit host-device memory transfers)

**Trade-offs:** Software coherence eliminates hardware complexity but requires programmers (or compilers/runtimes) to correctly manage cache state. Errors lead to stale data or corruption. The benefit is full control over when coherence traffic occurs.

### 3.4 Coherence Signals as Scheduling Inputs -- The RVM Innovation

This is where RVM's design diverges from all existing systems. No existing OS uses coherence metrics as a scheduling signal. RVM's scheduler (ruvix-sched) computes priority as:

```
score = deadline_urgency + novelty_boost - risk_penalty
```

Where `risk_penalty` is derived from the pending coherence delta -- a measure of how much a task's execution would reduce global structural coherence. This is computed using spectral graph theory (Fiedler value, spectral gap, effective resistance) from the `ruvector-coherence` crate.

**Why this matters:** Traditional schedulers optimize for latency, throughput, or fairness. RVM optimizes for structural consistency. A task that would introduce logical contradictions into the system's knowledge graph gets deprioritized. A task processing genuinely novel information gets boosted. This is the right scheduling objective for agent workloads where maintaining a coherent world model is more important than raw throughput.

**No prior art exists** for coherence-driven scheduling in operating systems. The closest analogs are:
- Database transaction schedulers that consider serializability (but these gate on commit, not schedule)
- Network quality-of-service schedulers that consider flow coherence (but this is packet-level, not semantic)
- Game engine entity-component schedulers that consider data locality (but this is cache-coherence, not semantic coherence)

---

## 4. Agent/Edge Computing Runtimes

### 4.1 Wasmtime Bare-Metal Embedding

**Current status:** Wasmtime can be compiled as a no_std Rust crate. The embedder must implement a platform abstraction layer (`wasmtime-platform.h`) specifying how to allocate virtual memory, handle signals, and manage threads.

**Hyperlight precedent:** Microsoft's Hyperlight Wasm project compiles wasmtime into a no_std guest that runs inside micro-VMs with no operating system. This is the strongest proof-of-concept for wasmtime on bare metal.

**Practical considerations:**
- Wasmtime's cranelift JIT compiler works in no_std mode but requires virtual memory for code generation
- The `signals-and-traps` feature can be disabled for platforms without virtual memory support
- Custom memory allocators must be provided via the platform abstraction

**RVM integration path:** RVM's Phase B plan (weeks 35-36) specifies porting wasmtime or wasm-micro-runtime to bare metal. Given Hyperlight's success with no_std wasmtime, wasmtime is the recommended path. The `ruvix-hal` MMU trait can provide the virtual memory abstraction that wasmtime's platform layer requires.

### 4.2 Lunatic (Erlang-Like WASM Runtime)

**What it is:** A universal runtime for server-side applications inspired by Erlang. Actors are represented as WASM instances with per-actor sandboxing and runtime permissions.

**Key features:**
- Preemptive scheduling of WASM processes via work-stealing async executor
- Per-process fine-grained resource access control (filesystem, memory, network) enforced at the syscall level
- Automatic transformation of blocking code into async operations
- Written in Rust using wasmtime and tokio, with custom stack switching

**Agent workload alignment:** Lunatic's actor model closely matches agent workloads:
- Each agent is an isolated WASM instance (Lunatic process)
- Agents communicate through typed message passing
- A failing agent can be restarted without affecting others (supervision trees)
- Different agents can be written in different languages (polyglot via WASM)

**RVM relevance:** Lunatic validates the "agents as lightweight WASM processes" model but runs on top of Linux (tokio for async I/O, wasmtime for WASM). RVM can adopt Lunatic's architectural patterns while eliminating the Linux dependency. Key patterns to adopt:
- Per-agent capability sets (RVM already has this via ruvix-cap)
- Supervision trees for agent fault recovery
- Work-stealing across cores (for Phase C SMP)

### 4.3 How Agent Workloads Differ from Traditional VM Workloads

| Dimension | Traditional VM/Container | Agent Workload |
|-----------|--------------------------|----------------|
| **Lifecycle** | Long-running process | Short-lived reasoning bursts + long idle |
| **State model** | Files and databases | Vectors, graphs, proof chains |
| **Communication** | TCP/Unix sockets | Typed semantic queues with coherence scores |
| **Isolation** | Address space separation | Capability-gated resource access |
| **Failure** | Kill and restart process | Isolate, checkpoint, replay from last coherent state |
| **Scheduling objective** | Fairness / throughput | Coherence preservation / novelty exploration |
| **Memory pattern** | Heap allocation / GC | Append-only regions + slab allocators |
| **Security model** | User/group permissions | Proof-gated mutations with attestation witnesses |

### 4.4 What an Agent-Optimized Hypervisor Needs

Based on the above analysis, an agent-optimized hypervisor requires:

1. **Kernel-native vector/graph stores** -- Agents think in embeddings and knowledge graphs, not files. These must be first-class kernel objects, not userspace libraries serializing to disk.

2. **Coherence-aware scheduling** -- The scheduler must understand that not all runnable tasks should run. A task that would decohere the world model should be delayed.

3. **Proof-gated mutations** -- Every state change must carry a cryptographic witness. This enables checkpoint/replay, audit, and distributed attestation.

4. **Zero-copy typed IPC** -- Agents exchange structured data (vectors, graph patches, proof tokens), not byte streams. The queue abstraction must be typed and schema-aware.

5. **Sub-millisecond task spawn** -- Agent reasoning involves spawning many short-lived sub-tasks. Task creation must be cheaper than thread creation.

6. **Capability delegation without kernel round-trip** -- Agents frequently delegate partial authority. This should be achievable through capability derivation in user space with kernel validation on use.

7. **Deterministic replay** -- For debugging and audit, the kernel must support replaying a sequence of operations and reaching the same state.

All seven of these requirements are already addressed by RVM's architecture (ADR-087).

---

## 5. Graph-Partitioned Scheduling

### 5.1 Min-Cut Based Task Placement

**Theory:** Given a graph where nodes are tasks and edges represent communication volume, the minimum cut partitioning assigns tasks to processors to minimize inter-processor communication. The min-cut objective directly minimizes the scheduling overhead of cross-core data movement.

**Algorithms:**
- Karger's randomized contraction: O(n^2 log n) for global min-cut
- Stoer-Wagner deterministic: O(nm + n^2 log n) for global min-cut
- KaHIP/METIS multilevel: Practical tools for balanced k-way partitioning

**RVM's ruvector-mincut crate** implements subpolynomial dynamic min-cut with self-healing networks, including:
- Exact and (1+epsilon)-approximate algorithms
- j-Tree hierarchical decomposition for multi-level partitioning
- Canonical pseudo-deterministic min-cut (source-anchored, tree-packing, dynamic tiers)
- Agentic 256-core parallel backend
- SNN-based neural optimization (attractor, causal, morphogenetic, strange loop, time crystal)

### 5.2 Spectral Partitioning for Workload Isolation

**Theory:** Spectral partitioning uses the eigenvectors of the graph Laplacian to identify natural clusters. The Fiedler vector (eigenvector corresponding to the second-smallest eigenvalue) provides an optimal bisection -- the Cheeger bound guarantees that spectral bisection produces partitions with nearly optimal conductance.

**RVM's ruvector-coherence spectral module** already implements:
- Fiedler value estimation via inverse iteration with CG solver
- Spectral gap ratio computation
- Effective resistance sampling
- Degree regularity scoring
- Composite Spectral Coherence Score (SCS) with incremental updates

The SpectralTracker supports first-order perturbation updates (`delta_lambda ~ v^T * delta_L * v`) for incremental edge weight changes, avoiding full recomputation on every graph mutation.

### 5.3 Dynamic Graph Rebalancing Under Load

**Challenge:** Static partitioning fails when workload patterns change at runtime. Agents spawn, terminate, and change their communication patterns dynamically.

**Approaches:**
- **Diffusion-based:** Migrate load from overloaded partitions to underloaded neighbors. O(diameter) convergence. Simple but can oscillate.
- **Repartitioning:** Periodically re-run the partitioner on the current communication graph. Expensive but globally optimal.
- **Incremental spectral:** Track the Fiedler vector incrementally (as ruvector-coherence does) and trigger repartitioning only when the spectral gap drops below a threshold.

**RVM design implication:** The scheduler's partition manager (ruvix-sched/partition.rs) currently uses static round-robin partition scheduling with fixed time slices. The spectral coherence infrastructure from ruvector-coherence is already in the workspace (ruvix-sched depends on it optionally via the `coherence` feature flag). The path forward:

1. Monitor the inter-task communication graph using queue message counters
2. Build a Laplacian from the communication weights
3. Compute the SCS incrementally using SpectralTracker
4. When SCS drops below threshold, trigger repartitioning using ruvector-mincut
5. Migrate tasks between partitions based on the new cut

### 5.4 The ruvector-sparsifier Connection

The ruvector-sparsifier crate provides dynamic spectral graph sparsification -- an "always-on compressed world model." For large task graphs, sparsification reduces the graph to O(n log n / epsilon^2) edges while preserving all cuts to within a (1+epsilon) factor. This means the scheduler can maintain an approximate communication graph at dramatically lower cost than the full graph, using it for partitioning decisions.

---

## 6. Existing RuVector Crates Relevant to Hypervisor Design

### 6.1 ruvector-mincut

**Relevance: CRITICAL for graph-partitioned scheduling**

- Provides the algorithmic backbone for task-to-partition assignment
- Subpolynomial dynamic min-cut means the scheduler can re-partition in response to workload changes without O(n^3) overhead
- The j-Tree hierarchical decomposition (feature `jtree`) maps directly to multi-level partition hierarchies
- The canonical min-cut feature provides deterministic partitioning -- the same communication graph always produces the same partition, enabling reproducible scheduling behavior
- SNN integration enables learned partitioning policies

**Integration point:** Wire into ruvix-sched's PartitionManager to dynamically assign new tasks to optimal partitions based on their communication pattern with existing tasks.

### 6.2 ruvector-sparsifier

**Relevance: HIGH for scalable partition management**

- Dynamic spectral sparsification keeps the scheduler's view of the task communication graph manageable as the number of tasks grows
- Static and dynamic modes: static for boot-time graph reduction, dynamic for runtime maintenance
- Preserves all cuts within (1+epsilon), so min-cut-based partition decisions remain valid on the sparsified graph
- SIMD and WASM feature flags for acceleration

**Integration point:** Preprocess the inter-task communication graph through the sparsifier before feeding it to ruvector-mincut for partition computation.

### 6.3 ruvector-solver

**Relevance: HIGH for spectral computations**

- Sublinear-time sparse linear system solver: O(log n) to O(sqrt(n)) for PageRank, Neumann series, forward/backward push, conjugate gradient
- Direct application: solving the graph Laplacian systems needed for Fiedler vector computation and effective resistance estimation
- The CG solver in ruvector-coherence/spectral.rs is a minimal inline implementation; ruvector-solver provides a more optimized, parallel version

**Integration point:** Replace the inline CG solver in spectral.rs with ruvector-solver's optimized implementation for faster coherence score computation in the scheduler hot path.

### 6.4 ruvector-cnn

**Relevance: MODERATE for novelty detection**

- CNN feature extraction for image embeddings with SIMD acceleration
- INT8 quantized inference for resource-constrained environments
- The scheduler's novelty tracker (ruvix-sched/novelty.rs) computes novelty as distance from a centroid in embedding space
- For vision-based agents, ruvector-cnn could provide the embedding that feeds into the novelty computation

**Integration point:** In RVF component space (above the kernel), vision agents use ruvector-cnn for perception. The resulting embedding vectors feed into the kernel's novelty tracker through the `update_task_novelty` syscall.

### 6.5 ruvector-coherence

**Relevance: CRITICAL -- already integrated**

- Provides the coherence measurement primitives that drive the scheduler's risk penalty
- Spectral module computes Fiedler value, spectral gap, effective resistance, degree regularity
- SpectralTracker supports incremental updates (first-order perturbation)
- HnswHealthMonitor provides health alerts when graph coherence degrades
- Already a workspace dependency of ruvix-sched (optional, behind `coherence` feature flag)

**Integration point:** Already wired. The spectral coherence score feeds into `compute_risk_penalty()` in the priority module.

### 6.6 ruvector-raft

**Relevance: HIGH for distributed RVM clusters**

- Raft consensus for distributed metadata coordination
- Relevant for Phase D (distributed RVM mesh, demo 5 in ADR-087)
- Provides leader election, log replication, and consistent state machine application
- Could coordinate partition assignments across a cluster of RVM nodes

**Integration point:** Future use for distributed scheduling consensus in multi-node RVM deployments.

### 6.7 Other Notable Crates

| Crate | Relevance | Use |
|-------|-----------|-----|
| `ruvector-graph` | HIGH | Graph database for task communication topology |
| `ruvector-hyperbolic-hnsw` | MODERATE | Hierarchical embedding search for agent memory |
| `ruvector-delta-consensus` | HIGH | Delta-based consensus for distributed state |
| `ruvector-attention` | MODERATE | Attention mechanisms for priority computation |
| `sona` | MODERATE | Self-optimizing neural architecture for scheduler tuning |
| `ruvector-nervous-system` | LOW | Higher-level coordination (above kernel) |
| `thermorust` | LOW | Thermal monitoring for Raspberry Pi targets |
| `ruvector-verified` | HIGH | ProofGate<T>, ProofEnvironment, attestation chain |

---

## 7. Synthesis: How Each Area Maps to RVM Design Decisions

### 7.1 Decision Matrix

| Research Area | Key Finding | RVM Design Decision | Status |
|---------------|-------------|----------------------|--------|
| Bare-metal Rust | Theseus/RedLeaf prove language isolation viable | Hybrid: type safety (kernel) + MMU (user) | Phase A done, Phase B planned |
| Bare-metal Rust | Hubris shows ~2000-line Rust kernel suffices | Keep nucleus minimal (12 syscalls, ~3000 LOC) | Implemented |
| Bare-metal Rust | Hyperlight proves no_std wasmtime works | Use wasmtime no_std for WASM runtime | Phase B weeks 35-36 |
| Capabilities | seL4 model is the gold standard | ruvix-cap implements seL4-style capabilities | Implemented (54 tests) |
| Capabilities | CHERI is future hardware path | HAL abstraction layer ready for CHERI | Designed, not yet needed |
| Capabilities | TickTock found 5 MPU bugs via verification | Prioritize formal verification of MMU code | Planned |
| Coherence | Barrelfish: make coherence explicit, don't rely on snooping | Per-core schedulers with message-passing (Phase C) | ruvix-smp designed |
| Coherence | No prior art for semantic coherence in scheduling | RVM's coherence-aware scheduler is novel | Implemented (39 tests) |
| Coherence | Spectral methods provide mathematical guarantees | ruvector-coherence spectral module | Implemented |
| Agent runtimes | Lunatic validates actors-as-WASM model | RVF components as capability-gated WASM actors | Designed |
| Agent runtimes | Agent workloads differ fundamentally from VM workloads | 6 primitives + 12 syscalls, no POSIX | Implemented |
| Graph scheduling | Min-cut minimizes cross-partition traffic | Wire ruvector-mincut into partition manager | Designed, not yet wired |
| Graph scheduling | Spectral partitioning gives near-optimal cuts | Already have spectral infrastructure | Implemented |
| Graph scheduling | Dynamic rebalancing needs incremental spectral updates | SpectralTracker supports perturbation updates | Implemented |

### 7.2 Open Research Questions

1. **Formal verification scope:** What subset of the ruvix kernel can be practically verified? The entire ruvix-cap crate is `#![forbid(unsafe_code)]` and is a good candidate. The ruvix-aarch64 crate contains inherent unsafe code (MMU manipulation) that would need different verification techniques (possibly refinement proofs as in seL4).

2. **Coherence signal latency:** Computing spectral coherence scores involves linear algebra (CG solver, power iteration). Can this be fast enough for the scheduling hot path? The inline CG solver in spectral.rs uses 10-15 iterations; benchmarking against ruvector-solver's optimized version is needed.

3. **WASM runtime selection:** Wasmtime's no_std support is proven (Hyperlight) but cranelift JIT requires virtual memory. For the initial Phase B port, should RVM use: (a) wasmtime with cranelift JIT (better performance, needs MMU), (b) wasmtime with winch baseline compiler (simpler, still needs MMU), or (c) wasm-micro-runtime (interpreter, no MMU needed, slower)?

4. **Multi-core coherence architecture:** When Phase C introduces SMP, should the scheduler use: (a) a single shared scheduler with spinlock protection (simple, doesn't scale), (b) per-core schedulers with work-stealing (Lunatic model), or (c) per-core schedulers with message-passing (Barrelfish model)? The Barrelfish data suggests (c) for >8 cores.

5. **Dynamic partition count:** The current PartitionManager uses a compile-time const generic `M` for maximum partitions. Should this be dynamic to support workloads with variable component counts?

### 7.3 Recommended Next Steps

1. **Immediate:** Wire `ruvector-mincut` into `ruvix-sched`'s PartitionManager for dynamic task-to-partition assignment based on communication graph analysis.

2. **Phase B priority:** Study Hyperlight's wasmtime no_std integration for the bare-metal WASM runtime port. The `wasmtime-platform.h` abstraction maps cleanly to `ruvix-hal` traits.

3. **Verification:** Begin formal verification of `ruvix-cap` using Kani (Rust model checker) or Creusot. The `#![forbid(unsafe_code)]` constraint makes this tractable.

4. **Benchmarking:** Measure spectral coherence computation latency in the scheduling hot path. If too slow, implement a fast-path approximation that falls back to full computation periodically (the SpectralTracker already supports this with `refresh_threshold`).

5. **Phase C design:** Adopt Barrelfish's per-core kernel model for SMP. The `ruvix-smp` crate's topology and IPI infrastructure is already aligned with this approach.

---

## 8. References

### Bare-Metal Rust OS Projects

- [RustyHermit GitHub](https://github.com/hermit-os/hermit-rs)
- [Theseus OS GitHub](https://github.com/theseus-os/Theseus)
- [Theseus: an Experiment in Operating System Structure and State Management, OSDI 2020](https://www.usenix.org/conference/osdi20/presentation/boos)
- [RedLeaf: Isolation and Communication in a Safe Operating System, OSDI 2020](https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram)
- [Tock OS GitHub](https://github.com/tock/tock)
- [TickTock: Verified Isolation in a Production Embedded OS, 2025](https://patpannuto.com/pubs/rindisbacher2025tickTock.pdf)
- [Hubris GitHub (Oxide Computer)](https://github.com/oxidecomputer/hubris)
- [Hubris and Humility (Oxide blog)](https://oxide.computer/blog/hubris-and-humility)
- [Redox OS](https://www.redox-os.org/)
- [Redox OS 2025-2026 Roadmap](https://www.webpronews.com/redox-os-2025-2026-roadmap-arm-support-security-boosts-and-variants/)
- [Hyperlight Wasm: Fast, Secure, and OS-free (Microsoft, March 2025)](https://opensource.microsoft.com/blog/2025/03/26/hyperlight-wasm-fast-secure-and-os-free/)
- [Hyperlight: 0.0009-second micro-VM execution time (Microsoft, Feb 2025)](https://opensource.microsoft.com/blog/2025/02/11/hyperlight-creating-a-0-0009-second-micro-vm-execution-time/)

### Capability-Based Systems

- [seL4 Whitepaper](https://sel4.systems/About/seL4-whitepaper.pdf)
- [seL4: Formal Verification of an OS Kernel, SOSP 2009](https://www.sigops.org/s/conferences/sosp/2009/papers/klein-sosp09.pdf)
- [Running Rust programs in seL4 using sel4-sys (Antmicro)](https://antmicro.com/blog/2022/08/running-rust-programs-in-sel4)
- [CHERI: Hardware-Enabled Memory Safety (IEEE S&P 2024)](https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/20240419-ieeesp-cheri-memory-safety.pdf)
- [ARM Morello Evaluation Platform (IEEE Micro 2023)](https://ieeexplore.ieee.org/document/10123148/)
- [A CHERI C Memory Model for Verified Temporal Safety (CPP 2025)](https://popl25.sigplan.org/details/CPP-2025-papers/8/A-CHERI-C-Memory-Model-for-Verified-Temporal-Safety)
- [CHERI Performance on Arm Morello (2025)](https://ieeexplore.ieee.org/document/11242069/)

### Multikernel and Coherence

- [The Multikernel: A New OS Architecture for Scalable Multicore Systems, SOSP 2009](https://people.inf.ethz.ch/troscoe/pubs/sosp09-barrelfish.pdf)
- [Barrelfish Architecture Overview](https://barrelfish.org/publications/TN-000-Overview.pdf)
- [Demystifying Cache Coherency in Modern Multiprocessor Systems (2025)](https://eajournals.org/wp-content/uploads/sites/21/2025/06/Demystifying.pdf)
- [Cache Coherence Protocols: MESI, MOESI, and Directory-Based Systems](https://eureka.patsnap.com/article/cache-coherence-protocols-mesi-moesi-and-directory-based-systems)

### Agent/WASM Runtimes

- [Wasmtime no_std support (Issue #8341)](https://github.com/bytecodealliance/wasmtime/issues/8341)
- [Lunatic: Erlang-Inspired Runtime for WebAssembly](https://github.com/lunatic-solutions/lunatic)
- [FOSDEM 2025: Redox OS -- a Microkernel-based Unix-like OS](https://archive.fosdem.org/2025/schedule/event/fosdem-2025-5973-redox-os-a-microkernel-based-unix-like-os/)

### Graph Partitioning

- [An Improved Spectral Graph Partitioning Algorithm (SIAM Journal on Scientific Computing)](https://epubs.siam.org/doi/10.1137/0916028)
- [Workload Scheduling in Distributed Stream Processors Using Graph Partitioning (IEEE)](https://ieeexplore.ieee.org/document/7363749/)
- [Distributed Framework for High-Quality Graph Partitioning (2025)](https://link.springer.com/article/10.1007/s11227-025-07907-2)

### RVM Internal

- ADR-087: RVM Cognition Kernel (docs/adr/ADR-087-ruvix-cognition-kernel.md)
- ADR-014: Coherence Engine Architecture (docs/adr/ADR-014-coherence-engine.md)
- ADR-029: RVF Canonical Format
- ADR-047: Proof-Gated Mutation Protocol
- ruvix workspace: crates/ruvix/ (22 internal crates)
- ruvector-mincut: crates/ruvector-mincut/
- ruvector-sparsifier: crates/ruvector-sparsifier/
- ruvector-solver: crates/ruvector-solver/
- ruvector-coherence: crates/ruvector-coherence/
- ruvector-raft: crates/ruvector-raft/
