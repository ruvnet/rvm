# Comparative Analysis Research Topics

**Date**: 2026-04-04
**Scope**: Four comparison studies between RVM and existing systems

---

## R7: RVM vs seL4 — Capability Models and Formal Verification Gap

**Question**: How does RVM's capability model map onto seL4's CNode/CSlot model, and what security properties does RVM lack due to the absence of formal verification?

**Relevance**: RVM's capability system (ADR-135) is explicitly inspired by seL4. Both use unforgeable tokens with monotonic attenuation and bounded delegation. However, RVM diverges from seL4 in several ways that have security implications.

**Key Comparison Points**:

| Aspect | seL4 | RVM | Implication |
|--------|------|-----|-------------|
| Capability storage | CNode/CSlot (tree-structured) | Flat capability table (per-partition) | RVM's flat table is simpler but lacks seL4's hierarchical revocation efficiency |
| Rights model | 18+ rights (platform-specific) | 7 rights (u8 bitmap) | RVM is more constrained; some seL4 operations have no RVM equivalent |
| Delegation depth | Unbounded (CDT tracks all derivations) | Bounded at 8 (ADR-135) | RVM trades flexibility for bounded revocation cost |
| Revocation | CDT walk (O(n) in derivation tree) | Epoch-based (O(d) in descendants) | RVM's epoch-based approach is faster but less precise |
| Formal verification | Full functional correctness (Isabelle/HOL) | Deferred (ADR-154 roadmap) | RVM cannot make the same security claims as seL4 until verification is complete |
| Concurrency | Single-core verified; multicore is recent | SMP from v1 (ADR-146) | seL4's multicore verification is partial; RVM's is not started |

**Approach**: (1) Map each seL4 CNode operation (mint, copy, mutate, delete, revoke) to its RVM equivalent. (2) Identify operations that seL4 supports but RVM does not (e.g., badge-based identification, endpoint capabilities). (3) For each gap, assess whether the gap is a security risk or a deliberate simplification. (4) Quantify the verification gap: which seL4-verified properties does RVM's proptest suite cover vs not cover?

**Expected Outcome**: A mapping table of seL4-to-RVM capability operations with security impact annotations, plus a gap analysis identifying properties that require formal verification before safety-critical deployment.

---

## R8: RVM vs Firecracker — Boot Time, Partition Switch, and Memory Model

**Question**: How does RVM's performance compare to Firecracker across the critical path metrics (boot, switch, memory efficiency)?

**Relevance**: Firecracker (AWS) is the closest existing system to RVM in terms of minimalism and use case (lightweight isolation for serverless/edge workloads). RVM targets different abstraction (coherence domains vs microVMs), but the performance characteristics must be competitive or the coherence advantage is moot.

**Key Comparison Points**:

| Metric | Firecracker | RVM Target | Notes |
|--------|------------|------------|-------|
| Cold boot to first user code | ~125ms (KVM + minimal Linux guest) | <250ms (bare-metal, no KVM) | RVM has no Linux dependency but also no KVM fast path |
| VM/partition switch | ~10us (KVM VMRUN/VMEXIT) | <10us (bare-metal EL2 switch) | RVM avoids KVM ioctl overhead but must manage stage-2 tables directly |
| Memory overhead per instance | ~5MB (minimal initrd) | TBD (partition metadata + capability table) | RVM targets smaller per-partition overhead |
| Max instances | ~4000 microVMs per host (Firecracker paper) | DC-12: 4096 logical, 256 physical | RVM multiplexes logical partitions over VMID slots |
| Network I/O | virtio-net (KVM passthrough) | Not yet specified (ADR-153 scope) | Firecracker has mature I/O; RVM defers to post-v1 |
| GPU support | None | ADR-144 (capability-gated) | RVM advantage |
| Formal verification | None | ADR-154 roadmap | Neither is verified today |

**Approach**: (1) Set up identical QEMU AArch64 virt environments for Firecracker and RVM. (2) Measure cold boot time with PMU cycle counters. (3) Measure partition/VM switch latency under identical workloads (ping-pong IPC between two instances). (4) Measure memory overhead with increasing instance counts (1, 10, 100, 1000). (5) Document the methodology for reproducibility (ADR-143 benchmark framework).

**Expected Outcome**: A benchmark comparison table with methodology documentation, identifying where RVM beats Firecracker (switch latency, GPU, per-partition overhead) and where it trails (boot time, I/O maturity).

---

## R9: RVM vs CFS/EEVDF — Scheduling Algorithms

**Question**: How does RVM's coherence-aware 2-signal scheduler (deadline_urgency + cut_pressure_boost) compare to Linux CFS and EEVDF under equivalent workloads?

**Relevance**: ADR-132 DC-4 defines RVM's v1 scheduler as deliberately simple: two signals only. Linux CFS (Completely Fair Scheduler) uses virtual runtime-based fairness, and EEVDF (Earliest Eligible Virtual Deadline First) is the newer replacement. RVM's scheduler optimizes for coherence locality, not fairness. This is a fundamentally different objective, and the comparison must account for this.

**Key Comparison Points**:

| Aspect | CFS | EEVDF | RVM |
|--------|-----|-------|-----|
| Objective | CPU fairness (virtual runtime) | Fairness + latency (eligible virtual deadline) | Coherence locality (cut pressure + deadline) |
| Fairness guarantee | Proportional share | Bounded latency | None (not a goal) |
| Context switch frequency | Adaptive (granularity knob) | Adaptive | Per-epoch (configurable, default 1ms) |
| Workload awareness | Weight-based nice levels | Deadline-aware | Graph-structure-aware |
| Tail latency | Depends on load | Bounded by deadline | Depends on cut pressure distribution |
| Multi-core | Per-CPU runqueue + load balancing | Same | Per-CPU scheduler + coherence CPU (ADR-146) |

**Approach**: (1) Implement a workload simulator that generates partition communication patterns (uniform, hotspot, producer-consumer, graph-structured). (2) For each pattern, simulate CFS, EEVDF, and RVM scheduling decisions. (3) Measure: tail latency (p99), throughput (completed operations per second), remote memory traffic (cross-partition accesses that could have been local). (4) RVM should win on remote traffic reduction; CFS/EEVDF should win on fairness. Quantify the tradeoff.

**Expected Outcome**: Simulation results showing the coherence-locality vs fairness tradeoff, with recommendations for workload classes where RVM's scheduler is advantageous.

---

## R10: RVM vs zswap/zram — Memory Compression vs Witness Reconstruction

**Question**: How does RVM's 4-tier memory model (with dormant-tier compression and cold-tier reconstruction) compare to Linux zswap/zram for memory-constrained workloads?

**Relevance**: Both RVM and zswap/zram address the problem of fitting more workload into limited physical memory. zswap compresses pages in a kernel-managed pool before writing to swap. zram compresses pages into a RAM-backed block device. RVM's approach is fundamentally different: dormant-tier pages are compressed, but cold-tier pages are not stored at all -- they are reconstructed from checkpoints plus witness replay (ADR-134 Section 7, ADR-136).

**Key Comparison Points**:

| Aspect | zswap | zram | RVM Dormant/Cold |
|--------|-------|------|------------------|
| Compression algorithm | LZO, LZ4, zstd (configurable) | LZO, LZ4, zstd | LZ4 (dormant tier) |
| Decompression latency | ~1-10us per page | ~1-10us per page | ~1-10us (dormant), ~1-100ms (cold, replay) |
| Memory savings | 2-3x compression ratio | 2-3x compression ratio | 2-3x (dormant), unbounded (cold, reconstructed) |
| Correctness guarantee | Byte-identical decompression | Byte-identical decompression | Depends on replay fidelity (R3) |
| Eviction policy | LRU | LRU | Cut-value + recency (coherence-aware) |
| Recovery from eviction | Read from swap device | Decompress from RAM | Replay from checkpoint |
| CPU cost | Compression + decompression | Compression + decompression | Compression (dormant) + SHA-256 replay (cold) |

**Approach**: (1) Set up identical memory-constrained environments (256MB, 512MB, 1GB) running equivalent workloads. (2) For zswap/zram: measure throughput and tail latency with varying compression algorithms. (3) For RVM: measure throughput and tail latency with coherence-aware demotion to dormant and cold tiers. (4) Measure the reconstruction latency distribution for cold-tier pages (this is unique to RVM and has no zswap equivalent). (5) Compare total memory efficiency: how many concurrent partitions can run within the memory budget?

**Expected Outcome**: A benchmark comparison showing RVM's advantage in total memory efficiency (cold-tier reconstruction allows more partitions than compression alone) and disadvantage in cold-tier access latency (replay is slower than decompression).

---

## Cross-References

- ADR-132: RVM Hypervisor Core (scheduler, memory model, design constraints)
- ADR-134: Witness Schema and Log Format (replay protocol for cold-tier reconstruction)
- ADR-135: Proof Verifier Design (capability model for seL4 comparison)
- ADR-136: Memory Hierarchy and Reconstruction (4-tier model)
- ADR-144: GPU Compute Support (GPU advantage over Firecracker)
- ADR-146: SMP and Per-CPU Scheduling (multi-core scheduler design)
- ADR-154: Formal Verification Roadmap (verification gap vs seL4)
