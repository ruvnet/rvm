# Theoretical Foundation Research Topics

**Date**: 2026-04-04
**Scope**: Six open research questions on the theoretical underpinnings of the RVM hypervisor

---

## R1: Coherence Convergence Guarantees

**Question**: Does the EMA-filtered coherence score converge for all input distributions, and what is the convergence rate?

**Relevance**: The coherence engine (ADR-132, ADR-141) uses an exponential moving average (EMA) filter over inter-partition communication weights to compute coherence scores. If the filter does not converge under certain workload patterns (e.g., periodic bursts, adversarial access patterns), the mincut-based placement decisions may oscillate, causing unnecessary partition migrations.

**Prior Work**: EMA convergence is well-understood for stationary stochastic processes. The open question is whether RVM's communication patterns are sufficiently stationary, or whether the coherence graph's topology changes (partition creation, destruction, split, merge) introduce non-stationarities that break convergence assumptions.

**Approach**: (1) Model the communication weight update as a discrete-time dynamical system. (2) Identify conditions on the update rate and graph topology change rate under which the EMA filter converges to a fixed point or limit cycle. (3) Simulate with synthetic workload traces (periodic, bursty, adversarial) and measure convergence time and oscillation amplitude. (4) If oscillation is detected, evaluate damping strategies (e.g., increasing EMA alpha, adding hysteresis to split/merge thresholds).

**Expected Outcome**: A theorem or empirical bound on convergence time as a function of EMA alpha and graph mutation rate, plus a recommendation for default alpha values.

---

## R2: MinCut Budget Analysis

**Question**: For the Stoer-Wagner algorithm on N nodes with E edges, what is the exact worst-case execution time on the target hardware, and what is the optimal iteration count for the DC-2 budget?

**Relevance**: ADR-132 DC-2 mandates a 50-microsecond hard budget for mincut per scheduler epoch. The Stoer-Wagner algorithm has complexity O(VE + V^2 log V). For MINCUT_MAX_NODES=32 (ADR-132), the worst case is a fully connected graph with E = 32*31/2 = 496 edges. The question is whether this worst case fits within 50us on the target hardware (ARM Cortex-A72 at 1.5GHz for Appliance, Cortex-M33 for Seed).

**Prior Work**: Stoer-Wagner runtime on modern hardware has been benchmarked for large graphs (thousands of nodes) but not characterized at the micro-level for small, cache-resident graphs. RVM's use case (N <= 32, cache-hot adjacency matrix) is unusual.

**Approach**: (1) Implement a cycle-accurate benchmark of the CPU mincut path on Cortex-A72 (QEMU + PMU counters). (2) Measure worst-case latency for fully connected 32-node graphs. (3) If the worst case exceeds 50us, determine the maximum N that fits within the budget. (4) Evaluate whether the GPU path (ADR-144, ADR-152) extends the feasible N.

**Expected Outcome**: A table mapping N to worst-case mincut latency on each target platform, plus a recommendation for MINCUT_MAX_NODES per hardware profile.

---

## R3: Reconstruction Fidelity

**Question**: Under what conditions does checkpoint + witness replay produce byte-identical state to the original execution?

**Relevance**: ADR-134 Section 7 defines the replay protocol: given a checkpoint and a witness log segment, replaying the segment deterministically reconstructs the kernel state. This is the foundation of RVM's recovery model (F2 failure class, ADR-132 DC-14). If reconstruction is not byte-identical, recovered partitions may exhibit different behavior than the original, violating deterministic recovery.

**Prior Work**: Deterministic replay systems (e.g., rr, PANDA) achieve byte-identical replay for single-threaded programs. Multi-threaded and hardware-interacting systems introduce non-determinism (interrupt timing, device state, MMIO responses) that breaks replay fidelity.

**Approach**: (1) Enumerate sources of non-determinism in RVM's privileged action path: timer interrupt timing, MMIO device responses, random number generation. (2) For each source, determine whether the witness record captures sufficient information to reproduce the non-determinism during replay. (3) Construct a test: checkpoint, run N privileged actions, replay from checkpoint, compare final state. (4) Identify and document any actions that are not replay-faithful and propose mitigation (e.g., recording timer values in the witness payload).

**Expected Outcome**: A proof (or counterexample) that checkpoint + witness replay is byte-identical for all privileged actions, plus a list of actions requiring additional replay data.

---

## R4: Proof Tier Latency Bounds

**Question**: Can the P1 <1us, P2 <100us, and P3 <10ms latency budgets (ADR-135 DC-3) be formally justified, and are they achievable on all target hardware?

**Relevance**: These budgets are currently engineering estimates based on implementation analysis (ADR-135 provides a cost breakdown for P1 and P2). A formal argument would strengthen confidence that the budgets are not arbitrary but are derived from the operations required at each tier.

**Prior Work**: seL4 provides worst-case execution time (WCET) analysis for its syscall paths on ARM. RVM's P1 (table lookup + bitmap AND) is structurally similar to seL4's capability lookup. P2 (8 constant-time checks) is more complex but still bounded.

**Approach**: (1) For P1: count the maximum number of instructions in the verify_p1() path. Multiply by the worst-case cycles-per-instruction on each target. Verify <1us. (2) For P2: same analysis, accounting for the constant-time execution of all 8 checks (no early exit). Include SHA-256 cost for mutation hash comparison (ADR-142). (3) For P3: bound the cost of SHA-256 preimage check, Merkle path verification (log N hashes for depth-N tree), and Ed25519 signature verification. (4) Validate on QEMU with PMU cycle counters.

**Expected Outcome**: WCET bounds for P1, P2, P3 on each target platform, with a formal argument that the bounds hold for all input sizes.

---

## R5: Memory Tier Transition Optimality

**Question**: When is demotion (moving a page to a colder tier) better than eviction (freeing the page entirely), and what is the optimal transition threshold?

**Relevance**: ADR-136 defines a 4-tier memory model (hot/warm/dormant/cold). The transition decision between tiers is driven by cut-value and recency score. However, the optimal threshold for demotion vs eviction depends on the probability that the page will be re-accessed, the cost of reconstruction from a colder tier, and the memory pressure from other partitions.

**Prior Work**: Traditional page replacement algorithms (LRU, CLOCK, LRU-K) optimize for hit rate. RVM's model adds two dimensions: (1) the coherence graph's cut-value, which predicts cross-partition access patterns, and (2) the reconstruction cost, which varies by tier (warm: decompress, dormant: decompress + replay, cold: full checkpoint restore).

**Approach**: (1) Model the tier transition decision as a cost-minimization problem: minimize expected_access_latency + memory_pressure_penalty. (2) Derive the optimal demotion threshold as a function of re-access probability and reconstruction cost. (3) Simulate with synthetic and real workload traces. (4) Compare RVM's coherence-aware demotion against LRU and LRU-K baselines.

**Expected Outcome**: A formula for the optimal demotion threshold as a function of cut-value, recency, and tier-specific reconstruction cost, plus simulation results comparing against baselines.

---

## R6: GPU Acceleration Speedup Model

**Question**: What is the theoretical speedup from GPU-accelerated mincut and batch scoring, modeled via Amdahl's law?

**Relevance**: ADR-144 claims 5.6x speedup for 32-node mincut and up to 32x for batch scoring of 1024 partitions. These targets are based on algorithmic analysis (O(N^3) vs O(N^2 log N) for mincut, O(P) vs O(1) for scoring). A formal Amdahl's law analysis would determine the actual system-level speedup, accounting for the serial fraction (data upload, result download, GPU launch overhead).

**Prior Work**: Amdahl's law provides the upper bound on speedup: S = 1 / (s + p/N), where s is the serial fraction, p is the parallel fraction, and N is the number of parallel processors. For GPU workloads, the serial fraction includes kernel launch overhead (~10us per ADR-144), host-device memory transfer, and result readback.

**Approach**: (1) Decompose the mincut and scoring workloads into serial and parallel fractions. (2) Measure the serial overhead (launch, transfer) on target GPU hardware. (3) Compute the Amdahl's law speedup bound for each workload at varying N. (4) Compare against the empirical benchmarks from ADR-144 Table 9. (5) Determine the crossover point: the minimum N at which GPU acceleration beats the CPU path.

**Expected Outcome**: Amdahl's law speedup curves for mincut and scoring as a function of N, plus the crossover N for each workload. This informs the GPU auto-selection threshold in the coherence engine.

---

## Cross-References

- ADR-132: RVM Hypervisor Core (DC-2 mincut budget, DC-3 proof tiers, DC-14 failure classes)
- ADR-134: Witness Schema and Log Format (replay protocol)
- ADR-135: Proof Verifier Design (P1/P2/P3 latency budgets)
- ADR-136: Memory Hierarchy and Reconstruction (4-tier model)
- ADR-141: Coherence Engine Kernel Integration (EMA filter, coherence scoring)
- ADR-144: GPU Compute Support (GPU acceleration targets)
- ADR-152: GPU MinCut Correctness Model (GPU/CPU equivalence)
