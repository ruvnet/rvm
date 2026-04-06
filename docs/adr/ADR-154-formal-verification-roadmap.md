# ADR-154: Formal Verification Roadmap

**Status**: Draft
**Date**: 2026-04-04
**Authors**: Claude Code (Opus 4.6)
**Supersedes**: None
**Related**: ADR-132 (RVM Hypervisor Core), ADR-135 (Proof Verifier Design), ADR-134 (Witness Schema), ADR-142 (TEE-Backed Verification)

---

## Context

ADR-132 explicitly lists formal verification as a non-goal for v1: "Full formal verification (deferred to post-v1; seL4-style proofs are multi-year efforts)." This is the correct phasing -- seL4's initial verification effort took approximately 20 person-years and targeted a much smaller codebase (~10,000 lines of C). RVM is substantially larger and more complex. However, the absence of formal verification does not mean the absence of a plan for it.

This ADR establishes which subsystems are candidates for formal verification, in what priority order, using which tools, and through what incremental approach. It is a roadmap, not a commitment to any specific verification timeline.

### Problem Statement

1. **Safety-critical adoption requires verification evidence**: Domains such as automotive (ISO 26262), aerospace (DO-178C), and medical devices (IEC 62304) require evidence of correctness beyond testing. Formal verification provides the strongest such evidence.
2. **Not all subsystems need verification equally**: The capability system's monotonic attenuation property is a simple enough invariant to verify with bounded model checking. The scheduler's interaction with the coherence engine is too complex for current tools. Prioritization is essential.
3. **Rust tooling is maturing**: Kani (Amazon), Prusti (ETH Zurich), and MIRAI (Facebook) provide Rust-specific verification capabilities that did not exist when seL4 was verified. The barrier to entry is lower than it was for C-based kernels.
4. **Property-based testing is a stepping stone**: Before investing in full model checking, property-based testing (via `proptest` or `bolero`) can discover invariant violations cheaply. Properties that survive extensive proptest campaigns are good candidates for formal proof.

### SOTA References

| Source | Key Contribution | Relevance |
|--------|-----------------|-----------|
| seL4 (Klein et al., 2009) | First formally verified OS kernel | Gold standard; informs what is achievable and what it costs |
| Kani (Amazon) | Rust model checker using CBMC | Primary tool candidate for bounded verification of RVM |
| Prusti (ETH Zurich) | Rust verifier based on Viper framework | Pre/post-condition verification for Rust functions |
| MIRAI (Meta) | Abstract interpretation for Rust | Tag analysis and reachability checking |
| Ferrocene (AdaCore + Ferrous) | Qualified Rust compiler for safety-critical systems | Provides the compiler qualification needed for certified deployments |
| CertiKOS (Gu et al., 2016) | Verified concurrent OS kernel in Coq | Demonstrates verification of concurrent kernel with hardware interaction |

---

## Decision

Establish a four-priority verification roadmap. Begin with property-based testing for all priorities. Graduate Priority 1 to model checking (Kani) as a pilot. Expand to other priorities based on pilot results.

### Priority 1: Capability Attenuation Monotonicity (rvm-cap)

**Property**: A derived capability never has more rights than its parent. Formally:

```
forall cap_parent, cap_child:
    derive(cap_parent, new_rights) = Some(cap_child)
    implies
    cap_child.rights.is_subset_of(cap_parent.rights)
```

**Why Priority 1**: This is the foundational security invariant. If attenuation is violated, a partition can escalate its privileges. The property is simple (subset relation on a u8 bitmap), the code is small (~200 lines in `rvm-cap/src/capability.rs`), and the state space is bounded (7 rights, depth <= 8).

**Verification approach**:

| Phase | Tool | What It Proves | Effort |
|-------|------|----------------|--------|
| Phase A | proptest | No counterexample found in 10M random derivation chains | 1 week |
| Phase B | Kani | Bounded proof for all u8 right combinations, depth 1-8 | 2 weeks |
| Phase C | Prusti (optional) | Pre/post-condition annotation on `derive()` | 1 week |

**Kani harness sketch**:

```rust
#[kani::proof]
fn verify_monotonic_attenuation() {
    let parent_rights: u8 = kani::any();
    let child_rights: u8 = kani::any();
    let parent = Capability {
        rights: CapRights(parent_rights),
        // ... other fields symbolic
    };

    if let Some(child) = derive(&parent, CapRights(child_rights), 0, &tree) {
        assert!(child.rights.is_subset_of(parent.rights));
    }
}
```

### Priority 2: Witness Chain Integrity (rvm-witness)

**Property**: If any witness record in the chain is modified after emission, the chain verification detects the modification. Formally:

```
forall chain[0..N], i in 0..N:
    tamper(chain[i]) implies
    verify_chain(chain) = Err(ChainBreak { index: i })
```

**Why Priority 2**: The witness chain is the audit backbone. If chain integrity can be silently violated, the entire auditability guarantee collapses. The property involves SHA-256 hash chaining (ADR-142), which is deterministic and bounded.

**Verification approach**:

| Phase | Tool | What It Proves | Effort |
|-------|------|----------------|--------|
| Phase A | proptest | Tampering any byte in any record is detected for chains of length 1-1000 | 1 week |
| Phase B | Kani | Bounded proof for chains of length 1-16 with symbolic record contents | 3 weeks |

**Challenges**: SHA-256 computation is expensive for symbolic execution. Kani may require abstraction of the hash function (replace SHA-256 with a symbolic collision-resistant function) to keep verification tractable.

### Priority 3: Partition Lifecycle State Machine (rvm-partition)

**Property**: Partitions transition only through valid states, and no transition produces a state that violates isolation. Formally:

```
forall partition, event:
    transition(partition.state, event) = new_state
    implies
    new_state in VALID_STATES
    and
    isolation_invariant(partition, new_state) holds
```

The valid states are: `Created`, `Running`, `Suspended`, `Hibernated`, `Migrating`, `Splitting`, `Merging`, `Destroyed`. The isolation invariant requires that no two partitions share a mutable memory region without an explicit CommEdge and capability grant.

**Why Priority 3**: The partition lifecycle is the core abstraction. Invalid transitions (e.g., `Destroyed` -> `Running`) could resurrect a partition with stale capabilities, violating isolation.

**Verification approach**:

| Phase | Tool | What It Proves | Effort |
|-------|------|----------------|--------|
| Phase A | proptest + state machine testing | No invalid transition reachable from any state via random event sequences | 2 weeks |
| Phase B | Kani | Bounded proof that the transition function preserves the isolation invariant for all state/event combinations | 4 weeks |

### Priority 4: Memory Isolation (rvm-memory)

**Property**: No two partitions can access the same physical page unless they share a memory region with appropriate capabilities. Formally:

```
forall p1, p2, page:
    p1 != p2
    and maps(p1, page) and maps(p2, page)
    implies
    exists region, cap:
        shared_region(region, p1, p2)
        and region.contains(page)
        and cap.rights.contains(READ or WRITE)
```

**Why Priority 4**: Memory isolation is a hardware-enforced property (stage-2 page tables on ARM, EPT on x86). The verification target is the page table construction logic in `rvm-memory`, not the hardware itself. This is the most complex verification target because it involves page table walks, physical address arithmetic, and IOMMU configuration.

**Verification approach**:

| Phase | Tool | What It Proves | Effort |
|-------|------|----------------|--------|
| Phase A | proptest | `regions_overlap_host()` returns true for all overlapping regions, false for all non-overlapping | 2 weeks |
| Phase B | Kani | Bounded proof for page tables with up to 64 entries | 6 weeks |
| Phase C | MIRAI | Abstract interpretation of the full page table construction path | 4 weeks |

---

## Tool Evaluation

### Kani (Primary Recommendation)

Kani is Amazon's Rust model checker, built on CBMC (C Bounded Model Checker). It verifies Rust code by translating it to a verification IR and exhaustively checking all paths up to a bounded depth.

| Aspect | Assessment |
|--------|-----------|
| Rust support | Native; understands ownership, borrowing, lifetimes |
| no_std compatibility | Yes; works with `#![no_std]` crates |
| Bounded verification | Up to configurable depth; sufficient for RVM's bounded data structures |
| Performance | Practical for functions with up to ~1000 lines and bounded loops |
| Maturity | Production use at Amazon; actively maintained |
| Limitations | Cannot verify unbounded loops; SHA-256 symbolic execution is expensive |

### Prusti (Secondary)

Prusti is ETH Zurich's Rust verifier, built on the Viper verification framework. It verifies pre/post-conditions annotated on Rust functions.

| Aspect | Assessment |
|--------|-----------|
| Annotation style | Rust attributes (`#[requires(...)]`, `#[ensures(...)]`) |
| Verification power | Function-level pre/post-conditions, loop invariants |
| no_std compatibility | Partial; some standard library annotations missing |
| Maturity | Research tool; less production-hardened than Kani |
| Best for | Annotating and verifying individual functions (derive, verify_p1) |

### MIRAI (Supplementary)

MIRAI is Meta's abstract interpretation tool for Rust. It performs tag analysis and reachability checking at the MIR level.

| Aspect | Assessment |
|--------|-----------|
| Analysis type | Abstract interpretation (over-approximation) |
| False positives | Expected; requires manual triage |
| Speed | Fast; can analyze entire crates in seconds |
| Best for | Finding unreachable code, tag-based security analysis |

---

## Relationship to seL4

seL4's formal verification provides a useful reference point, but RVM's approach differs in several important ways:

| Aspect | seL4 | RVM |
|--------|------|-----|
| Language | C + Isabelle/HOL | Rust + Kani/Prusti |
| Verification scope | Full functional correctness of kernel | Targeted properties of critical subsystems |
| Effort | ~20 person-years (initial) | Estimated 2-6 person-months per priority |
| Compiler trust | Verified C-to-ARM compilation chain | Ferrocene qualified compiler (future) |
| Hardware model | Formal ARM model | Hardware assumed correct; verify software logic |
| Concurrency | Single-core only (initial) | Single-core properties first; SMP deferred |

RVM does not aim to replicate seL4's full functional correctness proof. Instead, it targets the four specific properties above, which together cover the critical security and integrity invariants. This is a pragmatic choice: targeted verification of critical properties provides high assurance value at a fraction of the cost of full verification.

---

## Incremental Approach

The verification roadmap follows a "test, then prove" methodology:

```
Step 1: Property-based testing (proptest/bolero)
    - Define the property as a proptest strategy
    - Run 10M+ test cases
    - Fix any violations found
    - Commit the proptest as a regression test

Step 2: Bounded model checking (Kani)
    - Write a Kani proof harness for the same property
    - Run Kani with increasing bounds until verification completes or times out
    - If Kani times out, identify the bottleneck and abstract it
    - Commit the Kani harness as a CI verification step

Step 3: Annotation-based verification (Prusti, optional)
    - Annotate the function with pre/post-conditions
    - Verify with Prusti
    - Annotations serve as machine-checked documentation

Step 4: Continuous verification
    - Kani harnesses run in nightly CI (ADR-143)
    - Any code change that breaks a verified property fails the pipeline
    - New properties are added incrementally as subsystems mature
```

---

## Consequences

### Positive

1. **Clear prioritization**: Four priorities ordered by security impact and verification tractability. Prevents the "verify everything or nothing" trap.
2. **Incremental approach**: Property-based testing provides immediate value. Formal verification builds on tested properties, reducing wasted verification effort.
3. **Tool diversity**: Three complementary tools (Kani, Prusti, MIRAI) cover different verification niches. No single-tool dependency.
4. **CI integration**: Verification harnesses become regression tests, preventing future regressions of verified properties.

### Negative

1. **Not full functional correctness**: The roadmap verifies four specific properties, not the entire kernel. Bugs outside these properties remain undetected by formal methods.
2. **Tool maturity risk**: Kani and Prusti are actively developed but not yet as mature as Isabelle/HOL (seL4's verifier). Tool bugs could produce false confidence.
3. **Ongoing maintenance cost**: Verification harnesses must be updated when the verified code changes. This adds friction to development.

---

## Timeline Estimate

| Priority | Phase A (proptest) | Phase B (Kani) | Phase C (Optional) | Total |
|----------|-------------------|----------------|-------------------|-------|
| P1: Capability attenuation | 1 week | 2 weeks | 1 week (Prusti) | 4 weeks |
| P2: Witness chain integrity | 1 week | 3 weeks | -- | 4 weeks |
| P3: Partition lifecycle | 2 weeks | 4 weeks | -- | 6 weeks |
| P4: Memory isolation | 2 weeks | 6 weeks | 4 weeks (MIRAI) | 12 weeks |

**Total estimated effort**: 26 person-weeks (~6 person-months) for all four priorities. This assumes one engineer with verification experience.

---

## References

- Klein, G., et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009.
- Gu, R., et al. "CertiKOS: An Extensible Architecture for Building Certified Concurrent OS Kernels." OSDI 2016.
- Kani Rust Verifier: https://model-checking.github.io/kani/
- Prusti: https://www.pm.inf.ethz.ch/research/prusti.html
- MIRAI: https://github.com/facebookexperimental/MIRAI
- Ferrocene: https://ferrocene.dev/
- ADR-132: RVM Hypervisor Core (non-goals: formal verification deferred)
- ADR-135: Proof Verifier Design (capability model, monotonic attenuation)
- ADR-134: Witness Schema and Log Format (hash chain integrity)
- `rvm-cap/src/capability.rs`: Capability derive() implementation
- `rvm-witness/src/chain.rs`: Witness chain hash computation
- `rvm-partition/src/lifecycle.rs`: Partition state machine
- `rvm-memory/src/regions.rs`: regions_overlap_host() check
