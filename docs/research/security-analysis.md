# Security Analysis Research Topics

**Date**: 2026-04-04
**Scope**: Four security research topics covering side channels, covert channels, trust expiry, and audit integrity

---

## R11: Constant-Time Audit — Verify All P1/P2 Checks Are Truly Constant-Time

**Question**: Do the P2 verification checks in `rvm-proof` remain constant-time after compiler optimization on AArch64 and x86-64?

**Relevance**: ADR-135 mandates constant-time execution for P2 policy validation. ADR-142 requires constant-time comparison (`subtle::ConstantTimeEq`) for all hash and signature checks. However, writing constant-time Rust code is necessary but not sufficient -- the compiler may introduce variable-time behavior through optimizations such as branch-based lowering of conditional moves, auto-vectorization with early exits, or dead code elimination of seemingly redundant operations.

**Threat Model**: An attacker with precise timing measurements (e.g., cache-line flush + reload, branch predictor priming) observes the latency of P2 verification calls with varying proof inputs. If the latency varies based on which check fails first, the attacker learns which checks pass, enabling incremental proof forgery. The attack requires local timing measurements (same machine or same cache partition), which is realistic in a multi-partition hypervisor.

**Prior Work**: (1) The `dudect` tool (Reparaz et al., 2017) performs statistical constant-time testing using Welch's t-test on execution time distributions. (2) The `ct-verif` tool (Almeida et al., 2016) formally verifies constant-time properties via symbolic execution. (3) `subtle` crate documentation warns that constant-time guarantees depend on compiler behavior and recommends assembly audit.

**Approach**:

1. **Assembly audit**: Compile `verify_p2()` with `--release` optimization for both `aarch64-unknown-none` and `x86_64-unknown-none` targets. Inspect the generated assembly for: (a) conditional branches on secret-dependent values, (b) memory access patterns that vary with secret values, (c) early-exit paths that bypass remaining checks.
2. **Statistical testing**: Use `dudect` methodology -- run `verify_p2()` with two input classes (all checks pass, first check fails) for 10M iterations. Apply Welch's t-test to the timing distributions. If |t| > 4.5, reject the constant-time hypothesis.
3. **Compiler fence verification**: Verify that `core::hint::black_box()` barriers in the P2 path survive optimization. Check that the compiler does not eliminate the "execute all checks" pattern by proving a later check subsumes an earlier one.
4. **Cross-platform comparison**: Run the same analysis on Cortex-A72 (Appliance target) and QEMU virt (development target). Compiler backends may produce different code for different targets.

**Expected Outcome**: An assembly audit report for P2 verification on both target architectures. If constant-time violations are found, concrete patches (e.g., replacing `if` with conditional select, adding `black_box` barriers, using inline assembly for critical comparisons). A regression test that runs the `dudect` statistical check in nightly CI (ADR-143).

---

## R12: GPU Covert Channels — Can Partitions Leak Data via GPU Timing?

**Question**: Can two RVM partitions communicate through GPU timing side channels despite IOMMU isolation?

**Relevance**: ADR-144 provides per-partition GPU isolation via IOMMU page tables. However, IOMMU isolation protects memory access, not execution timing. If two partitions share a GPU (time-multiplexed via `GpuContext` save/restore), the execution time of one partition's kernel may depend on the cache state left by the other partition's kernel. This creates a timing covert channel.

**Threat Model**: Partition A (sender) modulates its GPU kernel execution time to encode information. Partition B (receiver) measures its own GPU kernel execution time, which varies based on A's GPU cache pollution. The channel bandwidth depends on the GPU context switch frequency and the timing measurement precision.

**Known GPU Covert Channel Classes**:

| Channel | Mechanism | Bandwidth Estimate |
|---------|-----------|-------------------|
| GPU L1 cache | Sender fills/evicts L1 lines; receiver measures L1 hit/miss | ~100 Kbps (Naghibijouybari et al., 2018) |
| GPU L2 cache | Same as L1 but across compute units | ~50 Kbps |
| GPU memory bus contention | Sender issues high-bandwidth transfers; receiver measures transfer latency | ~10 Kbps |
| GPU execution unit contention | Sender occupies ALUs; receiver measures kernel dispatch latency | ~5 Kbps |
| GPU power throttling | Sender induces thermal throttling; receiver observes clock frequency drop | ~1 Kbps |

**Approach**:

1. **Channel characterization**: Implement sender and receiver kernels for each channel class. Measure achievable bandwidth and error rate on the target GPU backend (WASM-SIMD for Seed, WebGPU/CUDA for Appliance).
2. **Mitigation evaluation**: For each channel, evaluate mitigations: (a) GPU cache flush on context switch (eliminates L1/L2 channels but adds latency), (b) GPU memory bus partitioning (if hardware supports it), (c) noise injection (randomize kernel launch timing), (d) GPU time-padding (pad all kernel launches to a fixed duration, eliminating timing variation).
3. **Cost-benefit analysis**: For each mitigation, measure the performance overhead against ADR-144 benchmark targets. Determine which mitigations are acceptable for the Appliance profile.
4. **Witness-based detection**: Evaluate whether GPU witness records (ADR-151) can detect covert channel activity through anomalous kernel timing patterns (e.g., bimodal execution time distribution).

**Expected Outcome**: A threat model document with measured channel bandwidths, a recommended mitigation strategy for each channel class, and performance overhead measurements. If GPU cache flush is recommended, provide an updated budget for `GpuContext` save/restore (ADR-144 DC-GPU-4).

---

## R13: TEE Collateral Expiry — What Happens When TEE Quotes Expire?

**Question**: What is the blast radius when TEE attestation collateral expires, and can an attacker force expiry?

**Relevance**: ADR-142 specifies that Intel TDX collateral expires after 30 days (per Intel's TDX Enabling Guide). When collateral expires, the `TeeQuoteVerifier::collateral_valid()` check returns false, and `TeeWitnessSigner` can no longer produce verified quotes. This affects all witness signing and P3 deep proof verification on the affected node.

**Threat Model**: An attacker blocks network access to the Intel Provisioning Certification Service (PCS) or AMD Key Distribution Service (KDS). After the collateral expiry window (30 days for TDX), the node can no longer refresh collateral. All TEE-backed signing degrades to software fallback (`Ed25519WitnessSigner`), which provides cryptographic signing but not hardware-bound attestation.

**Scenarios**:

| Scenario | Trigger | Impact | Duration |
|----------|---------|--------|----------|
| Normal expiry | 30 days without refresh | Degraded to software signing | Until connectivity restored |
| DNS poisoning | Attacker redirects PCS DNS | Stale collateral; quotes may be rejected by remote verifiers | Until DNS corrected |
| PCS outage | Intel/AMD service unavailable | All nodes with expired collateral degrade simultaneously | Until service restored |
| Clock manipulation | Attacker skews system clock forward | Premature collateral expiry | Until clock corrected |

**Approach**:

1. **Blast radius analysis**: Map which RVM operations depend on TEE collateral validity. Determine whether P1 and P2 verification (which do not use TEE quotes) continue to function. Verify that the fallback to `Ed25519WitnessSigner` is seamless and does not require operator intervention.
2. **Refresh strategy**: Evaluate proactive collateral refresh (refresh at 50% of expiry window, i.e., 15 days for TDX). Implement a health check that warns operators when collateral is within 7 days of expiry.
3. **Clock security**: Evaluate NTP authentication (NTS, RFC 8915) as a mitigation for clock manipulation attacks. Determine whether RVM should refuse to degrade if the clock jumps forward by more than a configurable threshold.
4. **Multi-platform resilience**: If the deployment uses multiple TEE platforms (e.g., TDX on some nodes, SEV-SNP on others), evaluate whether collateral expiry on one platform affects the others. Design for independent collateral lifecycles.

**Expected Outcome**: A blast radius table showing which RVM operations degrade on collateral expiry, a recommended refresh strategy, and a health monitoring specification for collateral validity.

---

## R14: Witness Truncation Attacks — Ring Buffer Overflow as Denial of Audit

**Question**: Can an attacker exploit the witness ring buffer overflow to erase evidence of malicious activity?

**Relevance**: ADR-134 Section 4 defines the witness log as a ring buffer with background drain. When the drain task cannot keep up, the oldest un-drained records are overwritten. The system detects this via a sequence gap and logs a `RecoveryEnter` witness when the drain catches up. However, if an attacker can intentionally cause ring buffer overflow, they can erase specific witness records by timing their malicious operations to coincide with the overflow window.

**Threat Model**: A malicious partition with high privilege (but not kernel-level) floods the witness log with legitimate but high-volume operations (e.g., rapid capability grants and revokes, or rapid GPU buffer alloc/free cycles using ADR-151 variants). The flood rate exceeds the drain rate, causing the ring buffer to wrap and overwrite records from before the flood. If the attacker times the flood to coincide with their malicious operation (e.g., an unauthorized migration), the malicious operation's witness record is overwritten before it can be drained to persistent storage.

**Attack Steps**:

1. Attacker identifies the ring buffer capacity (262,144 records per ADR-134) and drain rate.
2. Attacker performs the malicious operation (e.g., privilege escalation attempt).
3. Attacker immediately floods the witness log with 262,144+ innocuous operations.
4. The ring buffer wraps, overwriting the malicious operation's witness record.
5. When the drain catches up, it sees a sequence gap but the overwritten records are gone.

**Approach**:

1. **Rate limiting**: Evaluate per-partition witness emission rate limits. A partition that exceeds N witness records per epoch (e.g., 1000) triggers a `WitnessFloodDetected` event and is throttled.
2. **Priority draining**: Evaluate draining high-severity events (proof rejections, IOMMU violations, budget exceeded) before low-severity events (normal IPC, epoch summaries). This ensures security-critical records survive overflow.
3. **Dual-buffer architecture**: Evaluate a separate, smaller ring buffer for security-critical events (proof rejections, capability escalation attempts, IOMMU violations). This buffer has its own drain path and is not affected by floods in the main buffer.
4. **Immediate drain trigger**: When a security-critical event is emitted, trigger an immediate drain of at least the security buffer. This bounds the window during which the event could be overwritten.
5. **Witness hash anchoring**: Periodically write a hash anchor (SHA-256 of the last N records) to persistent storage. Even if records are overwritten, the anchor detects that the chain has been disrupted.

**Expected Outcome**: A concrete mitigation recommendation (rate limiting, priority draining, or dual buffer), with performance impact analysis. The mitigation must not violate the 500ns witness emission budget (ADR-134 Section 6) or add allocation to the fast path.

---

## Cross-References

- ADR-134: Witness Schema and Log Format (ring buffer, emission protocol, 500ns budget)
- ADR-135: Proof Verifier Design (P2 constant-time verification)
- ADR-142: TEE-Backed Cryptographic Verification (TEE pipeline, collateral refresh, constant-time)
- ADR-144: GPU Compute Support (GPU isolation, IOMMU, context switch)
- ADR-151: GPU Witness Event Registry (GPU-specific ActionKind variants)
- Naghibijouybari, H. et al. "Rendered Insecure: GPU Side Channel Attacks are Practical." CCS 2018.
- Reparaz, O. et al. "Dude, is my code constant time?" DATE 2017.
- Almeida, J.B. et al. "Verifying Constant-Time Implementations." USENIX Security 2016.
