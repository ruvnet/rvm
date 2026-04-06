# RVM Research Topics

**Last Updated**: 2026-04-04

This directory contains research briefs for open questions, comparative analyses, and security studies related to the RVM hypervisor. Each document identifies the research question, its relevance to RVM design decisions, known prior work, and suggested investigation approaches.

---

## Directory Structure

```
docs/research/
    README.md                             # This file
    specification-improvement-plan.md     # Full gap analysis and GOAP action plan
    theoretical-foundation.md             # 6 research topics on RVM's theoretical basis
    comparative-analysis.md               # 4 comparison studies against existing systems
    security-analysis.md                  # 4 security research topics
```

---

## Research Topics by Category

### Theoretical Foundation

| ID | Topic | Related ADRs | Priority |
|----|-------|-------------|----------|
| R1 | Coherence convergence guarantees | ADR-132, ADR-141 | High |
| R2 | MinCut budget analysis | ADR-132 DC-2, ADR-144 | High |
| R3 | Reconstruction fidelity | ADR-134, ADR-136 | High |
| R4 | Proof tier latency bounds | ADR-135 DC-3 | Medium |
| R5 | Memory tier transition optimality | ADR-136 | Medium |
| R6 | GPU acceleration speedup model | ADR-144, ADR-152 | Medium |

### Comparative Analysis

| ID | Topic | Comparison Target | Priority |
|----|-------|------------------|----------|
| R7 | RVM vs seL4 | Capability models, verification gap | High |
| R8 | RVM vs Firecracker | Boot time, partition switch, memory | Medium |
| R9 | RVM vs CFS/EEVDF | Scheduling algorithms | Medium |
| R10 | RVM vs zswap/zram | Memory compression vs reconstruction | Low |

### Security Analysis

| ID | Topic | Threat Class | Priority |
|----|-------|-------------|----------|
| R11 | Constant-time audit | Side-channel | High |
| R12 | GPU covert channels | Information leakage | High |
| R13 | TEE collateral expiry | Availability/trust | Medium |
| R14 | Witness truncation attacks | Denial of audit | Medium |

---

## How to Use These Documents

Each research brief follows a common structure:

1. **Question**: The specific research question
2. **Relevance**: Why this matters for RVM
3. **Prior Work**: Known results from literature or related systems
4. **Approach**: Suggested investigation methodology
5. **Expected Outcome**: What a successful investigation would produce

Research topics may be promoted to full ADRs when they produce concrete design recommendations. For example, R6 (GPU speedup model) directly informs ADR-152 (GPU MinCut Correctness Model).

---

## Cross-References

- ADR index: `docs/adr/`
- Specification improvement plan: `docs/research/specification-improvement-plan.md`
- RuVector integration: `docs/RUVECTOR-INTEGRATION.md`
