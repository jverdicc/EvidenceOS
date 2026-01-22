# RFC-0020: Score/Evidence Plugins, Quant Pack, and IC Evidence Test

## Summary

This RFC defines explicit interfaces for **Score** vs **Evidence** plugins, adds a minimal
quantitative domain pack, and standardizes an **IC Evidence Test** as a certified `TestObject`.
It also specifies ledger hooks for alpha-mining budget controls.

## Motivation

Metrics like IC are **scores**, not evidence. Evidence must be conserved, ledgered, and
comparable across claims. This RFC makes that separation explicit and introduces a
minimal set of quant-focused diagnostics and budgets needed to make adaptive discovery
costs visible.

## Terminology

- **Score**: A metric produced from data (e.g., IC, ICIR, IR, Sharpe) with no direct
  evidence accounting.
- **Evidence increment** (`e_increment`): A ledgered update produced by certified tests
  or e-processes.
- **QuantAdapter**: A domain pack that enforces common time-series evaluation hygiene.
- **TestObject**: A certified test definition with null, statistic, inference method,
  and evidence mapping.

## Requirements

### A. Plugin Interfaces (Score vs Evidence)

1. The system **MUST** support a `ScorePlugin` interface that returns a score value only.
2. The system **MUST** support an `EvidencePlugin` interface that returns an
   `e_increment` value that updates the ledger.
3. A `ScorePlugin` **MUST NOT** directly update the ledger.
4. An `EvidencePlugin` **MUST** be backed by a certified `TestObject` or an
   evidence-valid e-process.

**Canonical interface shapes:**

```json
// ScorePlugin result
{
  "score": 0.0,
  "metadata": {
    "score_type": "IC|ICIR|IR|Sharpe|...",
    "window": "optional",
    "units": "optional"
  }
}

// EvidencePlugin result
{
  "e_increment": 0.0,
  "metadata": {
    "test_object_id": "...",
    "method": "p_to_e|e_process",
    "audit": "optional"
  }
}
```

### B. Quant Domain Pack (Minimal)

The system **MUST** expose a `QuantAdapter` with the following certified checks
and utilities:

1. **Time-block splits + embargo**
   - Enforce non-overlapping time blocks.
   - Support embargo windows between train/test blocks.
2. **Cross-sectional grouping checks**
   - Validate group sizes, missingness, and survivorship bias flags.
3. **Dependence diagnostics**
   - Autocorrelation diagnostics for time series.
   - Cross-sectional correlation diagnostics for contemporaneous units.
4. **Shift partitions (regimes)**
   - Provide regime segmentation hooks to test stability under shifts.

Each check **MUST** emit an admissible diagnostic record that is traceable in the
capsule provenance.

### C. Certified TestObject: IC Evidence Test

The system **MUST** include a certified `TestObject` named `ic_evidence_test` with:

- **Null hypothesis**: \( \mathbb{E}[IC_t] \le 0 \)
- **Statistic**: mean IC over blocks (or ICIR with robust variance)
- **Inference**: block bootstrap, HAC, or permutation-by-block
- **Evidence mapping**: p-to-e mapping **OR** a betting-style e-process

**Canonical TestObject fields:**

```json
{
  "test_object_id": "ic_evidence_test",
  "null": "E[IC_t] <= 0",
  "statistic": "block_mean_IC | ICIR_robust",
  "inference": ["block_bootstrap", "HAC", "permutation_by_block"],
  "evidence_mapping": "p_to_e | e_process"
}
```

### D. Ledger Hooks for Alpha-Mining Controls

The ledger **MUST** support explicit budget hooks to make search costs visible and
chargeable. At minimum:

1. **Cross-claim dataset budget** (per dataset/vault)
2. **Per-claim budget** (per hypothesis family)
3. **Multiverse budget** (per spec family)
4. **Shift-slice budget** (per slicing family)

Each hook **MUST** be enforced as part of ledger admission and appear in the
transparency log for auditability.
