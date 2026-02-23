---
# EvidenceOS as a Research Extensibility Substrate

## Overview

EvidenceOS is designed to be extended by the AI safety
and formal verification research community. The Epistemic
Trial Harness (docs/EPISTEMIC_TRIAL_HARNESS.md) provides
a strict case/control infrastructure for empirically
comparing verification strategies, safety bounds, and
NullSpec designs under controlled conditions.

A researcher can:
- Register a new NullSpec design as a "treatment arm"
- Run it against the default permutation baseline as 
  a "control arm"
- Collect ETL capsule outcomes across thousands of runs
- Run survival analysis comparing certification rates,
  FROZEN threshold triggers, and adversarial success 
  rates between arms

The kernel does not need to know the semantic meaning of
what is being compared. It meters the ledger and records
outcomes deterministically. The researcher designs the
intervention.

---

## What Researchers Can Extend

### 1. NullSpec Designs

The NullSpec pins H0 before agent interaction begins.
Researchers can construct and register alternative 
NullSpecs as trial arms:

- Non-parametric / Permutation NullSpecs: 
  Exchangeability-based, no distributional assumption
- Domain-Adaptive NullSpecs: 
  Calibrated from pilot data before interaction
- Hierarchical NullSpecs: 
  Pool statistical power across related subgroups
- Composite NullSpecs: 
  Strict intersection of multiple H0 constraints

Implement the NullSpec trait. Note: the trait operates
on kernel-mediated observations, NOT raw holdout data.
The kernel controls holdout access; NullSpec receives
only what the kernel has already released and charged:
```rust
pub trait NullSpec: Send + Sync {
    /// Unique identifier for registry lookup
    fn id(&self) -> &'static str;

    /// Human-readable null hypothesis description
    fn null_hypothesis(&self) -> &str;

    /// Update e-value given a new kernel-released 
    /// observation. observation is post-canonicalization
    /// and post-charge — the kernel has already metered
    /// the leakage for this symbol.
    fn update_e_value(
        &self,
        current_e: f64,
        observation: &KernelObservation,
    ) -> Result<f64, NullSpecError>;

    /// k-bit cost this NullSpec charges per evaluation.
    /// Must be >= log2(oracle_num_symbols).
    fn leakage_cost_bits(&self) -> f64;

    /// Citation for the underlying statistical method.
    fn citation(&self) -> Option<&str>;
}
```

### 2. E-Process Constructions

EvidenceOS bounds false certification using e-values
and e-processes (nonneg supermartingales under H0).
Researchers can register alternative e-process designs:

- Betting-based e-processes (Waudby-Smith & Ramdas 2023)
- Hedged capital e-processes
- Composite e-processes (multiple null hypotheses)
- Domain-specific constructions for clinical or 
  genomic data
```rust
pub trait EProcess: Send + Sync {
    fn id(&self) -> &'static str;

    /// Update evidence wealth W given new observation.
    /// Must satisfy: E_H0[result] <= current_wealth
    /// (supermartingale property under H0).
    /// Proof or citation required for contributions.
    fn update(
        &self,
        current_wealth: f64,
        observation: &KernelObservation,
        null_spec: &dyn NullSpec,
    ) -> Result<f64, EProcessError>;

    /// Citation or proof sketch that this construction
    /// satisfies the supermartingale property.
    fn validity_reference(&self) -> &str;
}
```

### 3. Cost Models

The default cost model charges k_bits = log2(|Y|) per
oracle response (support-size bound, conservative).
Researchers can compare alternative cost models:

- Min-entropy cost (tighter, requires distribution est.)
- Empirical symbol frequency cost
- Context-adaptive cost
- Flat per-query cost (zero-one, oracle-size-independent)
```rust
pub trait CostModel: Send + Sync {
    fn id(&self) -> &'static str;

    fn charge_bits(
        &self,
        symbol: &Symbol,
        alphabet_size: usize,
        context: &LedgerContext,
    ) -> f64;

    /// Must satisfy: charge >= 0 for all inputs.
    /// Recommended: charge >= log2(alphabet_size)
    /// for conservative soundness. Tighter models
    /// require separate theoretical justification.
    fn is_conservative(&self) -> bool;
}
```

### 4. Oracles (BYOO — Bring Your Own Oracle)

The BYOO architecture allows researchers to plug in
custom verification models without modifying the kernel:

- Swap LLM-as-a-Judge for a formal SAT/SMT solver
- Integrate domain-specific reward models
  (e.g., protein-folding validator, theorem prover)
- Test kernel resilience against intentionally weak
  or adversarial oracles
- Compare oracle types empirically across trial arms

The kernel treats all oracles identically: it meters
the e-values they return and charges the ledger.
Oracle quality is bounded by the operator's choice.
The kernel guarantees enforcement is non-bypassable
given a valid oracle — see docs/POSITIONING.md Section 1.

### 5. TopicHash and Budget Strategies

Researchers can extend budget isolation mechanisms
to test distributed attack resilience:

- Semantic vs. Lineage Hashing: Compare 
  embedding-based TopicHashes against causal-DAG
  lineage tracing (MultiSignalTopicID)
- Budget scope: Compare per-session vs. per-claim
  vs. per-topic budget isolation strategies
- Epoch rollover policy: Compare immediate reset
  at DLC epoch vs. carry-forward of residual budget

Note: k-budget within an epoch is strictly monotone
non-decreasing (Ledger Invariant 2 in the paper).
k does not decay or recover within an epoch.
Epoch boundaries are the only reset mechanism.
Budget decay proposals that violate this invariant
are outside the UVP soundness envelope and must
include separate theoretical justification.

---

## How to Register a Research Arm

1) Implement your extension as a Rust struct
   satisfying the relevant trait

2) Add it to the compiled-in registry:
   crates/evidenceos-core/src/extensions/registry.rs

3) Register the arm in your trial config:
```json
{
  "trial_id": "nullspec_comparison_2026_q1",
  "arms": [
    {
      "arm_id": 0,
      "label": "control",
      "nullspec_id": "permutation_default_v1",
      "cost_model_id": "log2_alphabet",
      "e_process_id": "sequential_lr_default"
    },
    {
      "arm_id": 1,
      "label": "nonparametric_nullspec",
      "nullspec_id": "exchangeability_v1",
      "cost_model_id": "log2_alphabet",
      "e_process_id": "sequential_lr_default"
    },
    {
      "arm_id": 2,
      "label": "min_entropy_cost",
      "nullspec_id": "permutation_default_v1",
      "cost_model_id": "min_entropy_v1",
      "e_process_id": "sequential_lr_default"
    }
  ],
  "randomization": "blocked",
  "block_size": 10,
  "stratify_on": ["holdout_family", "adversary_type"],
  "trial_plan_committed_at": "pre-registration required"
}
```

4) Run the trial and analyze outcomes:
```bash
python -m analysis.survival \
  --etl path/to/etl.log \
  --compare-arms 0,1,2 \
  --endpoint adversary_success \
  --competing-event freeze \
  --out out/nullspec_comparison/
```

---

## Statistical Design Requirements

Use competing risks survival analysis (not naive KM):

- Primary event: adversary success
- Competing event: EvidenceOS freeze/escalation

KM with freeze-censoring is biased because freeze is
informative. Use cause-specific Cox or Fine-Gray.
See docs/EPISTEMIC_TRIAL_HARNESS.md for full details.

Success events are rare by design (~0.5% under
EvidenceOS). With rare events, you need thousands
of runs per arm to observe enough events for power.
Run power analysis before committing to a trial.

---

## Commitment and Blinding Requirements

1) Pre-register trial plan before any runs
   (commit trial_arms.json hash to ETL first)
2) Do not inspect arm outcomes mid-trial
   (auditor role only for ETL access)
3) Report all arms including underperforming ones
4) Normalize response timing across arms via DLC

---

## What This Framework Cannot Verify

The trial harness provides empirical evidence only.
It does not replace:

- Formal proof that your NullSpec satisfies 
  E_H0[E] <= 1 (mathematical verification required)
- Theoretical justification for tighter cost models
- Proof that your e-process is a supermartingale

The framework tests whether an extension integrates
correctly with the kernel and how it performs 
empirically. Theory and empirics are complementary.

---

## Contributing Extensions

1) Open a PR with Rust implementation + tests
2) Include trial results (ETL + analysis outputs)
3) Include citation if from published literature
4) Include proof sketch or pointer to paper proof
   that E_H0[E] <= 1 holds for your construction

Extensions merged to:
crates/evidenceos-core/src/extensions/

---

## Assurance Status

| Component | Status |
|---|---|
| Epistemic Trial Harness (case/control) | Live |
| BYOO Oracle interface | Live |
| NullSpec trait + registry | Architecture specified |
| EProcess trait + registry | Architecture specified |
| CostModel trait + registry | Architecture specified |
| Custom arm injection via trial_arms.json | Roadmap |

See docs/EPISTEMIC_TRIAL_HARNESS.md for harness
statistical design and analysis pipeline.

See docs/integrations/fda_clinical_trials.md for
FDA regulatory deployment (separate from this doc).
---
