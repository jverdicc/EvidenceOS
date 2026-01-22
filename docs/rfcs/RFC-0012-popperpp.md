# RFC-0012: POPPER++ Sequential Falsification Team

## Summary

POPPER++ integrates a sequential falsification protocol into EvidenceOS. It operationalizes POPPER's
anytime-valid sequential e-values, but replaces LLM-based relevance checks with soundness-by-
construction templates and explicit kernel enforcement. The protocol runs as an EvidenceOS Team
plugin that generates falsification sub-hypotheses, executes admissibility gates, and aggregates
sequential e-values until a stopping threshold is crossed or budgets are exhausted.

## Goals

- Provide a deterministic, replayable falsification loop with sequential e-value aggregation.
- Enforce admissibility and leakage checks before any sealed evaluation.
- Meter adaptivity, cross-claim dataset budgets, and evidence wealth in the ledger.
- Offer an EvidenceOS Team interface that can be integrated into a larger oracle/claim workflow.

## Non-goals

- Full experimental design automation or LLM-based hypothesis selection.
- Replacing EvidenceOS judge or capsule formats.
- Implementing new statistical tests beyond templated sub-hypotheses.

## Threat model

- **Leakage risk**: data-derived features or target leakage used during falsification rounds.
- **Adaptive overfitting**: repeated feedback causing invalid inference.
- **Cross-claim contamination**: a dataset overused across multiple claims.
- **Malicious design agent**: attempts to bypass admissibility or lane restrictions.

## Protocol stages

1. **Commit**: Claim + dataset are frozen. Config is validated, budgets initialized.
2. **Admissibility**: Kernel runs invariants, leakage gates, and schema checks.
3. **Falsification Loop (k rounds)**: Templates generate sub-hypotheses and a selector picks one per
   round. Each round produces a p-value and calibrated e-value.
4. **Freeze Confirmatory Set**: A subset of sub-hypotheses is frozen for sealed evaluation.
5. **Sealed Evaluation**: Oracle-protected evaluation on holdout data.
6. **Judge**: EvidenceOS judge inspects ledger, admissibility results, and e-process.
7. **Capsule**: A claim capsule is sealed with artifacts and ledger snapshot.

### Stage diagram

Commit -> Admissibility -> Falsification Loop (k rounds) -> Freeze Confirmatory Set ->
Sealed Evaluation -> Judge -> Capsule

## POPPER semantics (sequential e-values)

POPPER++ uses the POPPER paper's sequential e-values:

- **Calibrator**: for p-value p and parameter kappa in (0, 1),
  **e_i = kappa * p_i^(kappa - 1)**.
- **Aggregation**: e-values are multiplied over rounds. The null is rejected when
  the product crosses **>= 1/alpha**.

## Kernel/userland separation

- **Design Agent (userland)**: may be an LLM or heuristic system. It proposes sub-hypotheses but
  does not execute tests or bypass kernel constraints.
- **EvidenceOS kernel**: runs admissibility gates, executes tests via oracle lanes, charges ledger
  budgets, and generates the judge decision.

## Definitions

- **SubHypothesis**: a measurable implication of the main null hypothesis.
- **FalsificationExperiment**: a test definition for a SubHypothesis.
- **RoundResult**: p-value, e-value, and artifacts for a single falsification round.
- **EProcess**: sequential e-value aggregator with anytime validity.

## Ledger interactions

POPPER++ interacts with these ledger lanes:

- **Evidence wealth**: charged by the e-process and evidence lane policies.
- **Adaptivity rounds**: one per falsification round.
- **Cross-claim budget**: per-dataset test count (max_total_tests_per_dataset).
- **Privacy budget**: epsilon/delta charged when DP is enabled.

### Lane mapping

Lane policies map round types to execution lanes. Default mapping:

- FAST -> CANARY
- CANARY -> admissibility + invariants
- SEALED -> oracle-protected holdout
- HEAVY -> sealed evaluation + capsule sealing

## Data models

### FalsificationConfig

- alpha: float (0 < alpha < 1)
- kappa: float (0 < kappa < 1)
- max_rounds: int
- max_failed_rounds: int
- max_total_tests_per_claim: int
- max_total_tests_per_dataset: int
- lane_policy: dict[str, str]
- selection_policy: Literal["greedy_expected_info", "uniform", "bandit_ucb"]
- allow_llm_design: bool

### SubHypothesis

- id: str
- template: Literal["NEGATIVE_CONTROL", "PLACEBO", "SUBSET_INVARIANCE", "ALT_ESTIMATOR", "SHIFT_SLICE", "MULTIVERSE_SPEC"]
- null_nl: str
- alt_nl: str
- test_object: TestObjectRef
- metadata_only_ok: bool

### RoundResult

- round_idx: int
- subhypothesis_id: str
- p_value: float | None
- e_value: float | None
- status: Literal["PASS", "FAIL", "SKIP", "ERROR"]
- artifacts: list[ArtifactRef]
- notes: str | None

### FalsificationRun

- claim_id: str
- dataset_id: str
- config: FalsificationConfig
- rounds: list[RoundResult]
- aggregated_e: float
- decision: Literal["REJECT_H0", "NO_DECISION", "BUDGET_EXHAUSTED", "INVALID"]
- ledger_snapshot: EvidenceLedgerRef

## Security boundaries

- Only kernel-controlled lanes can access sealed data.
- Template library is the only source of sub-hypotheses.
- Any unknown template or forbidden feature is rejected pre-execution.
- Ledger enforcement is fail-closed on any budget or integrity violation.
