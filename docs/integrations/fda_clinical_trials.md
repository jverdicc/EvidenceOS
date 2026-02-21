# FDA Clinical Trials Integration Guide

## Overview
Clinical trials are high-stakes, adaptive decision systems: teams can be tempted to re-slice cohorts, swap endpoints, or repeatedly test variants until significance appears. EvidenceOS's clinical-trials framework uses the UVP lifecycle to make those adaptive moves explicit, budgeted, and auditable before submission.

This guide shows:
- how to map a trial workflow into UVP stages,
- how to configure the framework,
- how to run analysis with examples.

For the full trial-analysis protocol (units, endpoints, competing risks, CONSORT outputs), see the **Epistemic Trial Harness**: [`docs/EPISTEMIC_TRIAL_HARNESS.md`](../EPISTEMIC_TRIAL_HARNESS.md).

## UVP Lifecycle Mapping

| UVP Stage | FDA Trial Equivalent | Type-level Input | Type-level Output |
|---|---|---|---|
| CreateClaim | Register protocol and Statistical Analysis Plan (SAP) | `TrialProtocol`, `SAPHash`, `InclusionExclusionCriteria` | `claim_id`, initial `W`/`k` budgets |
| CommitArtifacts | Lock protocol artifacts before unblinding | `ProtocolVersion`, `EndpointDefinitions`, `RandomizationPlan` | `CommitmentReceipt` |
| FreezeGates | Validate admissibility before final analysis | `DataCutID`, `SiteQCReport`, `SafetyRules` | `AdmissibilityStatus` |
| SealClaim | Seal analysis environment for final readout | `DatasetHash`, `CodeHash`, `ContainerDigest` | `SealedEnvReceipt` |
| ExecuteClaim | Run pre-registered endpoints and subgroup checks | `TrialDataset`, `OracleQueries` | `DecisionSymbol`, `k_spend`, `W_update` |
| FROZEN | Stop adaptive mining / block non-registered analyses | `BudgetExhaustion`, `PolicyViolation` | `FROZEN` state + ETL event |

## How to use the clinical trials framework

### 1) Pre-register a trial claim
Treat the SAP as the NullSpec baseline and register all endpoints before execution.

```json
{
  "schema_id": "fda-clinical-trial-claim.v1",
  "claim_id": "nct-0420-primary-efficacy",
  "claim_name": "Phase III primary efficacy readout",
  "oracle_id": "clinical_primary_endpoint_oracle",
  "topic_signals": [
    "primary_endpoint",
    "safety_noninferiority",
    "subgroup_interaction"
  ],
  "sap_hash": "sha256:...",
  "alpha": 0.05,
  "k_budget": 32.0,
  "oracle_num_symbols": 3,
  "nullspec_kind": "pre_registered_sap"
}
```

### 2) Run a p-hacking stress simulation (example)
Use the simulation to demonstrate why bounded adaptivity is required for subgroup mining.

```bash
cd examples/simulations
python demo2_clinical_phacking.py
```

Expected behavior: the unbounded path may eventually show `p < 0.05`, while the bounded EvidenceOS threshold (`alpha'`) decays as `k` is spent and the run reaches a freeze point.

### 3) Run trial outcomes analysis from ETL exports (example)
Generate competing-risks and CONSORT-style artifacts using the trial harness pipeline.

```bash
python -m analysis.survival --etl path/to/etl.log --out out/clinical_trial_report
```

Typical outputs include:
- `cif_primary_by_arm.png` (cumulative incidence with competing risks),
- `cox_summary.csv` (cause-specific hazard summaries),
- `consort.dot` / `consort.png` (participant flow when graphviz is available).

## Key configuration parameters
- `oracle_num_symbols`: Number of discretized outcome symbols from the trial oracle (example: 3 for `benefit`, `neutral`, `harm`).
- `k_budget`: Total adaptive-query budget allowed across endpoint and subgroup probing before freezing.
- `alpha`: Family-wise statistical tolerance used in certification logic.
- `nullspec_kind`: Pre-registered analytical baseline (for trials, typically SAP-driven).

## Deployment notes
- Keep endpoint mapping fixed and pre-registered; do not alter event coding after observing outcomes.
- Use claim/session/cluster unit selection from the trial harness and keep it fixed through analysis.
- Explicitly model competing risks (for example, freeze/incident outcomes) instead of treating them as simple censoring.

## See also
- [`docs/INTEGRATION_PATTERNS.md`](../INTEGRATION_PATTERNS.md)
- [`docs/EPISTEMIC_TRIAL_HARNESS.md`](../EPISTEMIC_TRIAL_HARNESS.md)
- [`examples/simulations/demo2_clinical_phacking.py`](../../examples/simulations/demo2_clinical_phacking.py)
