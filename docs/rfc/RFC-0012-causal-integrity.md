# RFC-0012: Causal Integrity (DAG + Temporal + Backdoor Checks)

## Summary

EvidenceOS validates causal graphs to ensure deterministic DAG structure, temporal integrity, and
backdoor-adjustment hygiene before downstream inference.

## Requirements

- Causal graph parsing **MUST** be deterministic and reject malformed inputs.
- DAG validation **MUST** fail closed on cycles (`E_CAUSAL_DAG_CYCLE`).
- Temporal integrity **MUST** fail closed when any edge points from a later time index to an earlier
  time index (`E_TEMPORAL_INTEGRITY`).
- Backdoor heuristics **MUST** identify candidate confounders as the intersection of ancestors of
  treatment and outcome.
- Adjustment set validation **MUST** fail closed by default when candidate confounders are missing
  from the adjustment set (`E_BACKDOOR_UNADJUSTED`), with an option to downgrade to warnings for
  non-blocking workflows.
