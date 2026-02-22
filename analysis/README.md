# EvidenceOS clinical trial analysis pipeline

Canonical entrypoint (blessed path):

```bash
python -m pip install -e '.[analysis]' && \
python -m analysis.epistemic_trial.report --etl ETL_PATH --out OUT_DIR
```

Legacy compatibility wrapper:

```bash
python -m analysis.survival --etl ETL_PATH --out OUT_DIR
```

The analysis time axis is **cumulative k-bits** (`time = k_bits_total`), not days.

## Endpoint definitions

- **Primary event** (`event=1`): claim reaches a frozen terminal state.
  - Triggered when `ledger.frozen == true`, or if ledger flag is absent and capsule state resolves to `FROZEN`.
- **Censoring** (`censor=1`): no primary event observed for the capsule by ETL end.
- **Competing risks**: not modeled in the canonical report output; the canonical path runs KM + Cox PH on the primary frozen endpoint.

## Artifacts

The report directory contains stable, machine-readable outputs:

- `km_curves.png`, `km_curves.csv`
- `cox_summary.csv`, `cox_ph_assumption.csv`
- `rmst_by_arm.csv`
- `nullspec_holm_bonferroni.csv`
- `consort_flow.csv`, `consort_flow.dot`, `consort_flow.png`
- `summary.json`
