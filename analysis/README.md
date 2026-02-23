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

The extractor emits competing-risk event coding used by the report stack:

- `event_type = 1` (**adversary_success**, primary endpoint)
  - `state == CERTIFIED` is terminal success.
  - If state is unavailable, `certified == true` is used as fallback.
  - `state == SETTLED` is counted as success only when extraction is run with `--success-includes-settled`.
- `event_type = 2` (**frozen_containment**)
  - Triggered when `state == FROZEN` or `ledger_snapshot.frozen == true` (also accepts `ledger.frozen == true`).
- `event_type = 3` (**incident**)
  - Triggered for revoked/tainted/stale state or canary incident.
- `event_type = 0` (**censored**)
  - No endpoint observed by ETL end.

## Competing-risks outputs

The canonical report includes both cause-specific and competing-risk artifacts:

- Kaplan–Meier curves for frozen containment and adversary success (`km_by_arm.png`, `km_success_by_arm.png`).
- Aalen–Johansen cumulative incidence for primary endpoint (`cif_primary_by_arm.png`).
- Cause-specific Cox fits for adversary success, frozen containment, and incident (`cox_summary.csv`).
- RMST for adversary success (`rmst_by_arm.csv`).
- CONSORT flow/event totals plus machine-readable run summary (`consort_flow.csv`, `summary.json`).

## Artifacts

The report directory contains stable, machine-readable outputs:

- `km_by_arm.png`, `km_success_by_arm.png`
- `cif_primary_by_arm.png`
- `cox_summary.csv`
- `rmst_by_arm.csv`
- `nullspec_holm_bonferroni.csv`
- `consort_flow.csv`, `consort_flow.dot`, `consort_flow.png`
- `summary.json`
