# EvidenceOS Epistemic Trial Harness Analysis

This analysis package provides a userland pipeline for survival analysis and CONSORT-style flow artifacts from an ETL export.

For the statistical contract (trial unit definitions, endpoint mapping, competing risks assumptions, and concealment limits), see [`docs/EPISTEMIC_TRIAL_HARNESS.md`](EPISTEMIC_TRIAL_HARNESS.md).
For the blessed analysis entrypoint for this repository, use this document's one-command workflow (`python -m analysis.survival ...`) and treat it as the canonical pipeline.

## Install

```bash
python -m pip install -e '.[analysis]'
```

## One-command workflow

```bash
python -m analysis.survival --etl path/to/etl.log --out out_dir/
```

Artifacts generated in `out_dir/`:

- `km_by_arm.png` — Kaplan–Meier curves by arm for all-cause failure (descriptive; not a competing-risks estimator for cause probability).
- `cif_primary_by_arm.png` — cumulative incidence for primary events (Aalen-Johansen; competing-risk aware).
- `cox_summary.csv` — cause-specific Cox PH summaries for primary and competing events.
- `covariate_balance.csv` — arm-level covariate balance table.
- `consort.dot` (and `consort.png` when Graphviz binary is available) — CONSORT-equivalent flow diagram.

## Notes

- ETL parsing validates per-record CRC (`crc32(length_prefix || payload)`) and fails closed on mismatch.
- Cause-specific Cox models treat non-target events as censored for that cause, while cumulative incidence uses explicit competing-risk coding.
- If a report uses KM for cause-specific interpretation, it must explicitly justify independent-censoring assumptions.
