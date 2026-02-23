# EvidenceOS Epistemic Trial Harness Analysis

This analysis package provides a userland pipeline for survival analysis and CONSORT-style flow artifacts from an ETL export.

For the statistical contract (trial unit definitions, endpoint mapping, competing risks assumptions, and concealment limits), see [`docs/EPISTEMIC_TRIAL_HARNESS.md`](EPISTEMIC_TRIAL_HARNESS.md).
For the blessed analysis entrypoint for this repository, use this document's one-command workflow (`python -m analysis.survival ...`) and treat it as the canonical pipeline.

## Install

```bash
python -m pip install -e '.[analysis]'
```

## Endpoint and time definitions

The extractor emits explicit trial endpoint fields:

- `time` (alias of `duration_kbits`) measured in **k-bits consumed**.
- `event_type` integer encoding:
  - `0 = censored`
  - `1 = adversary_success` (primary endpoint)
  - `2 = frozen_containment`
  - `3 = incident` (revoked/tainted/stale/canary incident)

The same unit (`duration_kbits`) is used consistently across KM, CIF, Cox, and RMST outputs.

## One-command workflow

```bash
python -m analysis.survival --etl path/to/etl.log --out out_dir/
```

Artifacts generated in `out_dir/`:

- `km_by_arm.png` — Kaplan–Meier by arm with `frozen_containment` as the event and all other event types censored.
- `km_success_by_arm.png` — Kaplan–Meier by arm with `adversary_success` as the event and all other event types censored.
- `cif_primary_by_arm.png` — cumulative incidence for primary events (`adversary_success`) via Aalen–Johansen with explicit competing risks.
- `cox_summary.csv` — cause-specific Cox PH outputs for each cause (`adversary_success`, `frozen_containment`, `incident`) fit separately with non-target causes censored.
- `rmst_by_arm.csv` — RMST by arm using `adversary_success` as endpoint, includes explicit `horizon_kbits` and `rmst_kbits` columns.
- `consort_flow.csv`, `consort_flow.dot`, `consort_flow.png` — CONSORT-equivalent flow and endpoint counts consistent with extracted event-type totals.
- `summary.json` — artifact index and event/time mapping used for the run.

## Notes

- ETL parsing validates per-record CRC (`crc32(length_prefix || payload)`) and fails closed on mismatch.
- Cause-specific Cox models treat non-target events as censored for that cause, while cumulative incidence uses explicit competing-risk coding.
- `cif_primary_by_arm.png` is the preferred endpoint-probability artifact when competing risks are present.
