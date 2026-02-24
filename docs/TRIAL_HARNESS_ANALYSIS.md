# EvidenceOS Epistemic Trial Harness Analysis

This analysis package provides a userland pipeline for survival analysis and CONSORT-style flow artifacts from an ETL export.

For the statistical contract (trial unit definitions, endpoint mapping, competing risks assumptions, and concealment limits), see [`docs/EPISTEMIC_TRIAL_HARNESS.md`](EPISTEMIC_TRIAL_HARNESS.md).
For the blessed analysis entrypoint for this repository, use `python -m analysis.epistemic_trial.report ...` as the canonical pipeline. `python -m analysis.survival ...` remains a compatibility wrapper.

## Install

```bash
python -m pip install -e '.[analysis]'
```

## Endpoint and time definitions

The extractor emits explicit trial endpoint fields:

- `time` (alias of `duration_kbits`) measured in **k-bits consumed**.
- `event_type` integer encoding:
  - `0 = censored`
  - `1 = adversary_success` (primary endpoint; `state == CERTIFIED`, or fallback `certified == true` when state unavailable; `SETTLED` only when opted in during extraction)
  - `2 = frozen_containment` (`state == FROZEN` or `ledger_snapshot.frozen == true`; also accepts `ledger.frozen == true`)
  - `3 = incident` (revoked/tainted/stale/canary incident)

The same unit (`duration_kbits`) is used consistently across KM, CIF, Cox, and RMST outputs.

## One-command workflow

Canonical entrypoint:

```bash
python -m analysis.epistemic_trial.report --etl path/to/etl.log --out out_dir/
```

Compatibility wrapper:

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


## Auditor keying guidance for trial commitments

When joining capsules or ETL-derived exports across runs, use the pair:

- `trial_commitment_schema_version`
- `trial_commitment_hash_hex`

as a stable audit key.

Schema v2 uses prefix-free commitment encoding for intervention identifiers/versions, so auditors can safely rely on commitment uniqueness under normal SHA-256 assumptions. Schema v1 values remain valid for legacy records and should not be reinterpreted as v2.

