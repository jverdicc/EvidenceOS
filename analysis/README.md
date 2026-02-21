# EvidenceOS analysis report

Generate the end-to-end epistemic trial report with one command:

```bash
python -m pip install -r analysis/requirements.lock && \
python -m epistemic_trial.report --etl ETL_PATH --out OUT_DIR
```

The report directory contains:
- `km_curves.png`, `km_curves.csv`
- `cox_summary.csv`, `cox_ph_assumption.csv`
- `rmst_by_arm.csv`
- `nullspec_holm_bonferroni.csv`
- `consort_flow.png`, `consort_flow.csv`
- `summary.json`
