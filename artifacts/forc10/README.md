# FORC10 Artifact Reproduction Harness

The authoritative FORC10 paper reproduction path in this repository is:

- `artifacts/forc10/original_python/run_all.py`

Legacy scripts under `artifacts/forc10/scripts/` are compatibility wrappers only.

## One-command verification

From repository root:

```bash
make -C artifacts/forc10 verify
```

This runs the full deterministic experiment pipeline and compares outputs against
`artifacts/forc10/original_python/expected`.

## CI lightweight drift check

```bash
make -C artifacts/forc10 verify-lite
```

`verify-lite` runs the same schema and golden checks using `--quick` mode so CI can cheaply detect
reproducibility drift while full local verification remains available.

## Outputs

Generated outputs:
- `artifacts/forc10/out/raw/results.json`
- `artifacts/forc10/out/raw/results.csv`
- `artifacts/forc10/out/figures/table_1.csv`
- `artifacts/forc10/out/figures/table_1.md`

Expected outputs:
- `artifacts/forc10/original_python/expected/results.json`
- `artifacts/forc10/original_python/expected/results.csv`
- `artifacts/forc10/original_python/expected/table_1.csv`
- `artifacts/forc10/original_python/expected/table_1.md`
