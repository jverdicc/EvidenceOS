# FORC10 original_python reproducibility pipeline

This directory is the single authoritative paper reproduction path for FORC10 in this repository.
It replaces synthetic placeholder-style reproduction scripts with a deterministic, auditable pipeline
that executes the real repository-backed experiment sources.

## Layout

- `kernel/` – small shared utilities for subprocess execution and JSON I/O.
- `experiments/` – experiment entrypoints bound to concrete EvidenceOS system tests/artifacts.
- `figures/` – deterministic figure/table renderers.
- `expected/` – golden outputs checked by verification harness.
- `run_all.py` – one-command reproduction runner.
- `verify_outputs.py` – strict output comparer with numeric tolerance controls.
- `requirements.lock` – pinned runtime policy.

## One-command run

From repository root:

```bash
python3 artifacts/forc10/original_python/run_all.py \
  --repo-root . \
  --out-dir artifacts/forc10/out
```

This cleans `--out-dir`, runs all experiments, and writes stable JSON/CSV/Markdown outputs.

## CI lightweight drift check

```bash
python3 artifacts/forc10/original_python/run_all.py \
  --repo-root . \
  --out-dir artifacts/forc10/out \
  --quick
python3 artifacts/forc10/original_python/verify_outputs.py \
  --out-dir artifacts/forc10/out \
  --expected-dir artifacts/forc10/original_python/expected
```

`--quick` skips rerunning heavy test executables and validates the expected trend + key invariants from checked-in canonical raw artifacts.

## Expected runtime

- Full run: ~1-4 minutes on warm cache.
- Quick CI run: <30 seconds.
