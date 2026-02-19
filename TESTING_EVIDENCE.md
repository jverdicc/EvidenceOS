# Testing Evidence

## Evidence checklist

Run:

```bash
./scripts/test_evidence.sh
```

Expected key outputs:
- `artifacts/test_output.txt` contains successful `cargo fmt --check`, `cargo clippy`, `cargo test`, and `cargo llvm-cov` sections.
- `artifacts/coverage.lcov` is created and coverage gate `--fail-under-lines 95` passes.
- Fuzz smoke logs are created:
  - `artifacts/fuzz_aspec_verify.log`
  - `artifacts/fuzz_etl_read_entry.log`
  - `artifacts/fuzz_structured_claim_validate.log`

## Artifact paths
- `artifacts/test_output.txt`
- `artifacts/coverage.lcov`
- `artifacts/fuzz_aspec_verify.log`
- `artifacts/fuzz_etl_read_entry.log`
- `artifacts/fuzz_structured_claim_validate.log`

## CI artifacts
CI should upload all files under `artifacts/` as build artifacts.
