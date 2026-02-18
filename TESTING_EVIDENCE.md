# Testing Evidence

Run the full hardened verification gate locally with:

```bash
./scripts/test_evidence.sh
```

## Gate contents

The script executes, in order:

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace --all-targets --all-features`
4. `cargo llvm-cov --workspace --all-features --all-targets --lcov --output-path target/coverage.lcov --fail-under-lines 95`
5. Bounded fuzz smoke runs (30 seconds each):
   - `cargo fuzz run fuzz_aspec_verify -- -max_total_time=30`
   - `cargo fuzz run fuzz_etl_read_entry -- -max_total_time=30`

No ignored tests are used by CI.

## Evidence artifacts

The gate produces the following artifacts:

- `artifacts/test_output.txt` (combined stdout/stderr across all gate commands)
- `target/coverage.lcov` (coverage report, 95%+ enforced)
- `target/clippy-report.txt` (lint output when clippy runs)

Coverage includes unit, integration, and system tests by using `--all-targets`.

## CI behavior

GitHub Actions runs this script as the single quality gate and uploads the evidence artifacts so failures are reproducible from one command.
