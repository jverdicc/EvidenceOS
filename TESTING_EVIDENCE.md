# Testing Evidence

## Command

```bash
./scripts/test_evidence.sh
```

## Captured Example (abridged)

```text
== cargo fmt ==
== cargo clippy ==
== cargo test ==
== cargo llvm-cov (with integration/system tests) ==
== cargo fuzz smoke (30s per target) ==
```

## Expected Artifacts

- `artifacts/test_output.txt` (combined test log)
- `artifacts/coverage.lcov` (coverage output)
- `artifacts/fuzz_aspec_verify.log`
- `artifacts/fuzz_etl_read_entry.log`
- `artifacts/fuzz_structured_claim_validate.log`

## Gates

- Coverage threshold gate enforced by `cargo llvm-cov --fail-under-lines 95`.
- Fuzz smoke tests run each target for 30 seconds to catch panic-level regressions.
