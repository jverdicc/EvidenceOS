# Testing Evidence

## Command

```bash
./scripts/test_evidence.sh
```

## Captured Example (abridged)

```text
Coverage policy consistency check passed (threshold: 95%)
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

- Coverage policy consistency gate enforced by `./scripts/check_coverage_policy.py`, which verifies that `scripts/test_evidence.sh` (source of truth) matches `Makefile`, `docs/TEST_EVIDENCE.md`, `README.md`, and this file.
- Coverage threshold gate enforced by `cargo llvm-cov --fail-under-lines 95`.
- Fuzz smoke tests run each target for 30 seconds to catch panic-level regressions.

## Epistemic Trial Harness additions

- Added ETL schema compatibility tests for `ClaimSettlementEvent` in `crates/evidenceos-core/src/etl.rs`:
  - Legacy event payloads without trial fields deserialize with `None` defaults.
  - Full trial metadata payload round-trips through serde.
- Added trial harness tests under feature flag `trial-harness` in `crates/evidenceos-core/src/trial/tests.rs`:
  - ClassicalSupportBound threshold parity with kernel barrier math.
  - `k_cost` parity with `log2(alphabet_size)` charge semantics.
  - Router assignment distribution check over 10,000 draws.
  - Router nonce uniqueness checks.
  - Property tests for threshold parity and settlement-event serde/backward-compat.
