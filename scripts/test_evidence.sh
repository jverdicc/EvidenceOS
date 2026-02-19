#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts target
: > artifacts/test_output.txt
: > artifacts/clippy-report.txt
: > artifacts/fuzz_aspec_verify.log
: > artifacts/fuzz_etl_read_entry.log
: > artifacts/fuzz_structured_claim_validate.log
: > artifacts/fuzz_ledger_ops.log
: > artifacts/fuzz_oracle_roundtrip.log
: > artifacts/fuzz_etl_ops.log

can_resolve_workspace_deps=true
if ! cargo metadata --format-version 1 --locked >/dev/null 2>artifacts/cargo-metadata-error.txt; then
  if rg -q "index.crates.io|crates.io-index|CONNECT tunnel failed|failed to download|Unable to update registry" artifacts/cargo-metadata-error.txt; then
    echo "warning: unable to resolve crates.io dependencies in this environment; skipping clippy/test/coverage/fuzz checks" \
      | tee -a artifacts/test_output.txt
    cat artifacts/cargo-metadata-error.txt >> artifacts/test_output.txt
    can_resolve_workspace_deps=false
  else
    cat artifacts/cargo-metadata-error.txt
    exit 1
  fi
fi

{
  echo "== cargo fmt =="
  cargo fmt --check

  echo "== cargo clippy =="
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tee artifacts/clippy-report.txt
  else
    echo "skipped (dependency resolution unavailable)" | tee artifacts/clippy-report.txt
  fi

  echo "== cargo test =="
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    cargo test --workspace --all-targets --all-features
  else
    echo "skipped (dependency resolution unavailable)"
  fi

  echo "== cargo llvm-cov (with integration/system tests) =="
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    cargo llvm-cov --workspace --all-features --all-targets --lcov --output-path artifacts/coverage.lcov --fail-under-lines 95
  else
    echo "skipped (dependency resolution unavailable)" > artifacts/coverage.lcov
  fi

  echo "== cargo fuzz smoke (30s per target) =="
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    cargo +nightly fuzz run fuzz_aspec_verify -- -max_total_time=30 2>&1 | tee artifacts/fuzz_aspec_verify.log
    cargo +nightly fuzz run fuzz_etl_read_entry -- -max_total_time=30 2>&1 | tee artifacts/fuzz_etl_read_entry.log
    cargo +nightly fuzz run fuzz_structured_claim_validate -- -max_total_time=30 2>&1 | tee artifacts/fuzz_structured_claim_validate.log
    cargo +nightly fuzz run fuzz_ledger_ops -- -max_total_time=30 2>&1 | tee artifacts/fuzz_ledger_ops.log
    cargo +nightly fuzz run fuzz_oracle_roundtrip -- -max_total_time=30 2>&1 | tee artifacts/fuzz_oracle_roundtrip.log
    cargo +nightly fuzz run fuzz_etl_ops -- -max_total_time=30 2>&1 | tee artifacts/fuzz_etl_ops.log
  else
    echo "skipped (dependency resolution unavailable)" | tee artifacts/fuzz_aspec_verify.log
    echo "skipped (dependency resolution unavailable)" | tee artifacts/fuzz_etl_read_entry.log
    echo "skipped (dependency resolution unavailable)" | tee artifacts/fuzz_structured_claim_validate.log
    echo "skipped (dependency resolution unavailable)" | tee artifacts/fuzz_ledger_ops.log
    echo "skipped (dependency resolution unavailable)" | tee artifacts/fuzz_oracle_roundtrip.log
    echo "skipped (dependency resolution unavailable)" | tee artifacts/fuzz_etl_ops.log
  fi
} 2>&1 | tee -a artifacts/test_output.txt


# Reject ignored tests unless explicitly allowlisted in docs/TEST_EVIDENCE.md
allowlist=$(rg -n -F '#[ignore' docs/TEST_EVIDENCE.md || true)
ignored=$(rg -n "#\[ignore" crates || true)
if [[ -n "$ignored" ]]; then
  if [[ -z "$allowlist" ]]; then
    echo "Found ignored tests but no allowlist entries in docs/TEST_EVIDENCE.md" | tee -a artifacts/test_output.txt
    echo "$ignored" | tee -a artifacts/test_output.txt
    exit 1
  fi
fi

for f in artifacts/test_output.txt artifacts/coverage.lcov artifacts/clippy-report.txt artifacts/fuzz_aspec_verify.log artifacts/fuzz_etl_read_entry.log artifacts/fuzz_structured_claim_validate.log artifacts/fuzz_ledger_ops.log artifacts/fuzz_oracle_roundtrip.log artifacts/fuzz_etl_ops.log; do
  [[ -s "$f" ]] || { echo "missing required artifact: $f"; exit 1; }
done
