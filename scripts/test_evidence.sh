#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts target
: > artifacts/test_output.txt
: > artifacts/fuzz_aspec_verify.log
: > artifacts/fuzz_etl_read_entry.log
: > artifacts/fuzz_structured_claim_validate.log
: > artifacts/fuzz_ledger_ops.log
: > artifacts/fuzz_oracle_roundtrip.log
: > artifacts/fuzz_etl_ops.log

{
  echo "== cargo fmt =="
  cargo fmt --check

  echo "== cargo clippy =="
  cargo clippy --workspace --all-targets --all-features -- -D warnings

  echo "== cargo test =="
  cargo test --workspace --all-targets --all-features

  echo "== cargo llvm-cov (with integration/system tests) =="
  cargo llvm-cov --workspace --all-features --all-targets --lcov --output-path artifacts/coverage.lcov --fail-under-lines 95

  echo "== cargo fuzz smoke (30s per target) =="
  cargo +nightly fuzz run fuzz_aspec_verify -- -max_total_time=30 2>&1 | tee artifacts/fuzz_aspec_verify.log
  cargo +nightly fuzz run fuzz_etl_read_entry -- -max_total_time=30 2>&1 | tee artifacts/fuzz_etl_read_entry.log
  cargo +nightly fuzz run fuzz_structured_claim_validate -- -max_total_time=30 2>&1 | tee artifacts/fuzz_structured_claim_validate.log
  cargo +nightly fuzz run fuzz_ledger_ops -- -max_total_time=30 2>&1 | tee artifacts/fuzz_ledger_ops.log
  cargo +nightly fuzz run fuzz_oracle_roundtrip -- -max_total_time=30 2>&1 | tee artifacts/fuzz_oracle_roundtrip.log
  cargo +nightly fuzz run fuzz_etl_ops -- -max_total_time=30 2>&1 | tee artifacts/fuzz_etl_ops.log
} 2>&1 | tee -a artifacts/test_output.txt
