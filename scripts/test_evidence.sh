#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts target
: > artifacts/test_output.txt

{
  echo "== cargo fmt =="
  cargo fmt --check

  echo "== cargo clippy =="
  cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tee target/clippy-report.txt

  echo "== cargo test =="
  cargo test --workspace --all-targets --all-features

  echo "== cargo llvm-cov (with integration/system tests) =="
  cargo llvm-cov --workspace --all-features --all-targets --lcov --output-path target/coverage.lcov --fail-under-lines 95

  echo "== cargo fuzz smoke (30s per target) =="
  cargo +nightly fuzz run fuzz_aspec_verify -- -max_total_time=30
  cargo +nightly fuzz run fuzz_etl_read_entry -- -max_total_time=30
} 2>&1 | tee -a artifacts/test_output.txt
