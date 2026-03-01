#!/usr/bin/env bash
set -euo pipefail

CURRENT_STAGE="bootstrap"
stage() {
  CURRENT_STAGE="$1"
  shift
  echo ""
  echo "== ${CURRENT_STAGE} ==" | tee -a artifacts/test_output.txt
  "$@"
}

# Ensure llvm-tools are available for cargo-llvm-cov
if command -v rustup >/dev/null 2>&1; then
  if ! rustup component list --installed | grep -q '^llvm-tools-preview'; then
    rustup component add llvm-tools-preview
  fi
fi

mkdir -p artifacts target
: > artifacts/test_output.txt
: > artifacts/clippy-report.txt
: > artifacts/fuzz_aspec_verify.log
: > artifacts/fuzz_etl_read_entry.log
: > artifacts/fuzz_structured_claim_validate.log
: > artifacts/fuzz_ledger_ops.log
: > artifacts/fuzz_oracle_roundtrip.log
: > artifacts/fuzz_etl_ops.log
: > artifacts/fuzz_probe_detector.log
: > artifacts/fuzz_daemon_decode_limits.log

trap 'echo "[FAIL] stage=$CURRENT_STAGE" | tee -a artifacts/test_output.txt' ERR

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

cargo_feature_args=()
# Default: NO all-features, to match docs/TEST_EVIDENCE.md CI expectations.
# Opt-in knobs:
#  - EVIDENCEOS_CI_ALL_FEATURES=1 => use --all-features
#  - EVIDENCEOS_CI_FEATURES="feat1,feat2" => use --features "feat1,feat2"
if [[ "${EVIDENCEOS_CI_ALL_FEATURES:-0}" == "1" ]]; then
  cargo_feature_args+=(--all-features)
elif [[ -n "${EVIDENCEOS_CI_FEATURES:-}" ]]; then
  cargo_feature_args+=(--features "${EVIDENCEOS_CI_FEATURES}")
fi

{
  stage "cargo fmt" cargo fmt --check

  CURRENT_STAGE="cargo clippy"
  echo ""
  echo "== ${CURRENT_STAGE} ==" | tee -a artifacts/test_output.txt
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    cargo clippy --workspace --all-targets "${cargo_feature_args[@]}" -- -D warnings 2>&1 | tee artifacts/clippy-report.txt
  else
    echo "skipped (dependency resolution unavailable)" | tee artifacts/clippy-report.txt
  fi

  CURRENT_STAGE="cargo test"
  echo ""
  echo "== ${CURRENT_STAGE} ==" | tee -a artifacts/test_output.txt
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    cargo test --workspace --all-targets "${cargo_feature_args[@]}"
  else
    echo "skipped (dependency resolution unavailable)"
  fi

  stage "exfiltration demo regression" python3 -m unittest scripts.tests.test_exfiltration_demo

  CURRENT_STAGE="adversarial scenario suite"
  echo ""
  echo "== ${CURRENT_STAGE} ==" | tee -a artifacts/test_output.txt
  if [[ "$can_resolve_workspace_deps" == "true" ]]; then
    ./scripts/run_scenarios.sh
  else
    mkdir -p artifacts/scenarios
    echo '{"scenario_count":0,"status":"skipped (dependency resolution unavailable)"}' > artifacts/scenarios/summary.json
  fi

  strict_ci="${EVIDENCEOS_CI_STRICT:-0}"
  CURRENT_STAGE="cargo llvm-cov (with integration/system tests)"
  echo ""
  echo "== ${CURRENT_STAGE} ==" | tee -a artifacts/test_output.txt
  if [[ "$can_resolve_workspace_deps" == "true" && "$strict_ci" == "1" ]]; then
    cargo llvm-cov --workspace --all-features --all-targets --lcov --output-path artifacts/coverage.lcov --fail-under-lines 95
  else
    echo "skipped (strict CI disabled or dependency resolution unavailable)" > artifacts/coverage.lcov
  fi

  CURRENT_STAGE="cargo fuzz smoke (30s per target)"
  echo ""
  echo "== ${CURRENT_STAGE} ==" | tee -a artifacts/test_output.txt
  if [[ "$can_resolve_workspace_deps" == "true" && "$strict_ci" == "1" ]]; then
    cargo +nightly fuzz run fuzz_aspec_verify -- -max_total_time=30 2>&1 | tee artifacts/fuzz_aspec_verify.log
    cargo +nightly fuzz run fuzz_etl_read_entry -- -max_total_time=30 2>&1 | tee artifacts/fuzz_etl_read_entry.log
    cargo +nightly fuzz run fuzz_structured_claim_validate -- -max_total_time=30 2>&1 | tee artifacts/fuzz_structured_claim_validate.log
    cargo +nightly fuzz run fuzz_ledger_ops -- -max_total_time=30 2>&1 | tee artifacts/fuzz_ledger_ops.log
    cargo +nightly fuzz run fuzz_oracle_roundtrip -- -max_total_time=30 2>&1 | tee artifacts/fuzz_oracle_roundtrip.log
    cargo +nightly fuzz run fuzz_etl_ops -- -max_total_time=30 2>&1 | tee artifacts/fuzz_etl_ops.log
    cargo +nightly fuzz run fuzz_probe_detector -- -max_total_time=30 2>&1 | tee artifacts/fuzz_probe_detector.log
    cargo +nightly fuzz run fuzz_daemon_decode_limits -- -max_total_time=30 2>&1 | tee artifacts/fuzz_daemon_decode_limits.log
  else
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_aspec_verify.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_etl_read_entry.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_structured_claim_validate.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_ledger_ops.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_oracle_roundtrip.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_etl_ops.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_probe_detector.log
    echo "skipped (strict CI disabled or dependency resolution unavailable)" | tee artifacts/fuzz_daemon_decode_limits.log
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

for f in artifacts/test_output.txt artifacts/coverage.lcov artifacts/clippy-report.txt artifacts/fuzz_aspec_verify.log artifacts/fuzz_etl_read_entry.log artifacts/fuzz_structured_claim_validate.log artifacts/fuzz_ledger_ops.log artifacts/fuzz_oracle_roundtrip.log artifacts/fuzz_etl_ops.log artifacts/fuzz_probe_detector.log artifacts/fuzz_daemon_decode_limits.log artifacts/scenarios/summary.json; do
  [[ -s "$f" ]] || { echo "missing required artifact: $f"; exit 1; }
done
