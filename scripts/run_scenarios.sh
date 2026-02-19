#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="artifacts/scenarios"
mkdir -p "$ARTIFACT_DIR"
rm -f "$ARTIFACT_DIR"/*.json

SCENARIO_ARTIFACT_DIR="$ARTIFACT_DIR" \
  cargo test -p evidenceos-daemon --test scenarios_system -- --nocapture

[[ -s "$ARTIFACT_DIR/summary.json" ]] || { echo "missing scenario summary artifact"; exit 1; }
