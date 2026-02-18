#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/ci

echo "== daemon lifecycle v2 system tests =="
cargo test -p evidenceos-daemon --test e2e_claim_lifecycle -- --nocapture
cargo test -p evidenceos-daemon --test lifecycle_v2 -- --nocapture
