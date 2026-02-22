<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reader map

Use this page to pick a fast reading path based on your role.

## If you are a security reviewer

Start here:
1. [`docs/threat_model_worked_example.md`](threat_model_worked_example.md)
2. [`docs/uvp_blackbox_interface.md`](uvp_blackbox_interface.md)
3. [`docs/OPERATION_LEVEL_SECURITY.md`](OPERATION_LEVEL_SECURITY.md)
4. [`docs/TEST_COVERAGE_MATRIX.md`](TEST_COVERAGE_MATRIX.md)

Focus on: adaptive leakage model (W/k), lane transitions, deterministic settlement, ETL auditability, and fail-closed behavior.

## If you are an ML eval engineer / researcher

Start here:
1. [`docs/EPISTEMIC_TRIAL_HARNESS.md`](EPISTEMIC_TRIAL_HARNESS.md)
2. [`docs/TRIAL_HARNESS_ANALYSIS.md`](TRIAL_HARNESS_ANALYSIS.md)
3. [`examples/exfiltration_demo/`](../examples/exfiltration_demo/)
4. [`docs/threat_model_worked_example.md`](threat_model_worked_example.md)
5. [`docs/uvp_blackbox_interface.md`](uvp_blackbox_interface.md)
6. [`docs/ORACLES.md`](ORACLES.md)

Focus on: how to run the Epistemic Trial Harness end-to-end, how probing pressure is metered, how oracle outputs are constrained, and how to reason about verification under adaptive querying.

## If you are in governance / policy

Start here:
1. [`docs/uvp_blackbox_interface.md`](uvp_blackbox_interface.md)
2. [`docs/threat_model_worked_example.md`](threat_model_worked_example.md)
3. [`docs/STRUCTURED_CLAIMS.md`](STRUCTURED_CLAIMS.md)
4. [`docs/NULLSPEC_GOVERNANCE.md`](NULLSPEC_GOVERNANCE.md)

Focus on: what claims are certifiable, what guarantees are and are not provided, and what evidence exists for downstream audit.

## If you are a contributor

Start here:
1. [`README.md`](../README.md)
2. [`docs/START_HERE.md`](START_HERE.md)
3. [`docs/COVERAGE.md`](COVERAGE.md)
4. [`docs/TESTING_EVIDENCE.md`](TESTING_EVIDENCE.md)

Then run the baseline checks:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Daemon server module map

The daemon gRPC server is split for faster code-path review:

- `crates/evidenceos-daemon/src/server/mod.rs`: service/state wiring and shared helpers.
- `crates/evidenceos-daemon/src/server/handlers_v2.rs`: v2 gRPC handlers.
- `crates/evidenceos-daemon/src/server/handlers_v1.rs`: v1 compatibility handlers and transcode bridge.
- `crates/evidenceos-daemon/src/server/lifecycle.rs`: lifecycle transition module placeholder.
- `crates/evidenceos-daemon/src/server/sealing.rs`: sealing module placeholder.
- `crates/evidenceos-daemon/src/server/execution.rs`: execution module placeholder.
- `crates/evidenceos-daemon/src/server/telemetry.rs`: telemetry module placeholder.
