# Test Evidence

This document describes how to reproduce protocol, transport, and kernel evidence locally in under 15 minutes on a typical developer machine.

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`.
- No external `protoc` install needed (vendored protoc is used).

## Fast reproducibility path

Run the same checks expected in CI:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For protocol/transport focused verification, run the targeted suite:

```bash
cargo test -p evidenceos-protocol
cargo test -p evidenceos-daemon protocol_compat_system
cargo test -p evidenceos-daemon transport_hardening_system
cargo test -p evidenceos-daemon schema_aliases_system
```

## Evidence captured by these tests

### Protocol compatibility

- `daemon_protocol_v1_and_v2_smoke`
  - proves daemon serves both `evidenceos.v1` and `evidenceos.v2` client paths.
- `proto_roundtrip_backcompat_capsule`
  - proves shared fields match when fetched through v1 and v2 clients.

### Transport hardening

- `tls_required_rejects_plaintext`
  - plaintext gRPC traffic fails against TLS-only daemon.
- `mtls_rejects_no_client_cert`
  - client-authenticated TLS enforcement rejects clients with no cert.
- `auth_rejects_missing_token`
  - interceptor rejects missing bearer tokens with `UNAUTHENTICATED`.
- `auth_accepts_valid_token`
  - valid bearer token succeeds.

### Schema alias stability

- `structured_claims_accepts_known_aliases`
  - known DiscOS schema aliases are accepted.
- `topic_id_stability_under_aliases`
  - canonicalization removes alias-induced topic drift.

## Artifact strategy

Use existing project scripts when generating auditable CI-style logs:

```bash
make test-evidence
```

This writes logs and coverage artifacts under `artifacts/` (coverage, test output, clippy output, fuzz logs).

## Adversarial Scenario Suite Evidence

The adversarial scenario suite executes deterministic scenario specs from `docs/scenarios/` against a live daemon using only public gRPC APIs and returned evidence artifacts.

Run locally:

```bash
./scripts/run_scenarios.sh
```

Or via CI-equivalent evidence generation:

```bash
make test-evidence
```

Expected artifacts:

- `artifacts/scenarios/summary.json`
- `artifacts/scenarios/lifecycle_pass.json`
- `artifacts/scenarios/reject_invalid_claim.json`

Each artifact contains: scenario metadata, request/response summaries, expected vs observed verdict, and ETL proof verification results.
