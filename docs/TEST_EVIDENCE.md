# Test Evidence Harness

Evidence artifacts are generated with Makefile targets at repository root.

## Commands

- `make fmt`
- `make lint`
- `make test`
- `make test-evidence`
- `make audit`

### Tooling prerequisites

- `cargo llvm-cov` is required for `make test-evidence`.
  - Install with: `cargo install cargo-llvm-cov`
- `cargo audit` is required for `make audit`.
  - Install with: `cargo install cargo-audit`

## Artifact outputs

`make test-evidence` writes:

- `artifacts/coverage.lcov`
- `artifacts/coverage-html/`
- `artifacts/test.log`
- `artifacts/lint.log`

`make audit` writes:

- `artifacts/audit.log`

## Required thresholds

- `evidenceos-core` line coverage: **>= 90%**
- `evidenceos-daemon` line coverage: **>= 80%**
- No ignored tests unless explicitly documented with rationale.

The `make test-evidence` target enforces both coverage minimums and rejects ignored tests in crate sources.
