# Contributing to EvidenceOS

Thanks for contributing to EvidenceOS, a security-critical verification kernel.

## Development setup

```bash
cargo build --workspace
```

Run the daemon locally:

```bash
cargo run -p evidenceos-daemon -- --listen 127.0.0.1:50051 --data-dir ./data
```

> `--etl-path` is deprecated. Use `--data-dir` for local and production launches.

## Required checks

Before opening a PR, run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Optional extended evidence:

```bash
make test-evidence
```

## Test and coverage expectations

- Add tests for any protocol-impacting change.
- Prefer black-box tests through public APIs and observable behavior.
- Add boundary and determinism checks for new numeric/configurable parameters.
- If you add or change a parameterized behavior, update the relevant row(s) in `docs/TEST_COVERAGE_MATRIX.md` in the same PR.
- If you add new test assets or claims about behavior, update `docs/TEST_EVIDENCE.md`.

## Pull request process

1. Keep scope narrow and security-relevant rationale explicit.
2. Include docs updates for user-facing behavior/flags.
3. Include a short validation section in the PR body with the commands you ran.
4. Ensure no new daemon launch examples use deprecated `--etl-path`.

## Security review focus

Reviewers prioritize:

- nondeterminism in hashes, canonicalization, ordering,
- panic risk in request/runtime paths,
- input validation and fail-closed behavior,
- logging hygiene (no secrets/raw payloads), and
- evidence-backed claims.
