# Contributing to EvidenceOS

Thanks for your interest in improving EvidenceOS. This repository is a Rust verification-kernel implementation, so contribution quality is judged by **determinism, fail-closed behavior, and auditability**.

## Before you start

1. Read `AGENTS.md` for repository-level guardrails and CI requirements.
2. Read `TESTING_EVIDENCE.md` and `docs/TEST_EVIDENCE.md` for the expected validation workflow.
3. Read `docs/TEST_COVERAGE_MATRIX.md` to understand required test coverage patterns for ASPEC, ledger, oracle, and ETL surfaces.

## Development workflow

1. Create a topic branch from `main`.
2. Keep pull requests scoped (one concern per PR).
3. Prefer small commits with clear messages.
4. Update documentation and tests in the same PR when behavior or interfaces change.

## Required local checks

Run these before opening or updating a PR:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For stronger evidence, run the project harness:

```bash
make test-evidence
```

## Testing policy for contributors

- Test behavior through public APIs and externally visible interfaces.
- Do **not** copy production logic into tests; use fixtures and expected outcomes.
- Add boundary-case tests for numeric parameters (limits, zero, negatives when invalid, NaN/Inf where relevant).
- Add determinism assertions for deterministic functions (stable ordering, hash/canonicalization consistency, repeatability).
- New endpoints or protocol-surface changes require explicit justification and tests.

The matrix in `docs/TEST_COVERAGE_MATRIX.md` should be updated when adding new parameterized behavior.

## Pull request checklist

- [ ] Scope is clear and justified.
- [ ] No unintended protocol-logic drift.
- [ ] Tests are black-box focused and cover boundaries.
- [ ] Determinism expectations are explicitly tested where applicable.
- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass.
- [ ] Documentation updates included (`README.md`, `TESTING_EVIDENCE.md`, or docs under `docs/` as needed).

## Code review expectations

Reviewers will prioritize:

- nondeterminism risks in ledger hashes, ordering, and canonicalization,
- panic risk on daemon/request paths,
- input validation and fail-closed behavior,
- logging hygiene (no secrets/raw payloads), and
- compatibility with existing test evidence expectations.
