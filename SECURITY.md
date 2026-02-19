# Security Policy

## Supported scope

Security reports are accepted for:

- `evidenceos-core` and `evidenceos-daemon`,
- gRPC and protocol validation paths,
- deterministic execution and canonicalization behavior,
- ledger/accounting and ETL integrity.

## Reporting a vulnerability

Please report privately to **security@evidenceos.org**.

Include:

- affected commit/tag,
- impact summary,
- reproduction steps or proof-of-concept,
- any suggested mitigation.

Do **not** open a public issue for unpatched vulnerabilities.

## Response targets

- Initial acknowledgement: within 3 business days.
- Triage status update: within 7 business days.
- Fix timeline: depends on severity and release risk.

## Disclosure policy

- Coordinate disclosure with maintainers.
- Public advisory follows availability of a fix or mitigation.
- Credit reporters unless anonymity is requested.

## Severity guidance

The project treats as high priority:

- nondeterminism affecting hashes/ordering/canonicalization,
- panics on daemon request paths/runtime,
- validation gaps in network-facing input handling,
- weaknesses in ETL proof/signature verification paths.

These priorities align with `AGENTS.md` and existing test evidence expectations.

## Validation requirements for fixes

Security fixes should include regression tests and pass:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See `TESTING_EVIDENCE.md`, `docs/TEST_EVIDENCE.md`, and `docs/TEST_COVERAGE_MATRIX.md` for broader verification and coverage expectations.
