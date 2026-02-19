# Support

## Where to ask for help

- **Usage questions / troubleshooting:** Open a GitHub issue using the relevant template.
- **Feature ideas:** Open a GitHub feature request.
- **Security concerns:** Follow `SECURITY.md` and email security@evidenceos.org.
- **Code of conduct concerns:** Follow `CODE_OF_CONDUCT.md`.

## What to include in support requests

Provide enough context for reproducibility:

- EvidenceOS version/commit,
- OS and Rust toolchain (`rustc --version`, `cargo --version`),
- exact command(s) run,
- expected behavior vs actual behavior,
- sanitized logs or error output.

## Self-service diagnostics

Before opening a request, run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For complete evidence artifacts and coverage checks, see `TESTING_EVIDENCE.md` and `docs/TEST_EVIDENCE.md`.

## Project references

For contribution and test expectations:

- `CONTRIBUTING.md`
- `AGENTS.md`
- `TESTING_EVIDENCE.md`
- `docs/TEST_EVIDENCE.md`
- `docs/TEST_COVERAGE_MATRIX.md`
