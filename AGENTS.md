# AGENTS.md (EvidenceOS)

## Review guidelines
- Treat any nondeterminism affecting ledger hashes, ordering, or canonicalization as P0.
- Treat panics in request paths / daemon runtime as P0.
- No new network-facing endpoints without explicit justification and tests.
- Validate all gRPC inputs (size bounds, enums, strings); fail closed on invalid.
- Do not log secrets or raw payloads.
- CI must pass: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
