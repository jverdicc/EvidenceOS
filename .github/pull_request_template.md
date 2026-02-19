## Summary

Describe the change and why it is needed.

## Related references

- `AGENTS.md`
- `TESTING_EVIDENCE.md`
- `docs/TEST_EVIDENCE.md`
- `docs/TEST_COVERAGE_MATRIX.md`

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] Docs only
- [ ] Test-only

## Protocol and safety impact

- [ ] No protocol logic changes
- [ ] Determinism impact reviewed (ordering/hash/canonicalization)
- [ ] Panic risk reviewed on request/runtime paths
- [ ] Network-facing inputs validated fail-closed
- [ ] No secrets/raw payloads added to logs

## Testing checklist

- [ ] Tests are black-box (public APIs/external behavior)
- [ ] Tests do not copy/paste production logic into assertions
- [ ] Numeric boundary cases are tested
- [ ] Deterministic functions/flows include determinism assertions
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] No new `unsafe` code

## Evidence

Paste key command outputs or links to artifacts.
