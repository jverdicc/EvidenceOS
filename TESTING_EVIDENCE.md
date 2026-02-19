# Testing Evidence

## Commands

```bash
cargo test --all
cargo test --workspace
cargo fuzz run fuzz_aspec_verify -runs=2000
cargo fuzz run fuzz_etl_read_entry -runs=2000
```

## Tool versions

Capture with:

```bash
rustc --version
cargo --version
cargo fuzz --version
```

## What this proves

These checks exercise unit tests, integration/system tests (including tonic server lifecycle paths), bounded proptests embedded in crate tests, and fuzz smoke for ASPEC/ETL parser invariants. Together they provide fail-closed checks for policy validation, ledger accounting/monotonicity, oracle encoding and null-spec behavior, and ETL proof parsing and verification.
