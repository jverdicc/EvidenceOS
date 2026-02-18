# Testing Evidence

## How to run tests

### Unit tests

```bash
cargo test -p evidenceos-core --lib
cargo test -p evidenceos-protocol --lib
cargo test -p evidenceos-daemon --lib
```

### System tests (black-box gRPC)

```bash
cargo test -p evidenceos-daemon --test e2e_claim_lifecycle
```

### Full workspace gate

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## System test matrix

The `e2e_claim_lifecycle` suite covers:

- **CreateClaim parameter space**
  - `alpha`: `{0.01, 0.5, 0.99}` plus invalid (`0` via epoch invalid branch).
  - `epoch_size`: boundary valid (`1`), invalid (`0`), nominal (`10`).
  - `oracle_num_symbols`: minimal valid (`2`) and nominal (`4`).
- **CommitArtifacts / ASPEC**
  - success with admissible module.
  - rejection modules with forbidden classes:
    - banned import,
    - `call_indirect`,
    - `memory.grow`,
    - floating-point instruction.
- **Lifecycle transitions**
  - `CreateClaim -> CommitArtifacts -> FreezeGates -> SealClaim -> ExecuteClaim -> FetchCapsule`.
  - repeated `ExecuteClaim` is rejected after settlement.
- **Capsule and ETL proofs**
  - inclusion proof verification,
  - consistency proof verification,
  - Signed Tree Head signature verification using persisted daemon key material.
- **Revocation flow**
  - server-streaming revocation watcher receives events after subscribe.
- **Persistence**
  - restart daemon on same `data_dir` and verify stable `tree_size`, `root_hash`, capsule hash, and valid STH signature.

## CI commands

CI executes:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cargo test -p evidenceos-daemon --test e2e_claim_lifecycle`
- `cargo llvm-cov --workspace --all-features --lcov --output-path target/llvm-cov/lcov.info`
