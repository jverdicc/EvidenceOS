# Testing Evidence

This document records the exact verification commands run for this change and the captured artifacts.

## Environment versions

Command:

```bash
rustc --version
cargo --version
wasmtime --version
```

Captured output (`artifacts/ci/tool_versions.log`):

```text
rustc 1.93.1 (01f6ddf75 2026-02-11)
cargo 1.93.1 (083ac5135 2025-12-15)
bash: command not found: wasmtime
```

Since a standalone `wasmtime` binary is unavailable in this environment, the repo dependency version was confirmed from `Cargo.lock` as `wasmtime 25.0.3`.

## Build, format, lint, and test gates

### 1) Build

Command:

```bash
cargo build --workspace
```

Artifact: `artifacts/ci/build.log`

### 2) Formatting

Commands:

```bash
cargo fmt --all
cargo fmt --all -- --check
```

Artifact: `artifacts/ci/fmt.log`

### 3) Clippy (warnings denied)

Command:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Artifact: `artifacts/ci/clippy.log`

### 4) Full test matrix

Command:

```bash
cargo test --workspace --all-features --all-targets
```

Artifact: `artifacts/ci/test.log`

Result summary from `artifacts/ci/test.log`:
- `evidenceos-core`: 52 passed, 0 failed.
- `evidenceos-daemon` unit tests: 3 passed, 0 failed.
- `evidenceos-daemon` integration tests:
  - `e2e_claim_lifecycle`: 3 passed, 0 failed.
  - `lifecycle_v2`: 4 passed, 0 failed.
  - `pb_compile`: 1 passed, 0 failed.
  - `vault_execution`: 5 passed, 0 failed.
- `evidenceos-protocol`: all tests passed.

## Deterministic daemon system test script (v2 lifecycle)

Script added:

```bash
scripts/system_test_v2.sh
```

It runs:

```bash
cargo test -p evidenceos-daemon --test e2e_claim_lifecycle -- --nocapture
cargo test -p evidenceos-daemon --test lifecycle_v2 -- --nocapture
```

Artifact: `artifacts/ci/system_test.log`

This exercises daemon startup/shutdown and v2 lifecycle integration coverage through tonic end-to-end tests.

## Artifact index

- `artifacts/ci/build.log`
- `artifacts/ci/fmt.log`
- `artifacts/ci/clippy.log`
- `artifacts/ci/test.log`
- `artifacts/ci/system_test.log`
- `artifacts/ci/tool_versions.log`
