# Hardening Issue Drafts
*Internal working notes. Not authoritative documentation.
See docs/TEST_COVERAGE_MATRIX.md for current status.*

This file captures the repository scan results for `unwrap()`, `panic!()`, and `TODO` markers,
as well as issue drafts matching the requested format.

## Scan commands

- `rg -n "\\bunwrap!\\(|\\.unwrap\\(|\\bpanic!\\(|TODO"`
- `rg -n "\\bpanic!\\("`
- `rg -n "TODO|todo!\\(|\\bTODO\\b|FIXME"`

## Findings

### `unwrap()`

Found 14 instances, all in:

- `crates/evidenceos-core/src/aspec.rs` at lines 858, 950, 962, 975, 990, 1002, 1012, 1059, 1069, 1089, 1105, 1130, 1139, 1142.

### `panic!()`

No instances found.

### `TODO`

No instances found.

## Issue drafts

### 1) unwrap hardening

- **Title**: `[Hardening] Replace unsafe unwrap in crates/evidenceos-core/src/aspec.rs`
- **Body**:

  ```text
  The current implementation uses an unwrap at line 858 (also: 950, 962, 975, 990, 1002, 1012, 1059, 1069, 1089, 1105, 1130, 1139, 1142). This is a Denial-of-Service (DoS) vector for a safety kernel. Please refactor this to return a Result<T, KernelError> and handle it in the main gRPC loop.
  ```

- **Labels**: `technical-debt`, `security`, `industrial-strength`

### 2) panic hardening

No issue drafted because no `panic!()` usage was detected.

### 3) TODO hardening

No issue drafted because no `TODO` markers were detected.

## Note

Direct GitHub issue creation was not executed in this environment because `gh` CLI is unavailable and no GitHub API token is configured.
