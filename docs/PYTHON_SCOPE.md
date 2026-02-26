<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Python Scope

EvidenceOS runtime trust boundaries are Rust-first:

- The verification kernel is implemented in Rust.
- The daemon/runtime request path is implemented in Rust.

Python is intentionally retained for non-kernel workflows:

- `tests/paper_conformance` (paper conformance harness).
- `analysis/epistemic_trial` (clinical-trial survival analysis tooling and related analysis code).

## Trust boundary statement

Python is **not** in the trusted kernel TCB and is **not required** for daemon runtime operation.

## Operational implication

- Production daemon deployment and kernel execution do not depend on Python.
- Research analysis and paper-conformance workflows may depend on Python tooling.
