# Issue Drafts

This document tracks proposed GitHub issues for EvidenceOS maintainers to file.

---

## 1) README: Add Technical Summary + Verification Matrix + Threat Model

- **Labels:** `documentation`, `good first issue`
- **Definition of done:**
  - README includes a ~500-word technical summary.
  - README includes a Verification Matrix table with `Status` and `Evidence` links.
  - README includes an explicit out-of-scope section.

---

## 2) Docs drift fix: replace `--etl-path` with `--data-dir` everywhere

- **Labels:** `documentation`, `good first issue`
- **Scope:**
  - `README.md`
  - `.github/copilot-instructions.md`
  - Any docs/examples that still reference `--etl-path`.

---

## 3) Add `SECURITY.md` + `CONTRIBUTING.md` + Code of Conduct + issue templates

- **Labels:** `meta`, `good first issue`
- **Why:** security-critical repo needs responsible disclosure + predictable contributor workflow.

---

## 4) Observability: add Prometheus/OpenTelemetry metrics for ledger + ETL

- **Labels:** `observability`, `enhancement`
- **Acceptance criteria:**
  - Metrics endpoint is exposed.
  - Minimal dashboard JSON is added under `docs/`.

---

## 5) gRPC hardening: request size limits, timeouts, and per-endpoint rate limiting

- **Labels:** `security`, `hardening`
- **Acceptance criteria:**
  - Fail-closed behavior is implemented.
  - Integration tests prove limits are enforced.

---

## 6) ETL key rotation support (with historical key lookup by `key_id`)

- **Labels:** `security`, `enhancement`
- **Acceptance criteria:**
  - Integration test demonstrates verifying old STH signatures after rotation.

---

## 7) Fuzz expansion: add corpus-based fuzzing for gRPC decode + ETL proofs

- **Labels:** `testing`, `fuzzing`
- **Acceptance criteria:**
  - New fuzz targets exist.
  - CI documentation explains how to run fuzzing.

---

## 8) ASPEC corpus: add a minimized Wasm corpus + regression tests for each predicate

- **Labels:** `security`, `testing`
- **Acceptance criteria:**
  - Each ASPEC predicate has explicit pass/fail fixtures.
  - At least one fuzz/property test exists per predicate set.
