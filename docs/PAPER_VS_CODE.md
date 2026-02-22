# Paper ↔ Repo Parity (Living Document)

This document is the fastest way to answer: **what the FORC paper claims, what is implemented in the current repositories, and what is still partial/prototype**.

> Scope: this file is the shared parity source for the EvidenceOS + DiscOS split. If only one repo is in view, treat this page as authoritative and link to it from the other repo's README.

## Important repository reality (explicit)

- The paper artifact bundle includes a **Python reference implementation and Python experiments** used for paper evaluation snapshots.
- **Mainline DiscOS is now Rust** (separate repository), and EvidenceOS is Rust in this repository.
- Therefore, “paper artifact code” and “current production-oriented code” are intentionally not identical; parity is tracked row-by-row below.

## Paper claim → implementation parity table

| Paper section / claim | Repo implementation (EvidenceOS + DiscOS) | Status | Links |
| --- | --- | --- | --- |
| UVP trust boundary: untrusted userland (DiscOS) + trusted kernel (EvidenceOS) | EvidenceOS README and threat model docs define and enforce kernel/userland split; DiscOS remains separate untrusted orchestrator | Implemented | [`README.md`](../README.md), [`docs/THREAT_MODEL_BLACKBOX.md`](THREAT_MODEL_BLACKBOX.md), [`docs/uvp_blackbox_interface.md`](uvp_blackbox_interface.md) |
| Canonicalization + bounded leakage accounting (`W`, `k`) as first-class protocol primitives | Core docs and daemon runtime expose canonicalization, deterministic settlement, and accounting as required invariants | Implemented | [`README.md`](../README.md), [`docs/TEST_COVERAGE_MATRIX.md`](TEST_COVERAGE_MATRIX.md), [`docs/TEST_EVIDENCE.md`](TEST_EVIDENCE.md) |
| **PLN (Path-Length Normalization) controls** reduce timing channel bandwidth | Protocol-level PLN support exists, plus calibration harness and daemon profile validation; hardware cycle-accurate padding is explicitly not complete | **Partial** | [`docs/PLN.md`](PLN.md), [`crates/evidenceos-core/src/dlc.rs`](../crates/evidenceos-core/src/dlc.rs), [`crates/evidenceos-daemon/src/main.rs`](../crates/evidenceos-daemon/src/main.rs) |
| Structured claims profile for high-assurance outputs | Structured-claims canonicalization and bounded schema validation exist (including CBRN profile envelope checks) | Implemented | [`docs/STRUCTURED_CLAIMS.md`](STRUCTURED_CLAIMS.md), [`crates/evidenceos-daemon/src/vault.rs`](../crates/evidenceos-daemon/src/vault.rs) |
| **Appendix B-style structured claim DSL** (fully general DSL as written in paper appendix) | Current repo provides schema-driven structured-claim enforcement and canonical wire format, but no standalone appendix-DSL engine/spec artifact | **Partial** | [`docs/STRUCTURED_CLAIMS.md`](STRUCTURED_CLAIMS.md), [`docs/IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) |
| DiscOS implementation language in current mainline | DiscOS is a separate repo and current mainline is Rust; Python appears in paper artifact references/experiments, not as mainline implementation | Implemented (with historical divergence from artifact language) | [`README.md`](../README.md#evidenceos-rust) |
| Differential privacy lane/runtime path | Minimum DP lane reintroduced as ledger-side privacy loss accounting + budget enforcement (`ε`,`δ`) and optional claim-time budget wiring; this does **not** include host noise mechanisms yet | **Partial** | [`crates/evidenceos-core/src/ledger.rs`](../crates/evidenceos-core/src/ledger.rs), [`crates/evidenceos-daemon/src/server/handlers_v2.rs`](../crates/evidenceos-daemon/src/server/handlers_v2.rs), [`docs/DP_REINTRODUCTION_PLAN.md`](DP_REINTRODUCTION_PLAN.md) |

## FORC artifact reproduction path

Paper artifact reproduction should always pin **exact immutable refs** for both repos.

### EvidenceOS ref used for this parity baseline

- Repository: `EvidenceOS`
- Branch in this workspace: `work`
- Commit: `543958209679284260409b5797cbfc2f2ced6198`

### DiscOS ref used for paper artifact

- Repository: `DiscOS` (separate repo)
- Branch/tag/commit: `TODO (not available in this EvidenceOS-only workspace)`

### How to make this section actionable

When preparing/reviewing a FORC artifact bundle, replace the placeholders above with exact refs (preferred order):
1. Signed release tag
2. Full 40-char commit SHA
3. Branch name only as additional context (never as sole artifact locator)

Until those refs are filled, treat this section as an explicit TODO and do not claim exact paper artifact reproducibility from `main`/`work` alone.

## Reviewer quick answers (sub-60 seconds)

- **“Is PLN fully implemented?”** → **No, Partial** (protocol-level + calibration exists; cycle-accurate hardware padding is not complete).
- **“Is DiscOS Python?”** → **Paper artifact includes Python refs/experiments; current mainline DiscOS is Rust**.
- **“Is Appendix B structured claim DSL implemented?”** → **Partial** (schema-driven structured claims implemented; full appendix DSL as standalone engine is not present).
