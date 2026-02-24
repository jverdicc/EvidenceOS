# EvidenceOS research extensibility: what is real today vs. kernel-fork research

This document describes the **actual extension surface shipped today** and separates it from research-only kernel modifications.

For trial design and analysis assumptions, read `docs/EPISTEMIC_TRIAL_HARNESS.md`.
For NullSpec governance contracts, read `docs/NULLSPEC.md`.

## Extension surface categories

## A) No-kernel-changes extension (safe, shipped)

Use this when you want intervention arms without changing Rust kernel/runtime code.

### What you can change
- Trial-arm interventions in JSON (`scale_alpha_ppm`, `scale_access_credit_ppm`, `scale_k_bits_budget_ppm`).
- Assignment mode (`hashed` / `blocked`), stratification, and arm metadata.
- Downstream statistical analysis pipeline over ETL exports.

### Files and entry points
- `config/trial_arms.json` (default runtime config).
- `crates/evidenceos-daemon/src/trial/mod.rs` (schema, validation, defaults, assignment logic).
- `crates/evidenceos-daemon/src/server/core.rs` (config loading, env override `EVIDENCEOS_TRIAL_ARMS_CONFIG`, hash logging).
- `docs/EPISTEMIC_TRIAL_HARNESS.md` (analysis semantics and reporting expectations).
- `analysis/trial_dataframe.py`, `analysis/survival.py`, `analysis/consort.py` (analysis pipeline named by harness doc).

### Important guardrail
This path is the primary production mechanism for experimentation. Prefer it unless your question truly requires new statistical machinery inside the kernel.

---

## B) Config + contract extension (recommended for NullSpec work)

Use this when you need a different pre-committed null/e-process contract, while staying in the production governance model.

### What you can change
- Create and sign new `SignedNullSpecContractV1` contracts.
- Install/activate different contracts by `(oracle_id, holdout_handle)`.
- Choose among existing `NullSpecKind` / `EProcessKind` variants.

### Files and entry points
- `docs/NULLSPEC.md` (operator workflow: create/install/activate and fail-closed behavior).
- `crates/evidenceos-core/src/nullspec.rs` (contract schema, canonicalization, `NullSpecKind`, `EProcessKind`).
- `crates/evidenceos-core/src/nullspec_registry.rs` (loading/validation from registry files).
- `crates/evidenceosctl/src/main.rs` (`evidenceosctl nullspec create/install/activate`).
- `docs/OPERATIONS.md` (runtime registry paths/flags).

### When you must move to category C
If your null/e-process is not representable by the current enums (`NullSpecKind`, `EProcessKind`), you need kernel changes.

---

## C) Kernel fork extension (research)

Use this for new core math/logic not represented in shipped runtime knobs.

### Typical examples
- New cost-model families.
- New theorem-backed e-process constructions.
- New policy oracles / oracle backends.
- New e-process implementations in kernel decision logic.
- New `NullSpecKind` / `EProcessKind` enum variants and verification paths.

### Files typically modified
- `crates/evidenceos-core/src/nullspec.rs` and daemon evaluation paths for adding new `NullSpecKind` / `EProcessKind` variants and decision logic.
- `crates/evidenceos-daemon/src/trial/mod.rs` (if new arm action types are introduced).
- `crates/evidenceos-daemon/src/server/core.rs` and handler code (if runtime behavior changes).
- Tests under `crates/evidenceos-daemon/tests/` and core tests for determinism/safety invariants.

---

## Worked example: compare two NullSpecs

Goal: run a control/treatment study where control uses `nullspec_id = A` and treatment uses `nullspec_id = B`.

## Design intent
- Keep allocation/audit semantics from the Epistemic Trial Harness.
- Change only the pinned null contract between arms.

## What is possible today without kernel changes
1. Create/sign two contracts (`A`, `B`) via `evidenceosctl nullspec create`.
2. Install both contracts into the nullspec registry files.
3. Activate one contract for a given `(oracle_id, holdout_handle)` mapping.
4. Run trials and analyze ETL using the existing harness pipeline.

This supports **sequential runs** (or environment-level split), but not a native per-arm `nullspec_id` field in `trial_arms.json` today.

## What code changes are needed for true in-run A/B NullSpec assignment
To randomize `A` vs `B` within one trial config, add an arm-level nullspec binding and plumb it through assignment + capsule metadata:
- Extend `TrialArmConfig` in `crates/evidenceos-daemon/src/trial/mod.rs` with a validated nullspec selector (for example `nullspec_id_hex`).
- Resolve/apply the selected contract in daemon runtime where claim evaluation context is built (`crates/evidenceos-daemon/src/server/core.rs` and request handlers).
- Ensure claim capsules/telemetry continue to expose nullspec identity and trial commitment fields consistently.
- Add tests for deterministic assignment, fail-closed behavior on missing/invalid contracts, and ETL auditability.

### TODO roadmap
- Track native per-arm NullSpec assignment as a dedicated issue: <https://github.com/EvidenceOS/EvidenceOS/issues/new?title=Trial%20arms%3A%20per-arm%20nullspec_id%20binding>

---

## Practical decision guide

- If you are tuning intervention intensity only: use **A**.
- If you are changing the pre-committed null contract within existing schema: use **B**.
- If you need new statistical primitives or kernel decision math: use **C** (kernel fork).

This avoids drift between docs and shipped behavior while preserving a clear path for research upgrades.
