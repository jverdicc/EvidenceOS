# forc-submission-v1.0 Release Notes

## Release anchor
- Tag: `forc-submission-v1.0`
- Scope: FORC 2026 submission baseline for EvidenceOS (Rust kernel + supporting docs/artifacts).

## Implemented in this release
- Rust verification kernel and daemon baseline for UVP-style claim verification.
- Core documentation set in `docs/` covering architecture, threat model, runbooks, testing evidence, and integration guidance.
- Trial-harness specification and analysis references for clinical-trial-style evaluation workflows.
- Reproducibility artifacts for FORC submission context and historical comparison materials.

## Specified but not fully implemented
- Some roadmap/planning documents define future hardening and migration targets that are intentionally non-normative.
- Optional long-term Python reduction remains a future migration objective; Python stays for analysis/reproduction support.

## Documentation updates in this release
- Root markdown housekeeping and migration of legacy/draft notes into `docs/`.
- README streamlined as project front-door with canonical links to threat model and harness analysis.
- Added repository metadata helper under `.github/REPO_DESCRIPTION.md`.

## Compatibility / migration notes
- Runtime/kernel path remains Rust-only.
- Existing Python analysis/reproduction paths are unchanged and remain documented.
- Legacy setup instructions are retained as reference notes under `docs/LEGACY_SETUP.md`.

## Verification checklist
- Case-insensitive filename collision check script executed.
- Documentation drift checks executed.
- Markdown link integrity validated for `README.md` and `docs/` references.
