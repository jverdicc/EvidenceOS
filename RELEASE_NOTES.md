# forc-submission-v1.0 Release Notes

## What this tag represents

`forc-submission-v1.0` is the FORC submission baseline for EvidenceOS. It captures the Rust kernel/daemon implementation and the accompanying documentation/artifact set used for the submission package.

## What is implemented

- Rust verification kernel and Rust daemon for UVP claim lifecycle execution.
- Deterministic lifecycle/ledger behavior with ETL-backed evidence and verification surfaces documented in the repo.
- Reproducibility materials and test documentation under `docs/` and `artifacts/`.

## What is specified but not fully implemented

This release includes roadmap/specification documents for capabilities that are intentionally marked as partial or not implemented. Canonical status is maintained in `docs/IMPLEMENTATION_STATUS.md`.

Examples called out there include partial or roadmap items (e.g., some TEE/PLN/profiled hardening paths) that are not claimed as fully production-complete in this tag.

## Known gaps

Known hardening and follow-up gaps are tracked as internal working notes in `docs/HARDENING_ISSUE_DRAFTS.md` (non-authoritative) and should be interpreted alongside the authoritative coverage and status docs.
