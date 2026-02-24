# Paper ↔ Repo Parity (Living Document)

This document states exactly how the FORC paper artifact story maps onto the current repositories.

## Repository reality

- Paper experiments were run from an archived **Python DiscOS artifact snapshot**.
- Current production DiscOS is a **Rust rewrite** in the separate DiscOS repository.
- EvidenceOS in this repository is the trusted Rust kernel implementation.

## Reproduction modes

- **QUICK verify (CI-friendly, offline):** `make -C artifacts/forc10 verify MODE=quick`
  - Runs deterministic `--quick` checks for the FORC10 harness.
  - Verifies generated outputs against committed expected files.
- **FULL reproduction (paper-faithful):** `make -C artifacts/forc10 verify MODE=full`
  - Validates authoritative artifact bundle checksums from `artifacts/forc10/FULL_ARTIFACT_MANIFEST.json`.
  - Runs all implemented paper experiments and table generation in `artifacts/forc10/original_python`.
  - Fetches from the DOI/release URL via `scripts/fetch_forc10_artifacts.sh --source remote` with strict SHA-256 enforcement (or `--source local --local-archive ...` for pre-downloaded archives).

## Exact pinned references

### EvidenceOS (this repo)
- Repository: `EvidenceOS`
- Commit pinned for this parity revision: `7ff066a7cac265aa17543c20d9ef203b9c673a77`

### DiscOS (paper-authoritative archived code)
- Archive authority: Zenodo record `https://zenodo.org/records/18685556` (DOI `10.5281/zenodo.18685556`)
- Artifact archive URL used by tooling: `https://zenodo.org/records/18685556/files/forc10-paper-artifact.tar.gz?download=1`
- Pinned artifact SHA-256: `baf1feb8d91e8acbe218b13f81aa5ea3f65092819c81c162142bb7dbdcd0856b`
- Mainline DiscOS implementation status: Rust rewrite (separate repository), while the paper-faithful experiment path remains the archived Python artifact.

## Reviewer interpretation guide

- "DiscOS in paper" means the archived Python artifact snapshot above.
- "DiscOS today" means the Rust mainline project.
- Claims about paper reproduction should cite FULL mode outputs and the manifest-pinned artifact hashes.

## FULL-mode coverage

FULL mode reproduces:
- `artifacts/forc10/out/raw/results.json`
- `artifacts/forc10/out/raw/results.csv`
- `artifacts/forc10/out/figures/table_1.csv`
- `artifacts/forc10/out/figures/table_1.md`

Explicit exclusion:
- No additional figure/table generators beyond Table 1 exist in the repository-aligned FORC10 harness.
