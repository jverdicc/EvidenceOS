# EvidenceOS research extensibility

This document describes the production-supported extension model in EvidenceOS.

For trial design and analysis assumptions, read `docs/EPISTEMIC_TRIAL_HARNESS.md`.
For NullSpec governance contracts, read `docs/NULLSPEC.md`.

## Supported extension modes

### 1) Declarative extension via signed NullSpec contracts (safe, shipped)

This is the supported production path for extending theorem/e-process behavior **without** changing kernel code.

#### Workflow
1. Author a `SignedNullSpecContractV1` JSON payload.
2. Sign it with an approved key.
3. Place the signed contract in the NullSpec registry directory.
4. Run the daemon with:
   - `--nullspec-registry-dir` pointing to your contract registry
   - `--trusted-nullspec-keys-dir` pointing to the approved signer keyset
5. Activate/select contracts by `(oracle_id, holdout_handle)` using `evidenceosctl nullspec` commands.

#### Production guarantees
- Contracts are canonicalized and signature-verified.
- The daemon fails closed for invalid/untrusted contracts.
- This path is configuration-and-governance driven; no runtime plugin loading is exposed.

### 2) Code-level extension via trusted PRs (kernel changes)

Use this when your theorem family is not representable by current enums.

#### Required changes
- Extend Rust enums (for example `NullSpecKind` and/or `EProcessKind`).
- Add validation and evaluation logic for the new variants.
- Add tests covering determinism, fail-closed behavior, and safety invariants.

This is a trusted source-change path (PR + review), not an operator-side plugin surface.

## What is not a supported production path

- Trait-registry/plugin-style runtime extension points in `evidenceos-core` are not part of the supported production API.
- New network-facing extension endpoints are not provided.

## Practical decision guide

- If you need new contracts within existing schema: use **declarative signed contracts**.
- If you need new theorem families/primitive kinds: use **code-level PR extension**.
