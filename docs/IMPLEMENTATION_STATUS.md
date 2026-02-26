# Implementation Status (Paper Claims vs Repository Reality)

This document is the source of truth for whether a paper claim is production-implemented, partial, or still roadmap/spec-only.

## Paper-critical leakage and realization invariants

The following invariants are treated as protocol-level requirements and must remain enforced in code and tests:

- Per-oracle leakage charge: `k_i = log2(|Y_i|)`.
- Total leakage accounting: `k_tot = Σ k_i + k_out_bits` (+ any explicitly charged additive terms).
- Conservative alpha adjustment: `alpha' = alpha * 2^{-k_tot}`.
- Certification threshold: `E_value >= 2^{k_tot} / alpha`.
- Canonical realization decoding must reject malformed/non-canonical encodings **before** leakage is charged.
- No padding leakage: unused bits must be zero and out-of-range symbols must be rejected.

Reference enforcement points:

- `crates/evidenceos-core/src/ledger.rs`
- `crates/evidenceos-core/src/oracle.rs`
- `crates/evidenceos-core/src/aspec.rs`
- `docs/TEST_COVERAGE_PARAMETERS.md` (canonical byte decoder and leakage-accounting checks)

| Feature | Paper section | Implementation status | Code/tests |
|---|---|---|---|
| DiscOS↔EvidenceOS protocol compatibility (v1/v2 surface) | Protocol compatibility claims | Implemented | `crates/evidenceos-daemon/tests/protocol_compat_system.rs`, `crates/evidenceos-daemon/tests/golden_claims_vs_impl_system.rs` |
| Capsule verification (Signed Tree Head + inclusion proof) | Transparency/ETL verifiability claims | Implemented | `crates/evidenceos-daemon/tests/etl_verification_system.rs`, `crates/evidenceos-daemon/tests/golden_claims_vs_impl_system.rs`, `crates/evidenceos-core/src/crypto_transcripts.rs` |
| Revocation snapshot signature verification | Revocation integrity/auditability claims | Implemented | `crates/evidenceos-core/src/crypto_transcripts.rs`, `crates/evidenceos-daemon/tests/golden_claims_vs_impl_system.rs` |
| Signed oracle operator record verification (ed25519) | Oracle authenticity claims | Implemented | `crates/evidenceos-daemon/src/server/core.rs` (`verify_signed_oracle_record`, `verify_epoch_control_record`), `scripts/check_impl_status_guards.py` |
| Synthetic holdout derivation path | Holdout handling claims | Partial (insecure simulation mode only) | `crates/evidenceos-daemon/src/main.rs` (`--insecure-synthetic-holdout`), `crates/evidenceos-daemon/src/server/core.rs` (`derive_holdout_labels`), `scripts/check_impl_status_guards.py` |
| Differential privacy (DP) execution lane and host imports | DP accounting claims | Implemented behind feature flag (`dp_lane`) | `crates/evidenceos-core/src/dp_lane.rs`, `crates/evidenceos-core/tests/dp_lane_tests.rs`, `docs/DP_LANE.md` |
| PLN compile-time CFG branch equalization rewriter | PLN static+runtime padding claim | Not implemented (runtime fuel normalization + epoch rounding only) | `crates/evidenceos-daemon/src/server/core.rs` (`padded_fuel_total`), `crates/evidenceos-daemon/tests/vault_execution.rs`, `docs/PLN_PRODUCTION_PROFILE.md` |
| Holdout label encryption at rest (`labels.enc` + AES-256-GCM + env/KMS key providers) | Holdout encryption claims | Implemented (plaintext remains dev-only opt-in) | `crates/evidenceos-core/src/holdout_crypto.rs`, `crates/evidenceos-daemon/src/server/core.rs`, `crates/evidenceos-daemon/src/main.rs` |
| TEE backend selection and attestation capture (`disabled`/`noop`/`amd-sev-snp`) | TEE support claims | Partial (SEV-SNP helper-backed path is experimental) | `crates/evidenceos-core/src/tee.rs`, `crates/evidenceos-daemon/src/server/core.rs`, `crates/evidenceos-attest/src/lib.rs` |
| Access Credit Enforcement | Architecture specified | Config-file backend: Live; gRPC backend: Roadmap | `crates/evidenceos-daemon/src/server/core.rs`, `crates/evidenceos-daemon/tests/credit_tests.rs`, `docs/CREDIT_AND_ADMISSION.md` |
| Staked Admission (curve) | UVP Section 9.4 | Operator-provided: documented | `docs/CREDIT_AND_ADMISSION.md` |

## Status policy

- Any roadmap/spec-only behavior must be described as **Not implemented** or **Partial** in this table.
- CI guardrails (`scripts/check_impl_status_guards.py`) fail the build when known shortcut patterns reappear.


| DP Lane (Laplace) | Live (`dp_lane` feature) |
| DP Lane (Gaussian) | Live (`dp_lane` feature) |
| Advanced composition | Roadmap |
