# Implementation Status (Paper Claims vs Repository Reality)

This document is the source of truth for whether a paper claim is production-implemented, partial, or still roadmap/spec-only.

| Feature | Paper section | Implementation status | Code/tests |
|---|---|---|---|
| DiscOS↔EvidenceOS protocol compatibility (v1/v2 surface) | Protocol compatibility claims | Implemented | `crates/evidenceos-daemon/tests/protocol_compat_system.rs`, `crates/evidenceos-daemon/tests/golden_claims_vs_impl_system.rs` |
| Capsule verification (Signed Tree Head + inclusion proof) | Transparency/ETL verifiability claims | Implemented | `crates/evidenceos-daemon/tests/etl_verification_system.rs`, `crates/evidenceos-daemon/tests/golden_claims_vs_impl_system.rs`, `crates/evidenceos-core/src/crypto_transcripts.rs` |
| Revocation snapshot signature verification | Revocation integrity/auditability claims | Implemented | `crates/evidenceos-core/src/crypto_transcripts.rs`, `crates/evidenceos-daemon/tests/golden_claims_vs_impl_system.rs` |
| Signed oracle operator record verification (ed25519) | Oracle authenticity claims | Implemented | `crates/evidenceos-daemon/src/server.rs` (`verify_signed_oracle_record`), `scripts/check_impl_status_guards.py` |
| Synthetic holdout derivation path | Holdout handling claims | Partial (insecure simulation mode only) | `crates/evidenceos-daemon/src/main.rs` (`--insecure-synthetic-holdout`), `crates/evidenceos-daemon/src/server.rs`, `scripts/check_impl_status_guards.py` |
| Differential privacy (DP) execution lane and host imports | DP accounting claims | Not implemented in this release (removed from runtime; see reintroduction plan) | `docs/DP_REINTRODUCTION_PLAN.md`, `scripts/check_impl_status_guards.py` |
| PLN compile-time CFG branch equalization rewriter | PLN static+runtime padding claim | Not implemented (runtime fuel normalization + epoch rounding only) | `crates/evidenceos-daemon/src/server.rs` (`padded_fuel_total`), `crates/evidenceos-daemon/tests/vault_execution.rs`, `docs/PLN_PRODUCTION_PROFILE.md` |
| Holdout label encryption at rest (`labels.enc` + AES-256-GCM + env/KMS key providers) | Holdout encryption claims | Implemented (plaintext remains dev-only opt-in) | `crates/evidenceos-core/src/holdout_crypto.rs`, `crates/evidenceos-daemon/src/server/core.rs`, `crates/evidenceos-daemon/src/main.rs` |
| TEE backend selection and attestation capture (`disabled`/`noop`/`amd-sev-snp`) | TEE support claims | Partial (SEV-SNP helper-backed path is experimental) | `crates/evidenceos-core/src/tee.rs`, `crates/evidenceos-daemon/src/server/core.rs`, `crates/evidenceos-attest/src/lib.rs` |
| Access Credit Enforcement | Architecture specified | Config-file backend: Live; gRPC backend: Roadmap | `crates/evidenceos-daemon/src/server/core.rs`, `crates/evidenceos-daemon/tests/credit_tests.rs`, `docs/CREDIT_AND_ADMISSION.md` |
| Staked Admission (curve) | UVP Section 9.4 | Operator-provided: documented | `docs/CREDIT_AND_ADMISSION.md` |

## Status policy

- Any roadmap/spec-only behavior must be described as **Not implemented** or **Partial** in this table.
- CI guardrails (`scripts/check_impl_status_guards.py`) fail the build when known shortcut patterns reappear.
