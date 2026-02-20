# Test Coverage Matrix

This matrix links key kernel/daemon behaviors to unit tests, property/fuzz tests, and system/integration tests.

## Protocol compatibility

| Behavior | Unit tests | Property/Fuzz | System/Integration |
|---|---|---|---|
| v1/v2 protobuf generation compiles | `crates/evidenceos-daemon/tests/pb_compile.rs` | N/A | `crates/evidenceos-daemon/tests/protocol_compat_system.rs::daemon_protocol_v1_and_v2_smoke` |
| v1/v2 capsule parity | N/A | N/A | `crates/evidenceos-daemon/tests/protocol_compat_system.rs::proto_roundtrip_backcompat_capsule` |

## Structured claims canonicalization

| Behavior | Unit tests | Property/Fuzz | System/Integration |
|---|---|---|---|
| Alias acceptance (`cbrn-sc.v1`, `schema/v1`, etc.) | `crates/evidenceos-core/src/structured_claims.rs::tests::accepts_alias_schema_id` | `fuzz/fuzz_targets/fuzz_structured_claim_validate.rs::fuzz_target` | `crates/evidenceos-daemon/tests/schema_aliases_system.rs::structured_claims_accepts_known_aliases` |
| Topic stability under aliases | N/A | N/A | `crates/evidenceos-daemon/tests/schema_aliases_system.rs::topic_id_stability_under_aliases` |
| Canonical JSON determinism | `crates/evidenceos-core/src/structured_claims.rs::tests::validates_and_canonicalizes_cbrn_sc` | `crates/evidenceos-core/src/structured_claims.rs::tests::cbrn_sc_roundtrip_proptest` | `crates/evidenceos-daemon/tests/structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |

## Transport hardening

| Behavior | Unit tests | Property/Fuzz | System/Integration |
|---|---|---|---|
| TLS required rejects plaintext | N/A | N/A | `crates/evidenceos-daemon/tests/transport_hardening_system.rs::tls_required_rejects_plaintext` |
| mTLS rejects client without cert | N/A | N/A | `crates/evidenceos-daemon/tests/transport_hardening_system.rs::mtls_rejects_no_client_cert` |
| Auth rejects missing token | `crates/evidenceos-daemon/src/auth.rs::tests::missing_token_rejected` | N/A | `crates/evidenceos-daemon/tests/transport_hardening_system.rs::auth_rejects_missing_token` |
| Auth accepts valid token | `crates/evidenceos-daemon/src/auth.rs::tests::correct_token_accepted` | N/A | `crates/evidenceos-daemon/tests/transport_hardening_system.rs::auth_accepts_valid_token` |

## Ledger / ETL integrity

| Behavior | Unit tests | Property/Fuzz | System/Integration |
|---|---|---|---|
| ETL inclusion & consistency verification | `crates/evidenceos-core/src/etl.rs::tests::inclusion_proof_full_space_and_tamper_resistance` | `fuzz/fuzz_targets/fuzz_etl_ops.rs::fuzz_target` | `crates/evidenceos-daemon/tests/etl_verification_system.rs::verifies_inclusion_consistency_and_sth_signature` |
| Claim lifecycle guards | `crates/evidenceos-daemon/src/server.rs::tests::lane_config_mapping_is_deterministic` | `fuzz/fuzz_targets/fuzz_daemon_decode_limits.rs::fuzz_target` | `crates/evidenceos-daemon/tests/lifecycle_v2.rs::cannot_execute_before_seal` |

## Adversarial scenario evidence

| Behavior | Unit tests | Property/Fuzz | System/Integration |
|---|---|---|---|
| Scenario spec parsing and deterministic ordering (`scenario_id`, `category`, `deterministic_seed`) | N/A | N/A | `crates/evidenceos-daemon/tests/scenarios_system.rs::scenarios_produce_deterministic_public_evidence` |
| Scenario expected outcome enforcement (`PASS`, `REJECT`) | N/A | N/A | `crates/evidenceos-daemon/tests/scenarios_system.rs::scenarios_produce_deterministic_public_evidence` |
| Public ETL evidence verification in scenario runner | `crates/evidenceos-core/src/etl.rs::tests::inclusion_proof_full_space_and_tamper_resistance` | `fuzz/fuzz_targets/fuzz_etl_ops.rs::fuzz_target` | `crates/evidenceos-daemon/tests/scenarios_system.rs::scenarios_produce_deterministic_public_evidence` |

## Probe / distillation detection

| Behavior | Unit tests | Property/Fuzz | System/Integration |
|---|---|---|---|
| Probe thresholds and boundary transitions (Clean/Throttle/Escalate/Freeze) | `crates/evidenceos-daemon/src/probe.rs::tests::threshold_boundaries` | `crates/evidenceos-daemon/src/probe.rs::tests::detector_invariants` | `crates/evidenceos-daemon/tests/probing_detection_system.rs::probing_detection_grades_response_and_emits_evidence` |
| Sliding-window expiry and cooldown | `crates/evidenceos-daemon/src/probe.rs::tests::window_expiry_and_cooldown` | `fuzz/fuzz_targets/fuzz_probe_detector.rs::fuzz_target` | `crates/evidenceos-daemon/tests/probing_detection_system.rs::probing_detection_grades_response_and_emits_evidence` |
| Semantic uniqueness and topic diversity accounting | `crates/evidenceos-daemon/src/probe.rs::tests::diversity_counts` | `fuzz/fuzz_targets/fuzz_probe_detector.rs::fuzz_target` | `crates/evidenceos-daemon/tests/probing_detection_system.rs::probing_detection_grades_response_and_emits_evidence` |
| NullSpec ttl_epochs boundary | `crates/evidenceos-core/src/nullspec.rs::tests::ttl_boundary` | N/A | `crates/evidenceos-daemon/tests/execute_claim_v2_settlement_system.rs::execute_fails_closed_without_active_nullspec` |
| NullSpec alpha vector (Dirichlet) | `crates/evidenceos-core/src/eprocess.rs::tests::hand_verified_k3_sequence` | `crates/evidenceos-core/src/eprocess.rs::tests::eprocess_is_finite_nonnegative` | `crates/evidenceos-daemon/tests/execute_claim_v2_settlement_system.rs::oracle_e_value_drives_settlement_and_capsule_wealth` |
| NullSpec p0 vector length K | `crates/evidenceos-core/src/eprocess.rs::tests::rejects_bad_inputs` | `crates/evidenceos-core/src/eprocess.rs::tests::eprocess_is_finite_nonnegative` | `crates/evidenceos-daemon/tests/execute_claim_v2_settlement_system.rs::oracle_e_value_drives_settlement_and_capsule_wealth` |
| Activation mapping required | `crates/evidenceos-core/src/nullspec_store.rs` | N/A | `crates/evidenceos-daemon/tests/execute_claim_v2_settlement_system.rs::execute_fails_closed_without_active_nullspec` |
| Resolution hash mismatch fail-closed | N/A | N/A | `crates/evidenceos-daemon/tests/execute_claim_v2_settlement_system.rs` |
