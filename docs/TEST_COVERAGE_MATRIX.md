# EvidenceOS Parameter Coverage Matrix

This matrix maps each externally meaningful parameter to **unit + property/fuzz + integration/system** tests that exist in this repository.

## ASPEC (`crates/evidenceos-core/src/aspec.rs`)

| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| `lane` | `crates/evidenceos-core/src/aspec.rs::matrix_tests::lane_fp_and_loop_matrix` | `fuzz/fuzz_targets/fuzz_aspec_verify.rs::fuzz_target` | `crates/evidenceos-core/tests/aspec_policy_matrix_integration.rs::lane_fp_and_loop_matrix` |
| `allowed_imports` | `...::matrix_tests::rejects_unallowed_import` | `fuzz_aspec_verify` | `aspec_policy_matrix_integration.rs::invalid_wasm_fail_closed` |
| `max_data_segment_bytes` | `...::matrix_tests::data_segment_cap_enforced` | `fuzz_aspec_verify` | `crates/evidenceos-core/tests/aspec_thresholds_integration.rs::max_data_segment_bytes_boundary` |
| `max_entropy_ratio` | `...::matrix_tests::entropy_ratio_cap` | `fuzz_aspec_verify` | `aspec_thresholds_integration.rs::max_entropy_ratio_boundary` |
| `max_cyclomatic_complexity` | `...::matrix_tests::cyclomatic_cap_enforced` | `fuzz_aspec_verify` | `aspec_thresholds_integration.rs::max_cyclomatic_complexity_boundary` |
| `max_output_bytes` | `...::matrix_tests::output_proxy_matrix` | `fuzz_aspec_verify` | `aspec_policy_matrix_integration.rs::output_proxy_integration` |
| `max_loop_bound` | `...::matrix_tests::loop_bound_cap` | `fuzz_aspec_verify` | `aspec_policy_matrix_integration.rs::low_assurance_loop_bound_matrix` |
| `kolmogorov_proxy_cap` | `...::matrix_tests::heavy_lane_flag_boundary` | `fuzz_aspec_verify` | `aspec_thresholds_integration.rs::kolmogorov_proxy_cap_heavy_lane_flag_boundary` |
| `float_policy` | `...::matrix_tests::float_policy_reject_all` | `fuzz_aspec_verify` | `aspec_policy_matrix_integration.rs::lane_fp_and_loop_matrix` |

## Ledger (`crates/evidenceos-core/src/ledger.rs`)

| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| `alpha` | `ledger.rs::matrix_tests::rejects_invalid_alpha` | `ledger.rs::tests::conservation_ledger_invariants_hold_under_random_sequences` | `crates/evidenceos-core/tests/ledger_matrix_integration.rs::alpha_budget_matrix` |
| Ledger budget (`with_budget`) | `ledger.rs::matrix_tests::freeze_after_budget_exhaustion` | `...conservation_ledger_invariants...` | `ledger_matrix_integration.rs::ledger_budget_boundary_matrix` |
| `k_bits` charge input | `ledger.rs::matrix_tests::charge_all_rejects_negative_or_nonfinite` | `ledger.rs::tests::k_bits_total_never_decreases` | `ledger_matrix_integration.rs::ledger_charge_matrix` |
| `access_credit` | `ledger.rs::matrix_tests::access_credit_is_monotone` | `ledger.rs::matrix_tests::topic_pool_invariants_proptest` | `crates/evidenceos-core/tests/ledger_pools_integration.rs::topic_budget_pool_boundary_matrix_with_covariance` |
| `covariance_charge` | `ledger.rs::tests::dependence_tax_charges_covariance` | `ledger.rs::matrix_tests::topic_pool_invariants_proptest` | `ledger_pools_integration.rs::topic_budget_pool_boundary_matrix_with_covariance` |
| `e_value` settlement | `ledger.rs::matrix_tests::settle_rejects_nonpositive_or_nonfinite` | `ledger.rs::tests::monotone_high_water_mark_never_decreases` | `ledger_matrix_integration.rs::settle_e_value_matrix` |
| `JointLeakagePool.k_bits_budget` | `ledger.rs::matrix_tests::joint_pool_rejects_invalid_budget` | `ledger.rs::matrix_tests::joint_pool_invariants_proptest` | `ledger_pools_integration.rs::joint_leakage_pool_budget_boundary_matrix` |
| `TopicBudgetPool.k_bits_budget` | `ledger.rs::matrix_tests::topic_pool_rejects_invalid_budget` | `ledger.rs::matrix_tests::topic_pool_invariants_proptest` | `ledger_pools_integration.rs::topic_budget_pool_boundary_matrix_with_covariance` |
| `TopicBudgetPool.access_credit_budget` | `ledger.rs::tests::topic_budget_is_shared` | `ledger.rs::matrix_tests::topic_pool_invariants_proptest` | `ledger_pools_integration.rs::topic_budget_pool_boundary_matrix_with_covariance` |
| `CanaryPulse.alpha_drift` | `ledger.rs::tests::canary_pulse_freezes_at_threshold` | `ledger.rs::matrix_tests::canary_pulse_invariants_proptest` | `ledger_pools_integration.rs::canary_pulse_threshold_matrix_deterministic` |
| `e_merge` weights | `ledger.rs::tests::e_merge_uniform_weights` | `ledger.rs::matrix_tests::e_merge_weights_invariants_proptest` | `ledger_matrix_integration.rs::e_merge_matrix` |

## Oracle (`crates/evidenceos-core/src/oracle.rs`)

| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| `OracleResolution.num_symbols` | `oracle.rs::tests::encoding_len_known_values` | `oracle.rs::matrix_tests::oracle_roundtrip_varlen_symbols_proptest` | `crates/evidenceos-core/tests/oracle_matrix_integration.rs::symbol_count_matrix` |
| `bit_width` canonical length | `oracle.rs::tests::decode_rejects_wrong_length` | `...oracle_roundtrip_varlen_symbols_proptest` | `oracle_matrix_integration.rs::canonical_bytes_matrix` |
| `calibration_manifest_hash` | `oracle.rs::matrix_tests::calibration_fields_roundtrip` | `oracle.rs::matrix_tests::ttl_monotone_proptest` | `oracle_matrix_integration.rs::ttl_and_calibration_matrix` |
| `calibrated_at_epoch` | `oracle.rs::tests::ttl_expired_boundary` | `oracle.rs::matrix_tests::ttl_monotone_proptest` | `oracle_matrix_integration.rs::ttl_and_calibration_matrix` |
| `ttl_epochs` | `oracle.rs::tests::ttl_expired_boundary` | `oracle.rs::matrix_tests::ttl_monotone_proptest` | `oracle_matrix_integration.rs::ttl_and_calibration_matrix` |
| `delta_sigma` | `oracle.rs::tests::delta_sigma_zero_disables_hysteresis` | `oracle.rs::matrix_tests::oracle_query_proptest` | `oracle_matrix_integration.rs::hysteresis_matrix` |
| `tie_breaker` | `oracle.rs::matrix_tests::tie_breaker_unit_cases` | `oracle.rs::matrix_tests::tie_breaker_proptest` | `oracle_matrix_integration.rs::tie_break_matrix` |
| `NullSpec.domain` | `oracle.rs::matrix_tests::null_spec_rejects_empty_domain` | `oracle.rs::matrix_tests::null_spec_domain_proptest` | `oracle_matrix_integration.rs::nullspec_matrix` |
| `NullSpec.null_accuracy` | `oracle.rs::matrix_tests::null_spec_rejects_invalid_null_accuracy` | `oracle.rs::matrix_tests::null_accuracy_proptest` | `oracle_matrix_integration.rs::nullspec_matrix` |
| `NullSpec.e_value_fn` | `oracle.rs::tests::null_spec_likelihood_ratio_at_null` | `oracle.rs::matrix_tests::compute_e_value_proptest` | `oracle_matrix_integration.rs::evalue_matrix` |
| holdout labels input | `oracle.rs::matrix_tests::holdout_labels_rejects_empty` | `oracle.rs::matrix_tests::holdout_labels_proptest` | `oracle_matrix_integration.rs::holdout_matrix` |

## ETL (`crates/evidenceos-core/src/etl.rs`)

| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| `append(data)` entry length | `etl.rs::tests::validate_entry_len_boundaries` | `fuzz/fuzz_targets/fuzz_etl_read_entry.rs::fuzz_target` | `crates/evidenceos-daemon/tests/etl_verification_system.rs::verifies_inclusion_consistency_and_sth_signature` |
| `read_entry(index)` | `etl.rs::tests::etl_persistence_restores_entries_root_and_revocations` | `fuzz_etl_read_entry` | `crates/evidenceos-daemon/tests/e2e_claim_lifecycle.rs::claim_lifecycle_happy_path` |
| inclusion proof (`leaf_index`,`tree_size`,`path`) | `etl.rs::tests::inclusion_proof_full_space_and_tamper_resistance` | `etl.rs::tests::etl_inclusion_and_consistency_hold_for_random_appends` | `etl_verification_system.rs::verifies_inclusion_consistency_and_sth_signature` |
| consistency proof (`old_size`,`new_size`,`path`) | `etl.rs::tests::consistency_proof_full_space_and_tamper_resistance` | `etl.rs::tests::etl_inclusion_and_consistency_hold_for_random_appends` | `etl_verification_system.rs::verifies_inclusion_consistency_and_sth_signature` |
| revocation closure (`revoke`,`taint_descendants`) | `etl.rs::tests::revocation_taints_descendants_via_dependency_edges` | `etl.rs::tests::etl_inclusion_and_consistency_hold_for_random_appends` | `crates/evidenceos-daemon/tests/e2e_claim_lifecycle.rs::revoke_claim_propagates` |

## Structured Claims (`crates/evidenceos-core/src/structured_claims.rs`)

| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| `output_schema_id` (`legacy/v1`) | `structured_claims.rs::tests::legacy_bypass_round_trips_bytes` | `fuzz/fuzz_targets/fuzz_structured_claim_validate.rs::fuzz_target` | `crates/evidenceos-daemon/tests/structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| `output_schema_id` (`cbrn-sc.v1`,`cbrn/v1`) | `structured_claims.rs::tests::accepts_alias_schema_id` | `fuzz_structured_claim_validate` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| float rejection | `structured_claims.rs::tests::rejects_float_anywhere` | `fuzz_structured_claim_validate` | `structured_claims_system.rs::invalid_cbrn_sc_fails_closed_without_etl_append` |
| unknown field rejection | `structured_claims.rs::tests::rejects_unknown_fields` | `fuzz_structured_claim_validate` | `structured_claims_system.rs::invalid_cbrn_sc_fails_closed_without_etl_append` |
| quantity bounds (`value`,`confidence_bps`) | `structured_claims.rs::tests::validates_and_canonicalizes_cbrn_sc` | `structured_claims.rs::tests::cbrn_sc_roundtrip_proptest` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| references bounds | `structured_claims.rs::tests::validates_and_canonicalizes_cbrn_sc` | `structured_claims.rs::tests::cbrn_sc_roundtrip_proptest` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| reason codes bounds | `structured_claims.rs::tests::validates_and_canonicalizes_cbrn_sc` | `structured_claims.rs::tests::cbrn_sc_roundtrip_proptest` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| deterministic canonical bytes | `structured_claims.rs::tests::validates_and_canonicalizes_cbrn_sc` | `structured_claims.rs::tests::cbrn_sc_roundtrip_proptest` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| kout accounting | `structured_claims.rs::tests::validates_and_canonicalizes_cbrn_sc` | `fuzz_structured_claim_validate` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |

## ExecuteClaimV2 Settlement / Lane Config (`crates/evidenceos-daemon/src/server.rs`)

| Parameter / behavior | Unit test(s) | Property/fuzz | System/integration |
| --- | --- | --- | --- |
| `vault_result.e_value_total` settlement | `vault_execution.rs::vault_e_value_becomes_zero_when_accuracy_is_zero` | `fuzz/fuzz_targets/fuzz_oracle_roundtrip.rs::fuzz_target` | `crates/evidenceos-daemon/tests/structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| `kout_bits_total` leakage charge | `vault_execution.rs::structured_schema_output_near_bound_succeeds_and_plus_one_fails` | `fuzz/fuzz_targets/fuzz_structured_claim_validate.rs::fuzz_target` | `structured_claims_system.rs::valid_cbrn_sc_output_passes_and_returns_capsule` |
| structured output size bound by schema | `vault_execution.rs::structured_schema_output_near_bound_succeeds_and_plus_one_fails` | `fuzz_structured_claim_validate` | `structured_claims_system.rs::structured_output_too_large_rejected` |
| lane to policy mapping (`requested_lane`/`LaneConfig`) | `server.rs` unit tests (lane mapping) | `evidenceos-core aspec property tests` | `structured_claims_system.rs` + `lifecycle_v2.rs` |
| STH domain-separated signature digest | `server.rs::signed_tree_head_signature_verifies_and_tamper_fails` | `fuzz_etl_ops` | `etl_verification_system.rs::verifies_inclusion_consistency_and_sth_signature` |
