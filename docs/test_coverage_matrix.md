# EvidenceOS Test Coverage Matrix (Parameter-Level)

This matrix maps required parameter-level API coverage to concrete tests.

## ASPEC (`crates/evidenceos-core/src/aspec.rs`)

| Parameter | Unit test | Property/Fuzz | Integration/System |
|---|---|---|---|
| `lane` | `p_loops_high_assurance_reject` | `prop_lane_controls_fp_and_loop_rules`, `fuzz_aspec_verify` | `lane_fp_and_loop_matrix`, `aspec_policy_violations_fail_closed` |
| `allowed_imports` | `p_import_allowlist_rejects_disallowed` | `prop_import_allowlist_enforced`, `fuzz_aspec_verify` | `aspec_policy_violations_fail_closed` |
| `max_data_segment_bytes` | `p_data_segment_boundaries` | `prop_data_segment_cap_enforced`, `fuzz_aspec_verify` | `aspec_policy_violations_fail_closed` |
| `max_entropy_ratio` | `p_entropy_low_accept_high_with_magic_reject` | `prop_entropy_ratio_threshold_monotone`, `fuzz_aspec_verify` | `aspec_policy_violations_fail_closed` |
| `max_cyclomatic_complexity` | `p_branch_complexity_boundaries` | `prop_cyclomatic_complexity_threshold`, `fuzz_aspec_verify` | `aspec_policy_violations_fail_closed` |
| `max_output_bytes` | `boundary_params_output_kolmogorov_and_heavy_flag` | `prop_output_proxy_threshold`, `fuzz_aspec_verify` | `output_proxy_integration`, `aspec_policy_violations_fail_closed` |
| `max_loop_bound` | `p_loops_low_assurance_bounds_enforced` | `prop_loop_bound_enforced_when_marker_present`, `fuzz_aspec_verify` | `low_assurance_loop_bound_matrix` |
| `kolmogorov_proxy_cap` | `boundary_params_output_kolmogorov_and_heavy_flag` | `prop_heavy_lane_flag_threshold`, `fuzz_aspec_verify` | `output_proxy_integration` |

## Ledger (`crates/evidenceos-core/src/ledger.rs`)

| Parameter/API | Unit test | Property/Fuzz | Integration/System |
|---|---|---|---|
| `alpha_prime` | `alpha_prime_correctness` | `fuzz_ledger_ops` | `ledger_public_api_matrix` |
| `certification_barrier` | `barrier_correctness` | `fuzz_ledger_ops` | `ledger_public_api_matrix` |
| `e_merge` | `e_merge_uniform_weights`, `e_merge_rejects_invalid_inputs` | `e_merge_proptest_invariants`, `fuzz_ledger_ops` | `e_merge_integration_matrix`, `ledger_public_api_matrix` |
| `e_merge_equal` | `e_merge_equal_rejects_empty` | `fuzz_ledger_ops` | `ledger_public_api_matrix` |
| `e_product` | `e_product_rejects_invalid_or_empty` | `e_product_proptest_invariants`, `fuzz_ledger_ops` | `e_product_integration_matrix`, `ledger_public_api_matrix` |
| `JointLeakagePool` | `joint_pool_charges_correctly`, `joint_pool_rejects_invalid_budget` | `joint_pool_invariants_proptest`, `fuzz_ledger_ops` | `ledger_public_api_matrix` |
| `TopicBudgetPool` | `topic_budget_is_shared`, `topic_pool_rejects_invalid_budget` | `topic_pool_invariants_proptest`, `fuzz_ledger_ops` | `ledger_public_api_matrix` |
| `CanaryPulse` | `canary_pulse_freezes_at_threshold` | `canary_pulse_proptest_freezes_at_threshold`, `fuzz_ledger_ops` | `canary_pulse_integration`, `ledger_public_api_matrix` |
| `ConservationLedger` | `charge_all_rejects_negative_or_nonfinite`, `freeze_after_budget_exhaustion` | `conservation_ledger_invariants_hold_under_random_sequences`, `fuzz_ledger_ops` | `epsilon_delta_accounting_integration`, `ledger_public_api_matrix` |

## Oracle (`crates/evidenceos-core/src/oracle.rs`)

| Parameter/API | Unit test | Property/Fuzz | Integration/System |
|---|---|---|---|
| `NullSpec.domain` | `null_spec_domain_is_non_semantic` | `null_spec_domain_proptest`, `fuzz_oracle_roundtrip` | `fixed_e_value_matrix`, `oracle_public_api_matrix` |
| `NullSpec.null_accuracy` | `null_accuracy_validation` | `null_accuracy_proptest`, `fuzz_oracle_roundtrip` | `compute_e_value_matrix` |
| `EValueFn::LikelihoodRatio` | `null_spec_likelihood_ratio_at_null` | `compute_e_value_proptest`, `fuzz_oracle_roundtrip` | `compute_e_value_matrix` |
| `EValueFn::Fixed` | `fixed_e_value_validation` | `fixed_e_value_proptest`, `fuzz_oracle_roundtrip` | `fixed_e_value_matrix`, `oracle_public_api_matrix` |
| `OracleResolution.num_symbols` | `encoding_len_known_values`, `encode_decode_handles_multibyte_symbol_space` | `oracle_roundtrip_varlen_symbols_proptest`, `fuzz_oracle_roundtrip` | `codec_hash_matrix`, `oracle_public_api_matrix` |
| `OracleResolution.bit_width` | `encoding_len_known_values` | `oracle_roundtrip_varlen_symbols_proptest`, `fuzz_oracle_roundtrip` | `codec_hash_matrix` |
| `OracleResolution.codec_hash` | `codec_hash_is_stable` | `fuzz_oracle_roundtrip` | `codec_hash_matrix` |
| `OracleResolution.calibration_manifest_hash` | `calibration_fields_roundtrip` | `fuzz_oracle_roundtrip` | `calibration_fields_matrix` |
| `OracleResolution.calibrated_at_epoch` | `ttl_expired_boundary` | `ttl_expiry_proptest`, `fuzz_oracle_roundtrip` | `ttl_matrix`, `oracle_public_api_matrix` |
| `OracleResolution.ttl_epochs` | `ttl_none_vs_zero_and_one_boundaries` | `ttl_expiry_proptest`, `fuzz_oracle_roundtrip` | `ttl_matrix`, `oracle_public_api_matrix` |
| `OracleResolution.delta_sigma` | `delta_sigma_zero_disables_hysteresis` | `oracle_query_proptest`, `fuzz_oracle_roundtrip` | `holdout_boundary_matrix` |
| `OracleResolution.tie_breaker` | `tie_breaker_halfway_boundary` | `tie_breaker_proptest`, `fuzz_oracle_roundtrip` | `tie_breaker_matrix`, `oracle_public_api_matrix` |
| `encode_bucket/decode_bucket/validate_canonical_bytes` | `decode_rejects_wrong_length`, `decode_rejects_unused_bits_nonzero` | `oracle_canonical_validation_roundtrip`, `fuzz_oracle_roundtrip` | `oracle_public_api_matrix` |
| `quantize_unit_interval` | `quantize_clamps_out_of_range`, `quantize_nan_rejected` | `quantize_proptest`, `fuzz_oracle_roundtrip` | `quantize_matrix`, `oracle_public_api_matrix` |
| `query` | `accuracy_oracle_state_rejects_non_binary_preds` | `oracle_query_proptest`, `fuzz_oracle_roundtrip` | `oracle_public_api_matrix` |

## ETL (`crates/evidenceos-core/src/etl.rs`)

| Parameter/API | Unit test | Property/Fuzz | Integration/System |
|---|---|---|---|
| Merkle funcs (`leaf_hash`, `node_hash`, `merkle_root*`) | `fixed_vectors_for_three_leaves`, `ct_merkle_root_matches_reference_for_full_range` | `fuzz_etl_ops`, `fuzz_etl_read_entry` | `etl_public_api_matrix` |
| Inclusion proof APIs | `inclusion_proof_full_space_and_tamper_resistance` | `etl_inclusion_and_consistency_hold_for_random_appends`, `fuzz_etl_ops` | `etl_public_api_matrix` |
| Consistency proof APIs | `consistency_proof_full_space_and_tamper_resistance` | `etl_inclusion_and_consistency_hold_for_random_appends`, `fuzz_etl_ops` | `etl_public_api_matrix` |
| `RevocationEntry` | `revocation_taints_descendants_via_dependency_edges` | `fuzz_etl_ops` | `etl_public_api_matrix` |
| `Etl::open_or_create/append/read_entry/root_hash/root_at_size` | `etl_persistence_restores_entries_root_and_revocations` | `etl_inclusion_and_consistency_hold_for_random_appends`, `fuzz_etl_ops` | `etl_public_api_matrix` |
| `Etl::revoke/is_revoked/taint_descendants` | `revocation_closure_rebuilds_after_restart_and_taints_new_descendant` | `fuzz_etl_ops` | `etl_public_api_matrix` |
