# Test Coverage Matrix

## ASPEC policy
| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| Float policy / lane | `p_float_low_assurance_allows` (NEW) | `prop_lane_controls_fp_and_loop_rules` (NEW), `fuzz_aspec_verify` (existing, fixed) | `lane_fp_and_loop_matrix` (NEW) |
| Import allowlist | `p_import_allowlist_pass_and_fail` (existing) | `prop_import_allowlist_enforced` (NEW) | `invalid_wasm_fail_closed` (NEW) |
| Data segment cap | `p_data_boundaries` (existing) | `prop_data_segment_cap_enforced` (NEW) | `output_proxy_integration` (NEW) |
| Entropy threshold | `p_entropy_low_accept_high_with_magic_reject` (existing) | `prop_entropy_ratio_threshold_monotone` (NEW) | `invalid_wasm_fail_closed` (NEW) |
| Cyclomatic complexity | `p_branch_complexity_boundaries` (existing) | `prop_cyclomatic_complexity_threshold` (NEW) | `lane_fp_and_loop_matrix` (NEW) |
| Output proxy cap | `boundary_params_output_kolmogorov_and_heavy_flag` (existing) | `prop_output_proxy_threshold` (NEW) | `output_proxy_integration` (NEW) |
| Loop bounds | `p_loops_low_assurance_bounds_enforced` (NEW) | `prop_loop_bound_enforced_when_marker_present` (NEW) | `low_assurance_loop_bound_matrix` (NEW) |
| Heavy lane flag | `boundary_params_output_kolmogorov_and_heavy_flag` (existing) | `prop_heavy_lane_flag_threshold` (NEW) | `lane_fp_and_loop_matrix` (NEW) |

## Ledger
| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| alpha/budget validation | `rejects_invalid_alpha` (NEW), `rejects_invalid_budgets` (NEW) | `events_never_decrease_under_random_ops` (NEW) | `epsilon_delta_accounting_integration` (NEW) |
| charge/settle invariants | `charge_all_rejects_negative_or_nonfinite` (NEW), `settle_rejects_nonpositive_or_nonfinite` (NEW) | `random_meta_does_not_panic` (NEW) | `e_product_integration_matrix` (NEW) |
| event accounting | `events_record_kind_and_meta` (NEW), `epsilon_delta_accounting` (NEW) | `events_never_decrease_under_random_ops` (NEW) | `canary_pulse_integration` (NEW) |
| access credit / freeze | `access_credit_is_monotone` (NEW), `freeze_after_budget_exhaustion` (NEW) | `canary_pulse_proptest_freezes_at_threshold` (NEW) | `budget_exhaustion_is_fail_closed` (NEW) |
| joint/topic pools | `joint_pool_rejects_invalid_budget` (NEW), `topic_pool_rejects_invalid_budget` (NEW) | `joint_pool_invariants_proptest` (NEW), `topic_pool_invariants_proptest` (NEW) | `ledger_snapshot_system` (NEW) |
| e-combiners | `e_merge_rejects_invalid_inputs` (NEW), `e_merge_equal_rejects_empty` (NEW), `e_product_rejects_invalid_or_empty` (NEW) | `e_merge_proptest_invariants` (NEW), `e_product_proptest_invariants` (NEW) | `e_merge_integration_matrix` (NEW), `e_product_integration_matrix` (NEW) |

## Oracle
| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| tie-breaker / quantization | `tie_breaker_halfway_boundary` (NEW), `quantize_clamps_out_of_range` (NEW) | `tie_breaker_proptest` (NEW), `quantize_proptest` (NEW) | `tie_breaker_matrix` (NEW), `quantize_matrix` (NEW) |
| varlen codec / hash | `codec_hash_is_stable` (NEW), `calibration_fields_roundtrip` (NEW) | `oracle_roundtrip_varlen_symbols_proptest` (NEW) | `codec_hash_matrix` (NEW), `calibration_fields_matrix` (NEW) |
| ttl | `ttl_expired_boundary` (existing) | `ttl_expiry_proptest` (NEW) | `ttl_matrix` (NEW) |
| holdout validity | `holdout_labels_rejects_non_binary` (NEW), `accuracy_oracle_state_rejects_len_mismatch` (NEW) | `holdout_labels_proptest` (NEW), `oracle_query_proptest` (NEW) | `holdout_boundary_matrix` (NEW) |
| null spec | `null_accuracy_validation` (NEW), `fixed_e_value_validation` (NEW), `compute_e_value_rejects_nan` (NEW), `null_spec_domain_is_non_semantic` (NEW) | `null_accuracy_proptest` (NEW), `fixed_e_value_proptest` (NEW), `compute_e_value_proptest` (NEW), `null_spec_domain_proptest` (NEW) | `fixed_e_value_matrix` (NEW), `compute_e_value_matrix` (NEW) |

## ETL
| Parameter | Unit | Property/Fuzz | Integration/System |
|---|---|---|---|
| inclusion/consistency proof verification | `etl_proof_roundtrip_real_capsule_leaf` (existing) | `fuzz_etl_read_entry` (existing) | `etl_proofs_system` (NEW) |
| signature verification (STH/revocation) | `etl_persistence_restores_entries_root_and_revocations` (existing) | `fuzz_etl_read_entry` (existing) | `etl_proofs_system` (NEW) |

## How to update this matrix
When adding a new ASPEC/ledger/oracle/ETL parameter, add one row here and ensure at least one unit, one property/fuzz, and one integration/system test are linked to that row.
