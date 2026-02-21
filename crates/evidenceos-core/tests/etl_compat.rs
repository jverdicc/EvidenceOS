use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use evidenceos_core::capsule::{
    canonical_json, ClaimCapsule, ClaimState, EnvironmentAttestations, LedgerReceipt,
    LedgerSnapshot, ManifestEntry, PolicyOracleReceiptLike, TopicOracleReceiptLike,
};
use evidenceos_core::crypto_transcripts::sth_signature_digest;
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyClaimCapsule {
    schema: String,
    claim_id_hex: String,
    topic_id_hex: String,
    output_schema_id: String,
    code_ir_manifests: Vec<ManifestEntry>,
    dependency_capsule_hashes: Vec<String>,
    structured_output_hash_hex: String,
    canonical_output_hash_hex: String,
    kout_bits_upper_bound: u64,
    wasm_hash_hex: String,
    judge_trace_hash_hex: String,
    holdout_ref: String,
    holdout_commitment_hex: String,
    ledger: LedgerSnapshot,
    ledger_receipts: Vec<LedgerReceipt>,
    e_value: f64,
    certified: bool,
    decision: i32,
    reason_codes: Vec<u32>,
    semantic_hash_hex: Option<String>,
    physhir_hash_hex: Option<String>,
    lineage_root_hash_hex: Option<String>,
    output_schema_id_hash_hex: Option<String>,
    holdout_handle_hash_hex: Option<String>,
    disagreement_score: Option<u32>,
    semantic_physhir_distance_bits: Option<u32>,
    escalate_to_heavy: Option<bool>,
    policy_oracle_receipts: Vec<PolicyOracleReceiptLike>,
    topic_oracle_receipt: Option<TopicOracleReceiptLike>,
    nullspec_id_hex: Option<String>,
    oracle_resolution_hash_hex: Option<String>,
    eprocess_kind: Option<String>,
    nullspec_contract_hash_hex: Option<String>,
    trial_commitment_schema_version: Option<u32>,
    trial_arm_id: Option<u32>,
    trial_intervention_id: Option<String>,
    trial_intervention_version: Option<String>,
    trial_arm_parameters_hash_hex: Option<String>,
    trial_nonce_hex: Option<String>,
    trial_commitment_hash_hex: Option<String>,
    environment_attestations: EnvironmentAttestations,
    state: ClaimState,
}

fn small_string() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::char::range('a', 'z'), 1..16)
        .prop_map(|chars| chars.into_iter().collect())
}

fn tiny_hex(len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), len).prop_map(hex::encode)
}

fn finite_f64() -> impl Strategy<Value = f64> {
    (-100_000i64..100_000i64).prop_map(|v| v as f64 / 100.0)
}

fn claim_state_strategy() -> impl Strategy<Value = ClaimState> {
    prop_oneof![
        Just(ClaimState::Uncommitted),
        Just(ClaimState::Sealed),
        Just(ClaimState::Executing),
        Just(ClaimState::Settled),
        Just(ClaimState::Certified),
        Just(ClaimState::Revoked),
        Just(ClaimState::Tainted),
        Just(ClaimState::Stale),
        Just(ClaimState::Frozen),
    ]
}

fn ledger_snapshot_strategy() -> impl Strategy<Value = LedgerSnapshot> {
    (
        (
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
        ),
        (
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
            finite_f64(),
        ),
    )
        .prop_map(
            |(
                (
                    alpha,
                    log_alpha_target,
                    alpha_prime,
                    log_alpha_prime,
                    k_bits_total,
                    barrier_threshold,
                    barrier,
                    wealth,
                ),
                (w_max, epsilon_total, delta_total, access_credit_spent, compute_fuel_spent),
            )| LedgerSnapshot {
                alpha,
                log_alpha_target,
                alpha_prime,
                log_alpha_prime,
                k_bits_total,
                barrier_threshold,
                barrier,
                wealth,
                w_max,
                epsilon_total,
                delta_total,
                access_credit_spent,
                compute_fuel_spent,
            },
        )
}

fn environment_strategy() -> impl Strategy<Value = EnvironmentAttestations> {
    (
        small_string(),
        small_string(),
        small_string(),
        prop::option::of(small_string()),
        prop::option::of(tiny_hex(32)),
        prop::option::of(tiny_hex(16)),
    )
        .prop_map(
            |(
                runtime_version,
                aspec_version,
                protocol_version,
                tee_backend_name,
                tee_measurement_hex,
                tee_attestation_blob_b64,
            )| EnvironmentAttestations {
                runtime_version,
                aspec_version,
                protocol_version,
                tee_backend_name,
                tee_measurement_hex,
                tee_attestation_blob_b64,
            },
        )
}

fn claim_capsule_strategy() -> impl Strategy<Value = ClaimCapsule> {
    let manifest_strategy =
        (small_string(), tiny_hex(8)).prop_map(|(kind, hash_hex)| ManifestEntry { kind, hash_hex });
    let receipt_strategy = (small_string(), finite_f64(), small_string())
        .prop_map(|(lane, value, unit)| LedgerReceipt { lane, value, unit });
    let policy_receipt_strategy = (
        small_string(),
        tiny_hex(32),
        tiny_hex(32),
        small_string(),
        any::<u32>(),
    )
        .prop_map(
            |(oracle_id, manifest_hash_hex, wasm_hash_hex, decision, reason_code)| {
                PolicyOracleReceiptLike {
                    oracle_id,
                    manifest_hash_hex,
                    wasm_hash_hex,
                    decision,
                    reason_code,
                }
            },
        );
    let topic_receipt_strategy = (
        tiny_hex(32),
        tiny_hex(32),
        small_string(),
        any::<u64>(),
        tiny_hex(64),
    )
        .prop_map(
            |(
                claim_manifest_hash_hex,
                semantic_hash_hex,
                model_id,
                timestamp_unix,
                signature_hex,
            )| {
                TopicOracleReceiptLike {
                    claim_manifest_hash_hex,
                    semantic_hash_hex,
                    model_id,
                    timestamp_unix,
                    signature_hex,
                }
            },
        );

    (
        (small_string(), small_string(), small_string()),
        (
            prop::collection::vec(manifest_strategy, 0..4),
            prop::collection::vec(tiny_hex(8), 0..4),
            tiny_hex(32),
            tiny_hex(32),
            0u64..(1 << 20),
            tiny_hex(32),
            tiny_hex(32),
            small_string(),
            tiny_hex(32),
        ),
        (
            ledger_snapshot_strategy(),
            prop::collection::vec(receipt_strategy, 0..4),
            finite_f64(),
            any::<bool>(),
            any::<i32>(),
            prop::collection::vec(any::<u32>(), 0..4),
        ),
        (
            prop::option::of(tiny_hex(32)),
            prop::option::of(tiny_hex(32)),
            prop::option::of(tiny_hex(32)),
            prop::option::of(tiny_hex(32)),
            prop::option::of(tiny_hex(32)),
            prop::option::of(any::<u32>()),
            prop::option::of(any::<u32>()),
            prop::option::of(any::<bool>()),
        ),
        (
            prop::collection::vec(policy_receipt_strategy, 0..3),
            prop::option::of(topic_receipt_strategy),
            prop::option::of(tiny_hex(32)),
            prop::option::of(tiny_hex(32)),
            prop::option::of(small_string()),
            prop::option::of(tiny_hex(32)),
        ),
        (
            prop::option::of(any::<u32>()),
            prop::option::of(any::<u32>()),
            prop::option::of(small_string()),
            prop::option::of(small_string()),
            prop::option::of(tiny_hex(32)),
            prop::option::of(tiny_hex(16)),
            prop::option::of(tiny_hex(32)),
            environment_strategy(),
            claim_state_strategy(),
        ),
    )
        .prop_map(
            |(
                (claim_id_hex, topic_id_hex, output_schema_id),
                (
                    mut code_ir_manifests,
                    mut dependency_capsule_hashes,
                    structured_output_hash_hex,
                    canonical_output_hash_hex,
                    kout_bits_upper_bound,
                    wasm_hash_hex,
                    judge_trace_hash_hex,
                    holdout_ref,
                    holdout_commitment_hex,
                ),
                (ledger, ledger_receipts, e_value, certified, decision, reason_codes),
                (
                    semantic_hash_hex,
                    physhir_hash_hex,
                    lineage_root_hash_hex,
                    output_schema_id_hash_hex,
                    holdout_handle_hash_hex,
                    disagreement_score,
                    semantic_physhir_distance_bits,
                    escalate_to_heavy,
                ),
                (
                    policy_oracle_receipts,
                    topic_oracle_receipt,
                    nullspec_id_hex,
                    oracle_resolution_hash_hex,
                    eprocess_kind,
                    nullspec_contract_hash_hex,
                ),
                (
                    trial_commitment_schema_version,
                    trial_arm_id,
                    trial_intervention_id,
                    trial_intervention_version,
                    trial_arm_parameters_hash_hex,
                    trial_nonce_hex,
                    trial_commitment_hash_hex,
                    environment_attestations,
                    state,
                ),
            )| {
                code_ir_manifests.sort_by(|a, b| {
                    a.kind
                        .cmp(&b.kind)
                        .then_with(|| a.hash_hex.cmp(&b.hash_hex))
                });
                dependency_capsule_hashes.sort();
                ClaimCapsule {
                    schema: "evidenceos.v2.claim_capsule".to_string(),
                    claim_id_hex,
                    topic_id_hex,
                    output_schema_id,
                    code_ir_manifests,
                    dependency_capsule_hashes,
                    structured_output_hash_hex,
                    canonical_output_hash_hex,
                    kout_bits_upper_bound,
                    wasm_hash_hex,
                    judge_trace_hash_hex,
                    holdout_ref,
                    holdout_commitment_hex,
                    ledger,
                    ledger_receipts,
                    e_value,
                    certified,
                    decision,
                    reason_codes,
                    semantic_hash_hex,
                    physhir_hash_hex,
                    lineage_root_hash_hex,
                    output_schema_id_hash_hex,
                    holdout_handle_hash_hex,
                    disagreement_score,
                    semantic_physhir_distance_bits,
                    escalate_to_heavy,
                    policy_oracle_receipts,
                    topic_oracle_receipt,
                    nullspec_id_hex,
                    oracle_resolution_hash_hex,
                    eprocess_kind,
                    nullspec_contract_hash_hex,
                    trial_commitment_schema_version,
                    trial_arm_id,
                    trial_intervention_id,
                    trial_intervention_version,
                    trial_arm_parameters_hash_hex,
                    trial_nonce_hex,
                    trial_commitment_hash_hex,
                    trial: None,
                    environment_attestations,
                    state,
                }
            },
        )
}

proptest! {
    #[test]
    fn etl_backward_compat_and_merkle_root_stability(
        capsules in prop::collection::vec(claim_capsule_strategy(), 1..20),
        old_size_hint in 1usize..20,
        proof_idx_hint in 0usize..20,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl-compat.log");
        let mut etl = Etl::open_or_create(&path).expect("etl");
        let mut legacy_bytes = Vec::with_capacity(capsules.len());

        for capsule in &capsules {
            let bytes = capsule.to_json_bytes().expect("capsule bytes");
            let bytes_again = capsule.to_json_bytes().expect("capsule bytes again");
            prop_assert_eq!(&bytes, &bytes_again);

            let reparsed_current: ClaimCapsule = serde_json::from_slice(&bytes).expect("current parse");
            let current_roundtrip = reparsed_current.to_json_bytes().expect("current roundtrip bytes");
            prop_assert_eq!(&bytes, &current_roundtrip);

            let parsed_legacy: LegacyClaimCapsule = serde_json::from_slice(&bytes).expect("legacy parse");
            let legacy_roundtrip = canonical_json(&parsed_legacy).expect("legacy roundtrip bytes");
            prop_assert_eq!(&bytes, &legacy_roundtrip);

            etl.append(&bytes).expect("append capsule");
            legacy_bytes.push(legacy_roundtrip);
        }

        let root_current = etl.root_hash();
        let size = etl.tree_size() as usize;
        let idx = proof_idx_hint % size;
        let inclusion = etl.inclusion_proof(idx as u64).expect("inclusion proof");
        let leaf = etl.leaf_hash_at(idx as u64).expect("leaf hash");
        prop_assert!(verify_inclusion_proof(&inclusion, &leaf, idx, size, &root_current));

        let old_size = if old_size_hint % 2 == 0 { size } else { 1 };
        let old_root = etl.root_at_size(old_size as u64).expect("old root");
        let consistency = etl.consistency_proof(old_size as u64, size as u64).expect("consistency proof");
        prop_assert!(verify_consistency_proof(&old_root, &root_current, old_size, size, &consistency));

        let mut legacy_etl = Etl::open_or_create(&dir.path().join("etl-compat-legacy.log")).expect("legacy etl");
        for bytes in &legacy_bytes {
            legacy_etl.append(bytes).expect("append legacy bytes");
        }
        let root_legacy = legacy_etl.root_hash();
        prop_assert_eq!(root_current, root_legacy);

        let tree_size = etl.tree_size();
        let digest = sth_signature_digest(tree_size, root_current);
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let sig = signing_key.sign(&digest);
        prop_assert!(verifying_key.verify_strict(&digest, &sig).is_ok());
    }
}
