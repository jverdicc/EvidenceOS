use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::capsule::canonical_json;
use evidenceos_core::nullspec::{
    EProcessKind, NullSpecContractV1, NullSpecKind, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_store::NullSpecStore;
use evidenceos_core::oracle::OracleResolution;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOs;
use evidenceos_protocol::{sha256_domain, DOMAIN_ORACLE_OPERATOR_RECORD_V1};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tonic::Request;

#[derive(Serialize)]
struct OracleOperatorRecordPayload<'a> {
    oracle_id: &'a str,
    schema_version: u32,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: &'a str,
    calibration_epoch: Option<u64>,
    disjointness_attestation: &'a str,
    nonoverlap_proof_uri: Option<&'a str>,
    updated_at_epoch: u64,
    key_id: &'a str,
}

fn sign_oracle_record(sk: &SigningKey, payload: &OracleOperatorRecordPayload<'_>) -> String {
    let canonical = canonical_json(payload).expect("canonical");
    let digest = sha256_domain(DOMAIN_ORACLE_OPERATOR_RECORD_V1, &canonical);
    hex::encode(sk.sign(&digest).to_bytes())
}

fn write_operator_config(dir: &TempDir, calibration_hex: &str) {
    let key_id = "ops-k1";
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    std::fs::write(
        dir.path().join("trusted_oracle_keys.json"),
        serde_json::to_vec(&json!({"keys": {key_id: hex::encode(sk.verifying_key().to_bytes())}}))
            .expect("trusted keys"),
    )
    .expect("write trusted keys");

    let payload = OracleOperatorRecordPayload {
        oracle_id: "settle",
        schema_version: 1,
        ttl_epochs: 5,
        calibration_manifest_hash_hex: calibration_hex,
        calibration_epoch: Some(10),
        disjointness_attestation: "attested-disjoint",
        nonoverlap_proof_uri: None,
        updated_at_epoch: 42,
        key_id,
    };
    let signature = sign_oracle_record(&sk, &payload);
    std::fs::write(
        dir.path().join("oracle_operator_config.json"),
        serde_json::to_vec(&json!({
            "oracles": {
                "settle": {
                    "schema_version": 1,
                    "ttl_epochs": 5,
                    "calibration_manifest_hash_hex": calibration_hex,
                    "calibration_epoch": 10,
                    "disjointness_attestation": "attested-disjoint",
                    "nonoverlap_proof_uri": null,
                    "updated_at_epoch": 42,
                    "key_id": key_id,
                    "signature_ed25519": signature,
                }
            }
        }))
        .expect("oracle json"),
    )
    .expect("write oracle cfg");
}

fn wasm_emit_with_oracle(preds: &[u8]) -> Vec<u8> {
    let preds_esc = preds
        .iter()
        .map(|b| format!("\\{:02x}", b))
        .collect::<String>();
    wat::parse_str(format!(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (data (i32.const 32) "\01")
          (func (export "run")
            i32.const 0 i32.const {} call $oracle drop
            i32.const 32 i32.const 1 call $emit drop))"#,
        preds_esc,
        preds.len()
    ))
    .expect("wat")
}

async fn create_sealed_claim(data_dir: &str) -> Vec<u8> {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let claim_id = svc
        .create_claim_v2(Request::new(pb::CreateClaimV2Request {
            claim_name: "settle".into(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".into(),
                alpha_micros: 50_000,
                epoch_config_ref: "e".into(),
                output_schema_id: "legacy/v1".into(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: vec![1; 32],
                phys_hir_signature_hash: vec![2; 32],
                dependency_merkle_root: vec![3; 32],
            }),
            holdout_ref: "h".into(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            access_credit: 128,
        }))
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    let wasm = wasm_emit_with_oracle(&[1, 0, 1, 1]);
    svc.commit_artifacts(Request::new(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: vec![pb::Artifact {
            kind: "wasm".into(),
            artifact_hash: {
                let mut h = Sha256::new();
                h.update(&wasm);
                h.finalize().to_vec()
            },
        }],
        wasm_module: wasm,
    }))
    .await
    .expect("commit");
    svc.freeze_gates(Request::new(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    }))
    .await
    .expect("freeze");
    svc.seal_claim(Request::new(pb::SealClaimRequest {
        claim_id: claim_id.clone(),
    }))
    .await
    .expect("seal");
    drop(svc);
    claim_id
}

fn resolution_hash(resolution: &Value) -> [u8; 32] {
    let r: OracleResolution = serde_json::from_value(resolution.clone()).expect("resolution");
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&r).expect("res bytes"));
    h.finalize().into()
}

fn install_active_nullspec(
    data_dir: &str,
    resolution_hash: [u8; 32],
    calibration_manifest_hash: Option<[u8; 32]>,
) {
    let mut contract = NullSpecContractV1 {
        schema: NULLSPEC_SCHEMA_V1.to_string(),
        nullspec_id: [0_u8; 32],
        oracle_id: "settle".to_string(),
        oracle_resolution_hash: resolution_hash,
        holdout_handle: "h".to_string(),
        epoch_created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs()
            / 10,
        ttl_epochs: 10_000,
        kind: NullSpecKind::DiscreteBuckets {
            p0: vec![0.25, 0.25, 0.25, 0.25],
        },
        eprocess: EProcessKind::DirichletMultinomialMixture {
            alpha: vec![1.0, 1.0, 1.0, 1.0],
        },
        calibration_manifest_hash,
        created_by: "test".to_string(),
        signature_ed25519: Vec::new(),
    };
    contract.nullspec_id = contract.compute_id();
    let store = NullSpecStore::open(std::path::Path::new(data_dir)).expect("store");
    store.install(&contract).expect("install");
    store
        .rotate_active(
            &contract.oracle_id,
            &contract.holdout_handle,
            contract.nullspec_id,
        )
        .expect("activate");
}

#[tokio::test]
async fn freeze_pins_calibration_and_resolution_hash() {
    let temp = TempDir::new().expect("tmp");
    write_operator_config(&temp, &"aa".repeat(32));
    let claim_id = create_sealed_claim(temp.path().to_str().expect("path")).await;

    let state_path = temp.path().join("state.json");
    let state: Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("read")).expect("state json");
    let claim = state["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .find(|c| {
            let b = c["claim_id"].as_array().expect("id");
            let got = b
                .iter()
                .map(|x| x.as_u64().expect("u8") as u8)
                .collect::<Vec<_>>();
            got == claim_id
        })
        .expect("claim");

    assert_eq!(claim["oracle_resolution"]["ttl_epochs"], json!(5));
    assert_eq!(
        claim["oracle_resolution"]["calibration_manifest_hash"]
            .as_array()
            .expect("cal hash")
            .len(),
        32
    );
    let expected_hash = resolution_hash(&claim["oracle_resolution"]);
    let pin_hash = claim["oracle_pins"]["oracle_resolution_hash"]
        .as_array()
        .expect("pins hash")
        .iter()
        .map(|x| x.as_u64().expect("u8") as u8)
        .collect::<Vec<_>>();
    assert_eq!(pin_hash, expected_hash.to_vec());
}

#[tokio::test]
async fn execute_fails_closed_on_calibration_mismatch_and_post_freeze_mutation() {
    let temp = TempDir::new().expect("tmp");
    write_operator_config(&temp, &"aa".repeat(32));
    let data_dir = temp.path().to_str().expect("path");
    let claim_id = create_sealed_claim(data_dir).await;

    let state_path = temp.path().join("state.json");
    let mut state: Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("read")).expect("state json");
    let claim = state["claims"]
        .as_array_mut()
        .expect("claims")
        .iter_mut()
        .find(|c| {
            let b = c["claim_id"].as_array().expect("id");
            let got = b
                .iter()
                .map(|x| x.as_u64().expect("u8") as u8)
                .collect::<Vec<_>>();
            got == claim_id
        })
        .expect("claim");
    let expected_resolution_hash = resolution_hash(&claim["oracle_resolution"]);
    install_active_nullspec(data_dir, expected_resolution_hash, Some([0xBB; 32]));

    let svc = EvidenceOsService::build(data_dir).expect("service");
    let err = svc
        .execute_claim_v2(Request::new(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        }))
        .await
        .expect_err("must fail on contract calibration mismatch");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("calibration hash mismatch"));
    drop(svc);

    claim["oracle_resolution"]["calibrated_at_epoch"] = json!(999_u64);
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("encode"),
    )
    .expect("write state");

    install_active_nullspec(data_dir, expected_resolution_hash, Some([0xAA; 32]));
    let svc = EvidenceOsService::build(data_dir).expect("service2");
    let err = svc
        .execute_claim_v2(Request::new(pb::ExecuteClaimV2Request { claim_id }))
        .await
        .expect_err("must fail on pinned resolution hash mismatch");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("sealed pins"));
}
