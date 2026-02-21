use evidenceos_core::nullspec::{
    EProcessKind, NullSpecKind, SignedNullSpecContractV1, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_store::NullSpecStore;
use evidenceos_core::oracle::OracleResolution;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOs;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tonic::Request;

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

fn current_epoch(epoch_size: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
        / epoch_size
}

fn install_active_nullspec(data_dir: &str, epoch_created: u64, resolution_hash: [u8; 32]) {
    let mut contract = SignedNullSpecContractV1 {
        schema: NULLSPEC_SCHEMA_V1.to_string(),
        nullspec_id: [0_u8; 32],
        oracle_id: "settle".to_string(),
        oracle_resolution_hash: resolution_hash,
        holdout_handle: "h".to_string(),
        epoch_created,
        ttl_epochs: 10_000,
        kind: NullSpecKind::DiscreteBuckets {
            p0: vec![0.25, 0.25, 0.25, 0.25],
        },
        eprocess: EProcessKind::DirichletMultinomialMixture {
            alpha: vec![1.0, 1.0, 1.0, 1.0],
        },
        calibration_manifest_hash: None,
        created_by: "test".to_string(),
        signature_ed25519: Vec::new(),
    };
    contract.nullspec_id = contract.compute_id().expect("id");
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

fn patch_claim_resolution_ttl(
    data_dir: &str,
    claim_id: &[u8],
    calibrated: u64,
    ttl: u64,
) -> [u8; 32] {
    let state_path = std::path::Path::new(data_dir).join("state.json");
    let mut json: Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("read")).expect("decode");
    let claim_id_hex = hex::encode(claim_id);
    let claims = json["claims"].as_array_mut().expect("claims");
    let mut resolution_json: Option<Value> = None;
    for claim in claims.iter_mut() {
        let bytes = claim["claim_id"].as_array().expect("claim_id bytes");
        let current = bytes
            .iter()
            .map(|v| v.as_u64().expect("byte") as u8)
            .collect::<Vec<_>>();
        if hex::encode(current) == claim_id_hex {
            claim["oracle_resolution"]["calibrated_at_epoch"] = serde_json::json!(calibrated);
            claim["oracle_resolution"]["ttl_epochs"] = serde_json::json!(ttl);
            resolution_json = Some(claim["oracle_resolution"].clone());
            break;
        }
    }
    let resolution_json = resolution_json.expect("claim not found in persisted state");
    std::fs::write(
        state_path,
        serde_json::to_vec_pretty(&json).expect("encode"),
    )
    .expect("write");
    let resolution: OracleResolution =
        serde_json::from_value(resolution_json).expect("oracle resolution");
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&resolution).expect("resolution bytes"));
    h.finalize().into()
}

async fn create_sealed_claim(data_dir: &str, lane: &str) -> Vec<u8> {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let claim_id = svc
        .create_claim_v2(Request::new(pb::CreateClaimV2Request {
            claim_name: "settle".into(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: lane.into(),
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
            epoch_size: 4,
            oracle_num_symbols: 4,
            access_credit: 128,

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
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

#[tokio::test]
async fn oracle_ttl_enforcement_reject_and_escalation_policy() {
    std::env::set_var("EVIDENCEOS_ORACLE_TTL_POLICY", "reject_expired");
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path().to_str().expect("path");

    let claim_id = create_sealed_claim(data_dir, "fast").await;
    let resolution_hash = patch_claim_resolution_ttl(data_dir, &claim_id, 0, 1);
    install_active_nullspec(data_dir, current_epoch(4), resolution_hash);

    let svc = EvidenceOsService::build(data_dir).expect("service");
    let err = svc
        .execute_claim_v2(Request::new(pb::ExecuteClaimV2Request { claim_id }))
        .await
        .expect_err("must deny expired oracle");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("OracleExpired"));

    std::env::set_var("EVIDENCEOS_ORACLE_TTL_POLICY", "escalate_to_heavy");
    std::env::set_var("EVIDENCEOS_ORACLE_TTL_ESCALATION_TAX_MULTIPLIER", "2.0");
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path().to_str().expect("path");

    let claim_id = create_sealed_claim(data_dir, "heavy").await;
    let resolution_hash = patch_claim_resolution_ttl(data_dir, &claim_id, 0, 1);
    install_active_nullspec(data_dir, current_epoch(4), resolution_hash);

    let svc = EvidenceOsService::build(data_dir).expect("service");
    let err = svc
        .execute_claim_v2(Request::new(pb::ExecuteClaimV2Request { claim_id }))
        .await
        .expect_err("heavy lane path currently returns failed_precondition");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(!err.message().contains("OracleExpired"));
}
