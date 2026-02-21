use evidenceos_core::nullspec::{
    EProcessKind, NullSpecContractV1, NullSpecKind, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_store::NullSpecStore;
use evidenceos_core::oracle::OracleResolution;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server};

async fn start_server(data_dir: &str) -> EvidenceOsClient<Channel> {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });
    EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect")
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

fn install_active_nullspec(
    data_dir: &str,
    epoch_created: u64,
    ttl_epochs: u64,
    resolution_hash: [u8; 32],
) {
    let mut contract = NullSpecContractV1 {
        schema: NULLSPEC_SCHEMA_V1.to_string(),
        nullspec_id: [0_u8; 32],
        oracle_id: "settle".to_string(),
        oracle_resolution_hash: resolution_hash,
        holdout_handle: "h".to_string(),
        epoch_created,
        ttl_epochs,
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

async fn run_claim(
    client: &mut EvidenceOsClient<Channel>,
    wasm: Vec<u8>,
) -> (pb::ExecuteClaimV2Response, Value) {
    let claim_id = client
        .create_claim_v2(pb::CreateClaimV2Request {
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
            epoch_size: 4,
            oracle_num_symbols: 4,
            access_credit: 128,

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    client
        .commit_artifacts(pb::CommitArtifactsRequest {
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
        })
        .await
        .expect("commit");
    client
        .freeze_gates(pb::FreezeGatesRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("freeze");
    client
        .seal_claim(pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("seal");
    let exec = client
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("exec")
        .into_inner();
    let cap = client
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    let json: Value = serde_json::from_slice(&cap.capsule_bytes).expect("json");
    (exec, json)
}

#[tokio::test]
async fn oracle_e_value_drives_settlement_and_capsule_wealth() {
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path().to_str().expect("path");
    let resolution = OracleResolution::new(4, 0.0).expect("resolution");
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&resolution).expect("res bytes"));
    let resolution_hash: [u8; 32] = h.finalize().into();
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
        / 4;
    install_active_nullspec(data_dir, now_epoch, 10_000, resolution_hash);
    let mut client = start_server(data_dir).await;

    let (match_exec, match_capsule) =
        run_claim(&mut client, wasm_emit_with_oracle(&[1, 0, 1, 1])).await;
    let (mismatch_exec, mismatch_capsule) =
        run_claim(&mut client, wasm_emit_with_oracle(&[0, 0, 0, 0])).await;

    let wealth_a = match_capsule["ledger"]["wealth"]
        .as_f64()
        .expect("wealth a");
    let wealth_b = mismatch_capsule["ledger"]["wealth"]
        .as_f64()
        .expect("wealth b");
    assert!((wealth_a - match_exec.e_value).abs() < 1e-9);
    assert!((wealth_b - mismatch_exec.e_value).abs() < 1e-9);
    assert!(match_capsule["nullspec_id_hex"].is_string());
    assert_eq!(
        match_capsule["eprocess_kind"],
        "dirichlet_multinomial_mixture"
    );
}

#[tokio::test]
async fn execute_fails_closed_without_active_nullspec() {
    let temp = TempDir::new().expect("temp");
    let mut client = start_server(temp.path().to_str().expect("path")).await;
    let claim_id = client
        .create_claim_v2(pb::CreateClaimV2Request {
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
            epoch_size: 4,
            oracle_num_symbols: 4,
            access_credit: 128,

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    let wasm = wasm_emit_with_oracle(&[1, 1, 1, 1]);
    client
        .commit_artifacts(pb::CommitArtifactsRequest {
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
        })
        .await
        .expect("commit");
    client
        .freeze_gates(pb::FreezeGatesRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("freeze");
    client
        .seal_claim(pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("seal");
    let err = client
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
        .await
        .expect_err("must fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn canary_drift_freezes_subsequent_certifications_and_writes_incident() {
    std::env::set_var("EVIDENCEOS_PROBE_THROTTLE_TOTAL", "1000");
    std::env::set_var("EVIDENCEOS_PROBE_ESCALATE_TOTAL", "2000");
    std::env::set_var("EVIDENCEOS_PROBE_FREEZE_TOTAL", "3000");
    std::env::set_var("EVIDENCEOS_CANARY_ALPHA_DRIFT_MICROS", "900000");
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path().to_str().expect("path");
    let resolution = OracleResolution::new(4, 0.0).expect("resolution");
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&resolution).expect("res bytes"));
    let resolution_hash: [u8; 32] = h.finalize().into();
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
        / 4;
    install_active_nullspec(data_dir, now_epoch, 10_000, resolution_hash);
    let mut client = start_server(data_dir).await;

    let _ = run_claim(&mut client, wasm_emit_with_oracle(&[1; 4])).await;
    let (second_exec, _) = run_claim(&mut client, wasm_emit_with_oracle(&[1; 4])).await;

    assert_ne!(second_exec.decision, pb::Decision::Approve as i32);
    assert!(second_exec.reason_codes.contains(&91));

    let etl_bytes = std::fs::read(temp.path().join("etl.log")).expect("etl");
    let etl_text = String::from_utf8_lossy(&etl_bytes);
    assert!(etl_text.contains("canary_incident"));
}
