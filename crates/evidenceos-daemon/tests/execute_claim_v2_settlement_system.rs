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
    let mut client = start_server(temp.path().to_str().expect("path")).await;

    let (match_exec, match_capsule) =
        run_claim(&mut client, wasm_emit_with_oracle(&[1, 0, 1, 1])).await;
    let (mismatch_exec, mismatch_capsule) =
        run_claim(&mut client, wasm_emit_with_oracle(&[0, 0, 0, 0])).await;

    assert_ne!(match_exec.e_value, mismatch_exec.e_value);
    let wealth_a = match_capsule["ledger"]["wealth"]
        .as_f64()
        .expect("wealth a");
    let wealth_b = mismatch_capsule["ledger"]["wealth"]
        .as_f64()
        .expect("wealth b");
    assert!((wealth_a - match_exec.e_value).abs() < 1e-9);
    assert!((wealth_b - mismatch_exec.e_value).abs() < 1e-9);
}
