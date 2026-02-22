use std::net::SocketAddr;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
}

fn sha256(payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
}

fn valid_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            i32.const 0 i32.const 1 call $emit drop)
        )"#,
    )
    .expect("valid wat")
}

fn oracle_wasm(decision: i32) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "policy_oracle_decide") (param i32 i32) (result i32)
            i32.const {decision}))"#
    ))
    .expect("oracle wat")
}

fn install_oracle(data_dir: &std::path::Path, decision: i32, reason_code: u32) {
    let oracle_dir = data_dir.join("policy-oracles");
    std::fs::create_dir_all(&oracle_dir).expect("mkdir");
    let wasm = oracle_wasm(decision);
    std::fs::write(oracle_dir.join("defer.wasm"), &wasm).expect("write wasm");
    let manifest = serde_json::json!({
        "schema": "evidenceos.v1.policy_oracle_manifest",
        "oracle_id": "oracle.defer",
        "vendor": "safety-firm",
        "version": "1.0.0",
        "description": "test oracle",
        "wasm_filename": "defer.wasm",
        "wasm_sha256_hex": hex::encode(sha256(&wasm)),
        "reason_code": reason_code,
        "decision_mode": "veto_only",
        "max_fuel": 100000,
        "max_memory_bytes": 65536,
        "max_input_bytes": 4096,
        "require_signature": false,
        "signer_pubkey_ed25519_hex": null,
        "signature_ed25519_hex": null
    });
    std::fs::write(
        oracle_dir.join("oracle.json"),
        serde_json::to_vec(&manifest).expect("json"),
    )
    .expect("write manifest");
}

async fn start_server(data_dir: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });
    (addr, handle)
}

async fn client(addr: SocketAddr) -> EvidenceOsClient<Channel> {
    EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect")
}

async fn run_lifecycle(c: &mut EvidenceOsClient<Channel>) -> (Vec<u8>, pb::ExecuteClaimV2Response) {
    let claim_id = c
        .create_claim_v2(pb::CreateClaimV2Request {
            claim_name: "oracle-e2e".to_string(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".to_string(),
                alpha_micros: 50_000,
                epoch_config_ref: "epoch".to_string(),
                output_schema_id: "legacy/v1".to_string(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: hash(1),
                phys_hir_signature_hash: hash(2),
                dependency_merkle_root: hash(3),
            }),
            holdout_ref: "holdout".to_string(),
            epoch_size: 30,
            oracle_num_symbols: 4,
            access_credit: 64,

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;

    let wasm_module = valid_wasm();
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: vec![pb::Artifact {
            artifact_hash: sha256(&wasm_module),
            kind: "wasm".to_string(),
        }],
        wasm_module,
    })
    .await
    .expect("commit");

    c.freeze_gates(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("freeze");
    c.seal_claim(pb::SealClaimRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("seal");

    let resp = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("execute")
        .into_inner();
    (claim_id, resp)
}

#[tokio::test]
async fn policy_oracle_defer_forces_defer_and_receipts() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    install_oracle(&data_dir, 1, 9001);

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;
    let (claim_id, resp) = run_lifecycle(&mut c).await;
    assert_eq!(resp.decision, pb::Decision::Defer as i32);
    assert!(resp.reason_codes.contains(&9001));
    assert_eq!(resp.state, pb::ClaimState::Frozen as i32);

    let capsule = c
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("capsule")
        .into_inner();
    let v: Value = serde_json::from_slice(&capsule.capsule_bytes).expect("json");
    let receipts = v["policy_oracle_receipts"].as_array().expect("array");
    assert!(!receipts.is_empty());
    assert_eq!(receipts[0]["oracle_id"], "oracle.defer");
    handle.abort();
}

#[tokio::test]
async fn policy_oracle_reject_forces_reject() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    install_oracle(&data_dir, 2, 9002);

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;
    let (_claim_id, resp) = run_lifecycle(&mut c).await;
    assert_eq!(resp.decision, pb::Decision::Reject as i32);
    assert!(resp.reason_codes.contains(&9002));
    handle.abort();
}

#[tokio::test]
async fn policy_oracle_invalid_return_fails_closed_to_defer() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    install_oracle(&data_dir, 7, 9003);

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;
    let (_claim_id, resp) = run_lifecycle(&mut c).await;
    assert_eq!(resp.decision, pb::Decision::Defer as i32);
    assert!(resp.reason_codes.contains(&9003));
    assert_eq!(resp.state, pb::ClaimState::Frozen as i32);
    handle.abort();
}
