use std::net::SocketAddr;

use evidenceos_core::capsule::ClaimCapsule;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server, Code};

fn h(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn req(name: &str, access_credit: u64, oracle_num_symbols: u32) -> pb::CreateClaimV2Request {
    pb::CreateClaimV2Request {
        claim_name: name.to_string(),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".into(),
            alpha_micros: 50_000,
            epoch_config_ref: "e".into(),
            output_schema_id: "legacy/v1".into(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: h(1),
            phys_hir_signature_hash: h(2),
            dependency_merkle_root: h(3),
        }),
        holdout_ref: "h".into(),
        epoch_size: 8,
        oracle_num_symbols,
        access_credit,
        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: String::new(),
        dp_epsilon_budget: None,
        dp_delta_budget: None,
    }
}

fn artifacts(wasm: &[u8]) -> Vec<pb::Artifact> {
    let mut h = Sha256::new();
    h.update(wasm);
    vec![pb::Artifact {
        artifact_hash: h.finalize().to_vec(),
        kind: "wasm".into(),
    }]
}

fn valid_wasm() -> Vec<u8> {
    wat::parse_str("(module (import \"env\" \"emit_structured_claim\" (func $emit (param i32 i32) (result i32))) (memory (export \"memory\") 1) (data (i32.const 0) \"\\01\") (func (export \"run\") i32.const 0 i32.const 1 call $emit drop))").expect("wat")
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

#[tokio::test]
async fn full_claim_v2_lifecycle_snapshot_fields() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = c
        .create_claim_v2(req("c", 128, 4))
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: artifacts(&valid_wasm()),
        wasm_module: valid_wasm(),
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
    c.execute_claim_v2(pb::ExecuteClaimV2Request {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("execute");
    let cap = c
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    let parsed: ClaimCapsule = serde_json::from_slice(&cap.capsule_bytes).expect("capsule json");
    assert!(parsed.ledger.k_bits_total > 0.0);
    assert!(parsed.ledger.access_credit_spent > 0.0);
    assert!((parsed.ledger.wealth - parsed.ledger.w_max).abs() < 1e-9);
    assert!(parsed.ledger.barrier.is_finite());

    handle.abort();
}

#[tokio::test]
async fn budget_exhaustion_is_fail_closed() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;
    let claim_id = c
        .create_claim_v2(req("tiny", 0, 4))
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: artifacts(&valid_wasm()),
        wasm_module: valid_wasm(),
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
    let err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
        .await
        .expect_err("must fail");
    assert_eq!(err.code(), Code::FailedPrecondition);
    handle.abort();
}

#[tokio::test]
async fn non_canonical_output_rejected_and_does_not_charge() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;
    let claim_id = c
        .create_claim_v2(req("bad", 32, 1024))
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    let bad_wasm = wat::parse_str("(module (import \"env\" \"emit_structured_claim\" (func $emit (param i32 i32) (result i32))) (memory (export \"memory\") 1) (data (i32.const 0) \"\\ff\") (func (export \"run\") i32.const 0 i32.const 1 call $emit drop))").expect("wat");
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: artifacts(&bad_wasm),
        wasm_module: bad_wasm,
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
    let _ = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect_err("must reject");
    let fetch = c.fetch_capsule(pb::FetchCapsuleRequest { claim_id }).await;
    assert!(fetch.is_err());
    handle.abort();
}
