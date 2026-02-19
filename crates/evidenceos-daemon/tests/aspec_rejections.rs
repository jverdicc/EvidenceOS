use std::net::SocketAddr;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::Code;

fn hash_wasm(bytes: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

fn base_with_data(data: &str, body: &str, extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        "(module\n(import \"kernel\" \"emit_structured_claim\" (func $emit (param i32 i32)))\n(memory (export \"memory\") 4)\n(data (i32.const 0) \"{data}\")\n(func (export \"run\") {body})\n{extra}\n)"
    ))
    .expect("valid wat")
}

fn create_claim_req() -> pb::CreateClaimV2Request {
    pb::CreateClaimV2Request {
        claim_name: "aspec-reject".to_string(),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch".to_string(),
            output_schema_id: "schema".to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: vec![1; 32],
            phys_hir_signature_hash: vec![2; 32],
            dependency_merkle_root: vec![3; 32],
        }),
        holdout_ref: "holdout".to_string(),
        epoch_size: 4,
        oracle_num_symbols: 8,
        access_credit: 64,
    }
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

async fn new_client(addr: SocketAddr) -> EvidenceOsClient<Channel> {
    EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect")
}

async fn expect_commit_rejected(
    client: &mut EvidenceOsClient<Channel>,
    wasm_module: Vec<u8>,
    expected: Code,
) {
    let claim_id = client
        .create_claim_v2(create_claim_req())
        .await
        .expect("create claim")
        .into_inner()
        .claim_id;

    let err = client
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id,
            artifacts: vec![pb::Artifact {
                artifact_hash: hash_wasm(&wasm_module),
                kind: "wasm".to_string(),
            }],
            wasm_module,
        })
        .await
        .expect_err("commit should fail closed");
    assert_eq!(err.code(), expected);
}

#[tokio::test]
#[ignore = "long-running system matrix test"]
async fn aspec_policy_violations_fail_closed() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut client = new_client(addr).await;

    let disallowed_import = wat::parse_str(
        r#"(module
(import "env" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
(import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
(memory (export "memory") 1)
(func (export "run") i32.const 0 i32.const 0 i32.const 0 i32.const 0 call 0 drop)
)"#,
    )
    .expect("wat");
    expect_commit_rejected(&mut client, disallowed_import, Code::FailedPrecondition).await;

    let has_loop = base_with_data("", "(loop nop)", "");
    expect_commit_rejected(&mut client, has_loop, Code::FailedPrecondition).await;

    handle.abort();
}
