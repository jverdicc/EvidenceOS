use std::net::SocketAddr;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::{transport::Channel, transport::Server, Code, Request};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
}

fn valid_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit
            drop)
        )"#,
    )
    .expect("valid wat")
}

fn wasm_artifacts(wasm_module: &[u8]) -> Vec<pb::Artifact> {
    let mut hasher = Sha256::new();
    hasher.update(wasm_module);
    vec![pb::Artifact {
        artifact_hash: hasher.finalize().to_vec(),
        kind: "wasm".to_string(),
    }]
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

fn bearer(value: &str) -> MetadataValue<tonic::metadata::Ascii> {
    MetadataValue::try_from(format!("Bearer {value}")).expect("bearer metadata")
}

fn with_token<T>(request: T, token: &str) -> Request<T> {
    let mut req = Request::new(request);
    req.metadata_mut().insert("authorization", bearer(token));
    req
}

#[tokio::test]
async fn owner_can_execute_non_owner_cannot_fetch_and_operator_can_revoke() {
    std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let create = c
        .create_claim_v2(with_token(
            pb::CreateClaimV2Request {
                claim_name: "tenant-claim".to_string(),
                metadata: Some(pb::ClaimMetadataV2 {
                    lane: "fast".to_string(),
                    alpha_micros: 50_000,
                    epoch_config_ref: "epoch-1".to_string(),
                    output_schema_id: "legacy/v1".to_string(),
                }),
                signals: Some(pb::TopicSignalsV2 {
                    semantic_hash: hash(1),
                    phys_hir_signature_hash: hash(2),
                    dependency_merkle_root: hash(3),
                }),
                holdout_ref: "synthetic-holdout".to_string(),
                epoch_size: 10,
                oracle_num_symbols: 4,
                access_credit: 64,
                oracle_id: "builtin.accuracy".to_string(),
                nullspec_id: String::new(),
            },
            "owner-token",
        ))
        .await
        .expect("create")
        .into_inner();

    let claim_id = create.claim_id;
    let wasm = valid_wasm();
    c.commit_artifacts(with_token(
        pb::CommitArtifactsRequest {
            claim_id: claim_id.clone(),
            artifacts: wasm_artifacts(&wasm),
            wasm_module: wasm,
        },
        "owner-token",
    ))
    .await
    .expect("commit");

    c.freeze_gates(with_token(
        pb::FreezeGatesRequest {
            claim_id: claim_id.clone(),
        },
        "owner-token",
    ))
    .await
    .expect("freeze");

    c.seal_claim(with_token(
        pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        },
        "owner-token",
    ))
    .await
    .expect("seal");

    c.execute_claim_v2(with_token(
        pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        },
        "owner-token",
    ))
    .await
    .expect("owner execute should pass");

    let err = c
        .fetch_capsule(with_token(
            pb::FetchCapsuleRequest {
                claim_id: claim_id.clone(),
            },
            "other-token",
        ))
        .await
        .expect_err("non-owner fetch must fail");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.message(),
        "AUTHZ_CLAIM_OWNER_MISMATCH: caller does not own claim"
    );

    let mut revoke = with_token(
        pb::RevokeClaimRequest {
            claim_id,
            reason: "operator override".to_string(),
        },
        "operator-token",
    );
    revoke.metadata_mut().insert(
        "x-evidenceos-token-scopes",
        MetadataValue::from_static("operator"),
    );
    c.revoke_claim(revoke)
        .await
        .expect("operator revoke should pass");

    handle.abort();
    std::env::remove_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT");
}
