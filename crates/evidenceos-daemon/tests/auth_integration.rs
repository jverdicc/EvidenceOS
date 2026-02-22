use std::collections::HashSet;
use std::net::SocketAddr;

use evidenceos_daemon::auth::{AuthConfig, RequestGuard};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};

async fn start_server(data_dir: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    let guard = RequestGuard::new(
        Some(AuthConfig::BearerToken("top-secret".to_string())),
        None,
    );
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::with_interceptor(svc, guard))
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

async fn start_server_with_role_tokens(
    data_dir: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    let guard = RequestGuard::new(
        Some(AuthConfig::BearerRoleTokens {
            agent_tokens: HashSet::from(["agent-secret".to_string()]),
            auditor_tokens: HashSet::from(["auditor-secret".to_string()]),
        }),
        None,
    );
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::with_interceptor(svc, guard))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });
    (addr, handle)
}

fn with_bearer<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).expect("auth metadata"),
    );
    req
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

#[tokio::test]
async fn daemon_rejects_missing_auth_token() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let err = c
        .health(pb::HealthRequest {})
        .await
        .expect_err("request without token must fail");
    assert_eq!(err.code(), Code::Unauthenticated);
    handle.abort();
}

#[tokio::test]
async fn daemon_accepts_correct_auth_token() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let mut req = Request::new(pb::HealthRequest {});
    req.metadata_mut().insert(
        "authorization",
        "Bearer top-secret".parse().expect("header"),
    );

    let resp = c
        .health(req)
        .await
        .expect("token should be accepted")
        .into_inner();
    assert_eq!(resp.status, "ok");
    handle.abort();
}

#[tokio::test]
async fn daemon_enforces_max_request_size() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let mut req = Request::new(pb::CreateClaimV2Request {
        claim_name: "x".repeat(1024),
        metadata: None,
        signals: None,
        holdout_ref: "h".repeat(1024),
        epoch_size: 1,
        oracle_num_symbols: 2,
        access_credit: 1,

        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: String::new(),
        dp_epsilon_budget: None,
        dp_delta_budget: None,
    });
    req.metadata_mut().insert(
        "authorization",
        "Bearer top-secret".parse().expect("header"),
    );

    let err = c
        .create_claim_v2(req)
        .await
        .expect_err("oversized request should fail");
    assert_eq!(err.code(), Code::OutOfRange);
    handle.abort();
}

#[tokio::test]
async fn agent_role_cannot_fetch_capsule_or_etl_proofs() {
    std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server_with_role_tokens(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let create = c
        .create_claim_v2(with_bearer(
            pb::CreateClaimV2Request {
                claim_name: "role-authz".to_string(),
                metadata: Some(pb::ClaimMetadataV2 {
                    lane: "fast".to_string(),
                    alpha_micros: 50_000,
                    epoch_config_ref: "epoch-1".to_string(),
                    output_schema_id: "legacy/v1".to_string(),
                }),
                signals: Some(pb::TopicSignalsV2 {
                    semantic_hash: vec![1; 32],
                    phys_hir_signature_hash: vec![2; 32],
                    dependency_merkle_root: vec![3; 32],
                }),
                holdout_ref: "synthetic-holdout".to_string(),
                epoch_size: 10,
                oracle_num_symbols: 4,
                access_credit: 64,
                oracle_id: "builtin.accuracy".to_string(),
                nullspec_id: String::new(),
                dp_epsilon_budget: None,
                dp_delta_budget: None,
            },
            "agent-secret",
        ))
        .await
        .expect("create")
        .into_inner();

    let wasm = valid_wasm();
    c.commit_artifacts(with_bearer(
        pb::CommitArtifactsRequest {
            claim_id: create.claim_id.clone(),
            artifacts: wasm_artifacts(&wasm),
            wasm_module: wasm,
        },
        "agent-secret",
    ))
    .await
    .expect("commit");

    c.freeze_gates(with_bearer(
        pb::FreezeGatesRequest {
            claim_id: create.claim_id.clone(),
        },
        "agent-secret",
    ))
    .await
    .expect("freeze");

    c.seal_claim(with_bearer(
        pb::SealClaimRequest {
            claim_id: create.claim_id.clone(),
        },
        "agent-secret",
    ))
    .await
    .expect("seal");

    c.execute_claim_v2(with_bearer(
        pb::ExecuteClaimV2Request {
            claim_id: create.claim_id.clone(),
        },
        "agent-secret",
    ))
    .await
    .expect("execute");

    let err = c
        .fetch_capsule(with_bearer(
            pb::FetchCapsuleRequest {
                claim_id: create.claim_id.clone(),
            },
            "agent-secret",
        ))
        .await
        .expect_err("agent fetch must fail");
    assert_eq!(err.code(), Code::PermissionDenied);

    let err = c
        .get_inclusion_proof(with_bearer(
            pb::GetInclusionProofRequest { leaf_index: 0 },
            "agent-secret",
        ))
        .await
        .expect_err("agent inclusion proof must fail");
    assert_eq!(err.code(), Code::PermissionDenied);

    let err = c
        .get_consistency_proof(with_bearer(
            pb::GetConsistencyProofRequest {
                first_tree_size: 1,
                second_tree_size: 1,
            },
            "agent-secret",
        ))
        .await
        .expect_err("agent consistency proof must fail");
    assert_eq!(err.code(), Code::PermissionDenied);

    let _capsule = c
        .fetch_capsule(with_bearer(
            pb::FetchCapsuleRequest {
                claim_id: create.claim_id,
            },
            "auditor-secret",
        ))
        .await
        .expect("auditor fetch should pass");

    handle.abort();
    std::env::remove_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT");
}
