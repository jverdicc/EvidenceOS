use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use evidenceos_daemon::auth::{AuthConfig, RequestGuard};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> String {
    format!("req-{}", REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed))
}

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
    req.metadata_mut().insert(
        "x-request-id",
        MetadataValue::try_from(next_request_id()).expect("request id metadata"),
    );
    req
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
    req.metadata_mut().insert(
        "x-request-id",
        MetadataValue::try_from(next_request_id()).expect("request id"),
    );
    req.metadata_mut().insert(
        "x-request-id",
        MetadataValue::try_from(next_request_id()).expect("request id"),
    );

    let resp = c
        .health(req)
        .await
        .expect("token should be accepted")
        .into_inner();
    assert_eq!(resp.status, "SERVING");
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
        claim_name: "x".repeat(6 * 1024 * 1024),
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
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server_with_role_tokens(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let err = c
        .fetch_capsule(with_bearer(
            pb::FetchCapsuleRequest {
                claim_id: vec![],
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


    handle.abort();
}

