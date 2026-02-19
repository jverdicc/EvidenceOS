use std::net::SocketAddr;

use evidenceos_daemon::auth::{AuthConfig, RequestGuard};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};

async fn start_server(
    data_dir: &str,
    max_bytes: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
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
            .max_decoding_message_size(max_bytes)
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

#[tokio::test]
async fn daemon_rejects_missing_auth_token() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy(), 1024 * 1024).await;
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

    let (addr, handle) = start_server(&data_dir.to_string_lossy(), 1024 * 1024).await;
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

    let (addr, handle) = start_server(&data_dir.to_string_lossy(), 128).await;
    let mut c = client(addr).await;

    let mut req = Request::new(pb::CreateClaimV2Request {
        claim_name: "x".repeat(1024),
        metadata: None,
        signals: None,
        holdout_ref: "h".repeat(1024),
        epoch_size: 1,
        oracle_num_symbols: 2,
        access_credit: 1,
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
