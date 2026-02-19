use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
}

async fn start_server(data_dir: &str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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

async fn client(addr: std::net::SocketAddr) -> EvidenceOsClient<Channel> {
    EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect")
}

fn request_with_alias(alias: &str) -> pb::CreateClaimV2Request {
    pb::CreateClaimV2Request {
        claim_name: format!("alias-{alias}"),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch-1".to_string(),
            output_schema_id: alias.to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: hash(1),
            phys_hir_signature_hash: hash(2),
            dependency_merkle_root: hash(3),
        }),
        holdout_ref: "holdout-1".to_string(),
        epoch_size: 20,
        oracle_num_symbols: 4,
        access_credit: 64,
    }
}

#[tokio::test]
async fn structured_claims_accepts_known_aliases() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    for alias in [
        "cbrn-sc.v1",
        "cbrn/v1",
        "schema/v1",
        "cbrn_sc.v1",
        "cbrn-sc/v1",
    ] {
        let created = c
            .create_claim_v2(request_with_alias(alias))
            .await
            .expect("alias should be accepted")
            .into_inner();
        assert_eq!(created.state, pb::ClaimState::Uncommitted as i32);
    }

    handle.abort();
}

#[tokio::test]
async fn topic_id_stability_under_aliases() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let canonical = c
        .create_claim_v2(request_with_alias("cbrn-sc.v1"))
        .await
        .expect("canonical create")
        .into_inner();
    let alias = c
        .create_claim_v2(request_with_alias("schema/v1"))
        .await
        .expect("alias create")
        .into_inner();

    assert_eq!(canonical.topic_id, alias.topic_id);

    handle.abort();
}
