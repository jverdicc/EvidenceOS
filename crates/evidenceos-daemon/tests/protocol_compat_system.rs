use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient as EvidenceOsV2Client;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer as EvidenceOsV2Server;
use evidenceos_protocol::pb::v1;
use evidenceos_protocol::pb::v1::evidence_os_client::EvidenceOsClient as EvidenceOsV1Client;
use evidenceos_protocol::pb::v1::evidence_os_server::EvidenceOsServer as EvidenceOsV1Server;
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
    let addr = listener.local_addr().expect("local addr");
    let incoming = TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsV2Server::new(svc.clone()))
            .add_service(EvidenceOsV1Server::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });
    (addr, handle)
}

async fn v2_client(addr: std::net::SocketAddr) -> EvidenceOsV2Client<Channel> {
    EvidenceOsV2Client::connect(format!("http://{addr}"))
        .await
        .expect("v2 connect")
}

async fn v1_client(addr: std::net::SocketAddr) -> EvidenceOsV1Client<Channel> {
    EvidenceOsV1Client::connect(format!("http://{addr}"))
        .await
        .expect("v1 connect")
}

fn v2_create(seed: u8) -> pb::CreateClaimV2Request {
    pb::CreateClaimV2Request {
        claim_name: format!("claim-v2-{seed}"),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: format!("epoch-v2-{seed}"),
            output_schema_id: "legacy/v1".to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: hash(seed),
            phys_hir_signature_hash: hash(seed.wrapping_add(1)),
            dependency_merkle_root: hash(seed.wrapping_add(2)),
        }),
        holdout_ref: format!("holdout-v2-{seed}"),
        epoch_size: 20,
        oracle_num_symbols: 4,
        access_credit: 64,
    }
}

fn v1_create(seed: u8) -> v1::CreateClaimV2Request {
    v1::CreateClaimV2Request {
        claim_name: format!("claim-v1-{seed}"),
        metadata: Some(v1::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: format!("epoch-v1-{seed}"),
            output_schema_id: "legacy/v1".to_string(),
        }),
        signals: Some(v1::TopicSignalsV2 {
            semantic_hash: hash(seed),
            phys_hir_signature_hash: hash(seed.wrapping_add(1)),
            dependency_merkle_root: hash(seed.wrapping_add(2)),
        }),
        holdout_ref: format!("holdout-v1-{seed}"),
        epoch_size: 20,
        oracle_num_symbols: 4,
        access_credit: 64,
    }
}

#[tokio::test]
async fn daemon_protocol_v1_and_v2_smoke() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;

    let mut v2 = v2_client(addr).await;
    let v2_claim = v2
        .create_claim_v2(v2_create(7))
        .await
        .expect("v2 create should succeed")
        .into_inner();
    assert_eq!(v2_claim.state, pb::ClaimState::Uncommitted as i32);

    let mut v1 = v1_client(addr).await;
    let v1_claim = v1
        .create_claim_v2(v1_create(9))
        .await
        .expect("v1 create should succeed")
        .into_inner();
    assert_eq!(v1_claim.state, v1::ClaimState::Uncommitted as i32);

    handle.abort();
}

#[tokio::test]
async fn proto_roundtrip_backcompat_capsule() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;

    let mut v2 = v2_client(addr).await;
    let claim = v2
        .create_claim_v2(v2_create(11))
        .await
        .expect("v2 create")
        .into_inner();

    let v2_capsule = v2
        .fetch_capsule(pb::FetchCapsuleRequest {
            claim_id: claim.claim_id.clone(),
        })
        .await
        .expect("v2 fetch")
        .into_inner();

    let mut v1 = v1_client(addr).await;
    let v1_capsule = v1
        .fetch_capsule(v1::FetchCapsuleRequest {
            claim_id: claim.claim_id,
        })
        .await
        .expect("v1 fetch")
        .into_inner();

    assert_eq!(v1_capsule.capsule_hash, v2_capsule.capsule_hash);
    assert_eq!(v1_capsule.etl_index, v2_capsule.etl_index);
    assert_eq!(v1_capsule.capsule_bytes, v2_capsule.capsule_bytes);

    handle.abort();
}
