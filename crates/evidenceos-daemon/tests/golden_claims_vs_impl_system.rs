use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::crypto_transcripts::{verify_revocations_snapshot, verify_sth_signature};
use evidenceos_core::etl::{leaf_hash, verify_inclusion_proof_ct};
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

fn v2_create(seed: u8) -> pb::CreateClaimV2Request {
    pb::CreateClaimV2Request {
        claim_name: format!("golden-v2-{seed}"),
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
        claim_name: format!("golden-v1-{seed}"),
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

async fn start_server(data_dir: &str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    unsafe {
        std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
    }
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

#[tokio::test]
async fn golden_claims_vs_impl_status_gate() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut v2 = EvidenceOsV2Client::<Channel>::connect(format!("http://{addr}"))
        .await
        .expect("v2 connect");
    let mut v1 = EvidenceOsV1Client::<Channel>::connect(format!("http://{addr}"))
        .await
        .expect("v1 connect");

    let v2_claim = v2
        .create_claim_v2(v2_create(7))
        .await
        .expect("v2 create")
        .into_inner();
    let v1_claim = v1
        .create_claim_v2(v1_create(9))
        .await
        .expect("v1 create")
        .into_inner();
    assert_eq!(v2_claim.state, pb::ClaimState::Uncommitted as i32);
    assert_eq!(v1_claim.state, v1::ClaimState::Uncommitted as i32);

    let leaf = leaf_hash(b"capsule-reference");
    assert!(verify_inclusion_proof_ct(&leaf, 0, 1, &[], &leaf));

    let sth_resp = v2
        .get_signed_tree_head(pb::GetSignedTreeHeadRequest {})
        .await
        .expect("get sth")
        .into_inner();
    let sth = pb::SignedTreeHead {
        tree_size: sth_resp.tree_size,
        root_hash: sth_resp.root_hash,
        signature: sth_resp.signature,
        key_id: sth_resp.key_id,
    };
    let key = v2
        .get_public_key(pb::GetPublicKeyRequest {
            key_id: sth.key_id.clone(),
        })
        .await
        .expect("get key")
        .into_inner()
        .ed25519_public_key;
    verify_sth_signature(&sth, &key).expect("sth signature");

    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let synthetic_sth = pb::SignedTreeHead {
        tree_size: 1,
        root_hash: [9u8; 32].to_vec(),
        signature: signing_key
            .sign(&evidenceos_core::crypto_transcripts::sth_signature_digest(
                1, [9u8; 32],
            ))
            .to_bytes()
            .to_vec(),
        key_id: vec![1u8; 32],
    };
    let synthetic_snapshot = pb::WatchRevocationsResponse {
        entries: vec![pb::RevocationEntry {
            claim_id: vec![2u8; 32],
            timestamp_unix: 42,
            reason: "golden-revocation".to_string(),
        }],
        signature: {
            let digest = evidenceos_core::crypto_transcripts::revocations_snapshot_digest(
                &[pb::RevocationEntry {
                    claim_id: vec![2u8; 32],
                    timestamp_unix: 42,
                    reason: "golden-revocation".to_string(),
                }],
                &synthetic_sth,
            )
            .expect("digest");
            signing_key.sign(&digest).to_bytes().to_vec()
        },
        signed_tree_head: Some(synthetic_sth),
        key_id: vec![1u8; 32],
    };
    verify_revocations_snapshot(&synthetic_snapshot, &signing_key.verifying_key().to_bytes())
        .expect("revocation snapshot");

    unsafe {
        std::env::remove_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT");
    }
    handle.abort();
}
