use std::net::SocketAddr;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server, Code};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
}

fn valid_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit)
        )"#,
    )
    .expect("valid wat")
}

fn wasm_artifacts(wasm_module: &[u8]) -> Vec<pb::Artifact> {
    use sha2::{Digest, Sha256};
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

async fn create_claim_v2(c: &mut EvidenceOsClient<Channel>, seed: u8) -> Vec<u8> {
    c.create_claim_v2(pb::CreateClaimV2Request {
        claim_name: format!("claim-{seed}"),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: format!("epoch-{seed}"),
            output_schema_id: format!("schema-{seed}"),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: hash(seed),
            phys_hir_signature_hash: hash(seed.wrapping_add(1)),
            dependency_merkle_root: hash(seed.wrapping_add(2)),
        }),
        holdout_ref: format!("holdout-{seed}"),
        epoch_size: 10,
        oracle_num_symbols: 4,
        access_credit: 64,
    })
    .await
    .expect("create claim v2")
    .into_inner()
    .claim_id
}

async fn commit_freeze_seal(c: &mut EvidenceOsClient<Channel>, claim_id: Vec<u8>) {
    let wasm = valid_wasm();
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: wasm_artifacts(&wasm),
        wasm_module: wasm,
    })
    .await
    .expect("commit");

    c.freeze_gates(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("freeze");

    c.seal_claim(pb::SealClaimRequest { claim_id })
        .await
        .expect("seal");
}

#[tokio::test]
async fn full_lifecycle_v2_through_tonic_server() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 1).await;
    commit_freeze_seal(&mut c, claim_id.clone()).await;

    let execute = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("execute")
        .into_inner();
    assert!(!execute.capsule_hash.is_empty());

    let capsule = c
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    assert!(!capsule.capsule_bytes.is_empty());
    assert!(!capsule.capsule_hash.is_empty());
    assert!(capsule.signed_tree_head.is_some());
    assert!(capsule.inclusion_proof.is_some());
    assert!(capsule.consistency_proof.is_some());

    handle.abort();
}

#[tokio::test]
async fn negative_parameter_boundaries_for_public_rpcs() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    // CreateClaim boundaries
    let err = c
        .create_claim(pb::CreateClaimRequest {
            topic_id: vec![],
            holdout_handle_id: vec![0; 32],
            phys_hir_hash: vec![0; 32],
            epoch_size: 1,
            oracle_num_symbols: 2,
            alpha: 0.5,
            access_credit: 1,
        })
        .await
        .expect_err("topic id length check");
    assert_eq!(err.code(), Code::InvalidArgument);

    // CreateClaimV2 boundaries
    let err = c
        .create_claim_v2(pb::CreateClaimV2Request {
            claim_name: String::new(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".to_string(),
                alpha_micros: 50_000,
                epoch_config_ref: "e".to_string(),
                output_schema_id: "o".to_string(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: vec![0; 32],
                phys_hir_signature_hash: vec![0; 32],
                dependency_merkle_root: vec![0; 32],
            }),
            holdout_ref: "h".to_string(),
            epoch_size: 1,
            oracle_num_symbols: 2,
            access_credit: 1,
        })
        .await
        .expect_err("empty claim_name rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    let valid_claim = create_claim_v2(&mut c, 2).await;

    // CommitArtifacts boundaries
    let err = c
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id: valid_claim.clone(),
            artifacts: vec![],
            wasm_module: valid_wasm(),
        })
        .await
        .expect_err("empty artifacts rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // FreezeGates boundary
    let err = c
        .freeze_gates(pb::FreezeGatesRequest { claim_id: vec![] })
        .await
        .expect_err("claim_id length rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // SealClaim boundary
    let err = c
        .seal_claim(pb::SealClaimRequest { claim_id: vec![] })
        .await
        .expect_err("claim_id length rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // ExecuteClaim boundary
    let err = c
        .execute_claim(pb::ExecuteClaimRequest {
            claim_id: vec![],
            decision: pb::Decision::DecisionApprove as i32,
            reason_codes: vec![],
            canonical_output: vec![],
        })
        .await
        .expect_err("claim_id length rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // ExecuteClaimV2 boundary
    let err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id: vec![] })
        .await
        .expect_err("claim_id length rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // GetCapsule boundary
    let err = c
        .get_capsule(pb::GetCapsuleRequest { claim_id: vec![] })
        .await
        .expect_err("claim_id length rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // GetInclusionProof boundary (huge index)
    let err = c
        .get_inclusion_proof(pb::GetInclusionProofRequest {
            leaf_index: u64::MAX,
        })
        .await
        .expect_err("index out of bounds");
    assert_eq!(err.code(), Code::NotFound);

    // GetConsistencyProof boundary
    let err = c
        .get_consistency_proof(pb::GetConsistencyProofRequest {
            first_tree_size: 2,
            second_tree_size: 1,
        })
        .await
        .expect_err("invalid size pair");
    assert_eq!(err.code(), Code::InvalidArgument);

    // FetchCapsule boundary
    let err = c
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id: vec![] })
        .await
        .expect_err("claim_id length rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // RevokeClaim boundaries
    let err = c
        .revoke_claim(pb::RevokeClaimRequest {
            claim_id: vec![0; 32],
            reason: String::new(),
        })
        .await
        .expect_err("empty reason rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    // RPCs without parameters still called for coverage and behavior checks.
    c.health(pb::HealthRequest {}).await.expect("health ok");
    c.get_public_key(pb::GetPublicKeyRequest {})
        .await
        .expect("pubkey ok");
    c.get_signed_tree_head(pb::GetSignedTreeHeadRequest {})
        .await
        .expect("sth ok");
    c.get_revocation_feed(pb::GetRevocationFeedRequest {})
        .await
        .expect("revocation feed ok");
    c.watch_revocations(pb::WatchRevocationsRequest {})
        .await
        .expect("watch revocations ok");

    handle.abort();
}
