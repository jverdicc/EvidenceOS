use evidenceos_core::capsule::ClaimCapsule;
use evidenceos_core::crypto_transcripts::verify_sth_signature as verify_sth_signature_core;
use evidenceos_core::etl::{
    verify_consistency_proof as verify_consistency_proof_core,
    verify_inclusion_proof as verify_inclusion_proof_core,
};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use evidenceos_verifier::{verify_consistency_proof, verify_inclusion_proof, verify_sth_signature};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server};

struct TestServer {
    client: EvidenceOsClient<Channel>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    async fn start(data_dir: &str) -> Self {
        let svc = EvidenceOsService::build(data_dir).expect("service");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let incoming = TcpListenerStream::new(listener);
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            Server::builder()
                .add_service(EvidenceOsServer::new(svc))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = rx.await;
                })
                .await
                .expect("server run");
        });
        let client = EvidenceOsClient::connect(format!("http://{addr}"))
            .await
            .expect("connect");
        Self {
            client,
            shutdown: Some(tx),
        }
    }

    async fn stop(mut self) {
        let _ = self.shutdown.take().expect("shutdown").send(());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn wasm_legacy() -> Vec<u8> {
    wat::parse_str("(module (import \"env\" \"emit_structured_claim\" (func $emit (param i32 i32) (result i32))) (memory (export \"memory\") 1) (data (i32.const 0) \"\\01\") (func (export \"run\") i32.const 0 i32.const 1 call $emit drop))").expect("wat")
}

async fn execute_once(
    client: &mut EvidenceOsClient<Channel>,
    name: &str,
) -> pb::FetchCapsuleResponse {
    let claim_id = client
        .create_claim_v2(pb::CreateClaimV2Request {
            claim_name: name.into(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".into(),
                alpha_micros: 50_000,
                epoch_config_ref: "e".into(),
                output_schema_id: "legacy/v1".into(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: vec![1; 32],
                phys_hir_signature_hash: vec![2; 32],
                dependency_merkle_root: vec![3; 32],
            }),
            holdout_ref: "h".into(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            access_credit: 128,

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    let wasm = wasm_legacy();
    let artifact_hash = {
        let mut h = Sha256::new();
        h.update(&wasm);
        h.finalize().to_vec()
    };
    client
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id: claim_id.clone(),
            artifacts: vec![pb::Artifact {
                kind: "wasm".into(),
                artifact_hash,
            }],
            wasm_module: wasm,
        })
        .await
        .expect("commit");
    client
        .freeze_gates(pb::FreezeGatesRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("freeze");
    client
        .seal_claim(pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("seal");
    client
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("execute");
    client
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner()
}

fn rotate_key(data_dir: &std::path::Path, seed: u8) {
    use ed25519_dalek::SigningKey;
    let mut secret = [0u8; 32];
    secret.fill(seed);
    let key = SigningKey::from_bytes(&secret);
    let key_id: [u8; 32] = Sha256::digest(key.verifying_key().to_bytes()).into();
    let keys_dir = data_dir.join("keys");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    std::fs::write(
        keys_dir.join(format!("{}.key", hex::encode(key_id))),
        secret,
    )
    .expect("write key");
    std::fs::write(
        keys_dir.join("active_key_id"),
        format!("{}\n", hex::encode(key_id)),
    )
    .expect("write active");
}

fn verify_sth_with_response_key(sth: &pb::SignedTreeHead, key: &[u8]) {
    verify_sth_signature(sth, key).expect("sth signature");
    verify_sth_signature_core(sth, key).expect("sth signature core");
}

#[tokio::test]
async fn verifies_inclusion_consistency_and_sth_signature() {
    let temp = TempDir::new().expect("temp");
    let mut server = TestServer::start(temp.path().to_str().expect("path")).await;
    let pubk = server
        .client
        .get_public_key(pb::GetPublicKeyRequest { key_id: vec![] })
        .await
        .expect("pk")
        .into_inner();

    let _first = execute_once(&mut server.client, "c1").await;
    let second = execute_once(&mut server.client, "c2").await;

    let ip = second.inclusion_proof.expect("inclusion");
    let sth = second.signed_tree_head.expect("sth");

    let leaf: [u8; 32] = ip.leaf_hash.try_into().expect("leaf");
    let root_hash: [u8; 32] = second.root_hash.try_into().expect("root");
    let path: Vec<[u8; 32]> = ip
        .audit_path
        .into_iter()
        .map(|x| x.try_into().expect("h"))
        .collect();
    assert!(verify_inclusion_proof(
        &path,
        &leaf,
        ip.leaf_index as usize,
        ip.tree_size as usize,
        &root_hash
    ));
    assert!(verify_inclusion_proof_core(
        &path,
        &leaf,
        ip.leaf_index as usize,
        ip.tree_size as usize,
        &root_hash
    ));

    verify_sth_signature(&sth, &pubk.ed25519_public_key).expect("sth signature");

    let cp = second.consistency_proof.expect("consistency");
    let proof = server
        .client
        .get_consistency_proof(pb::GetConsistencyProofRequest {
            first_tree_size: cp.old_tree_size,
            second_tree_size: cp.new_tree_size,
        })
        .await
        .expect("cp")
        .into_inner();
    let old_root: [u8; 32] = proof.first_root_hash.try_into().expect("old");
    let new_root: [u8; 32] = proof.second_root_hash.try_into().expect("new");
    let cp_path: Vec<[u8; 32]> = cp
        .path
        .into_iter()
        .map(|x| x.try_into().expect("cp path"))
        .collect();
    assert!(verify_consistency_proof(
        &old_root,
        &new_root,
        cp.old_tree_size as usize,
        cp.new_tree_size as usize,
        &cp_path
    ));
    assert!(verify_consistency_proof_core(
        &old_root,
        &new_root,
        cp.old_tree_size as usize,
        cp.new_tree_size as usize,
        &cp_path
    ));
    server.stop().await;
}

#[tokio::test]
async fn key_rotation_preserves_old_head_verification() {
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path();
    let mut server = TestServer::start(data_dir.to_str().expect("path")).await;

    let first = execute_once(&mut server.client, "first").await;
    let sth_a = first.signed_tree_head.clone().expect("sth a");
    let key_a = server
        .client
        .get_public_key(pb::GetPublicKeyRequest {
            key_id: sth_a.key_id.clone(),
        })
        .await
        .expect("get key a")
        .into_inner()
        .ed25519_public_key;
    verify_sth_with_response_key(&sth_a, &key_a);

    server.stop().await;
    rotate_key(data_dir, 99);

    let mut server = TestServer::start(data_dir.to_str().expect("path")).await;
    let second = execute_once(&mut server.client, "second").await;
    let sth_b = second.signed_tree_head.clone().expect("sth b");
    assert_ne!(sth_a.key_id, sth_b.key_id);

    let key_b = server
        .client
        .get_public_key(pb::GetPublicKeyRequest {
            key_id: sth_b.key_id.clone(),
        })
        .await
        .expect("get key b")
        .into_inner()
        .ed25519_public_key;
    verify_sth_with_response_key(&sth_b, &key_b);

    let old_again = server
        .client
        .get_public_key(pb::GetPublicKeyRequest {
            key_id: sth_a.key_id.clone(),
        })
        .await
        .expect("get old key")
        .into_inner()
        .ed25519_public_key;
    verify_sth_with_response_key(&sth_a, &old_again);
    server.stop().await;
}

#[tokio::test]
async fn property_random_rotation_and_append_stays_verifiable() {
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path();
    let mut state: u64 = 0xE4_1234_ABCD;

    let mut known_sths: Vec<pb::SignedTreeHead> = Vec::new();
    for step in 0..20_u8 {
        let mut server = TestServer::start(data_dir.to_str().expect("path")).await;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        if state % 10 < 3 {
            server.stop().await;
            rotate_key(data_dir, step.wrapping_add(11));
            continue;
        }

        let resp = execute_once(&mut server.client, &format!("c-{step}")).await;
        let sth = resp.signed_tree_head.expect("sth");
        known_sths.push(sth.clone());

        for prev in &known_sths {
            let key = server
                .client
                .get_public_key(pb::GetPublicKeyRequest {
                    key_id: prev.key_id.clone(),
                })
                .await
                .expect("get key")
                .into_inner()
                .ed25519_public_key;
            verify_sth_with_response_key(prev, &key);
        }
        server.stop().await;
    }
}

#[tokio::test]
async fn trial_metadata_keeps_etl_verification_and_old_format_parsing() {
    let temp = TempDir::new().expect("temp");
    let mut server = TestServer::start(temp.path().to_str().expect("path")).await;

    let response = execute_once(&mut server.client, "trial-capsule").await;

    let ip = response.inclusion_proof.clone().expect("inclusion");
    let leaf: [u8; 32] = ip.leaf_hash.try_into().expect("leaf");
    let root_hash: [u8; 32] = response.root_hash.clone().try_into().expect("root");
    let path: Vec<[u8; 32]> = ip
        .audit_path
        .clone()
        .into_iter()
        .map(|x| x.try_into().expect("path hash"))
        .collect();
    assert!(verify_inclusion_proof(
        &path,
        &leaf,
        ip.leaf_index as usize,
        ip.tree_size as usize,
        &root_hash
    ));
    assert!(verify_inclusion_proof_core(
        &path,
        &leaf,
        ip.leaf_index as usize,
        ip.tree_size as usize,
        &root_hash
    ));

    let capsule: Value =
        serde_json::from_slice(&response.capsule_bytes).expect("capsule json value");
    let trial = capsule["trial"]
        .as_object()
        .expect("trial metadata present");
    assert!(
        trial["arm_id"].as_u64().is_some(),
        "trial arm id is present"
    );
    assert!(
        trial["intervention_id"].as_str().is_some(),
        "trial intervention id is present"
    );
    assert!(
        trial["trial_nonce_hex"].as_str().is_some(),
        "trial nonce is present"
    );

    let mut old_format = capsule.clone();
    old_format
        .as_object_mut()
        .expect("capsule object")
        .remove("trial");
    let old_format_bytes = serde_json::to_vec(&old_format).expect("old format bytes");
    let parsed_old: ClaimCapsule =
        serde_json::from_slice(&old_format_bytes).expect("old-format parse");
    assert_eq!(parsed_old.trial, None);

    let parsed_current: ClaimCapsule =
        serde_json::from_slice(&response.capsule_bytes).expect("current parse");
    assert!(parsed_current.trial.is_some());

    server.stop().await;
}
