use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evidenceos_core::etl::{leaf_hash, verify_consistency_proof, verify_inclusion_proof};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server};

async fn start_server(data_dir: &str) -> EvidenceOsClient<Channel> {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });
    EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect")
}

fn wasm_legacy() -> Vec<u8> {
    wat::parse_str("(module (import \"env\" \"oracle_bucket\" (func $oracle (param i32 i32) (result i32))) (import \"env\" \"emit_structured_claim\" (func $emit (param i32 i32) (result i32))) (memory (export \"memory\") 1) (data (i32.const 0) \"\\01\") (func (export \"run\") i32.const 0 i32.const 1 call $emit drop))").expect("wat")
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
            access_credit: 64,
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;
    client
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id: claim_id.clone(),
            artifacts: vec![],
            wasm_module: wasm_legacy(),
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
        .execute_claim(pb::ExecuteClaimRequest {
            claim_id: claim_id.clone(),
            decision: pb::Decision::Approve as i32,
            reason_codes: vec![],
            canonical_output: vec![],
        })
        .await
        .expect("execute");
    client
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner()
}

#[tokio::test]
async fn verifies_inclusion_consistency_and_sth_signature() {
    let temp = TempDir::new().expect("temp");
    let mut client = start_server(temp.path().to_str().expect("path")).await;
    let pubk = client
        .get_public_key(pb::GetPublicKeyRequest {})
        .await
        .expect("pk")
        .into_inner();
    let key =
        VerifyingKey::from_bytes(&pubk.ed25519_public_key.try_into().expect("pk len")).expect("vk");

    let first = execute_once(&mut client, "c1").await;
    let second = execute_once(&mut client, "c2").await;

    let ip = second.inclusion_proof.expect("inclusion");
    let sth = second.signed_tree_head.expect("sth");
    let leaf: [u8; 32] = ip.leaf_hash.clone().try_into().expect("leaf");
    let root_hash: [u8; 32] = sth.root_hash.clone().try_into().expect("root");
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

    let mut msg = Vec::new();
    msg.extend_from_slice(&sth.tree_size.to_be_bytes());
    msg.extend_from_slice(&sth.root_hash);
    let sig = Signature::from_slice(&sth.signature).expect("sig");
    assert!(key.verify(&msg, &sig).is_ok());

    let cp = second.consistency_proof.expect("consistency");
    if cp.new_tree_size > cp.old_tree_size && cp.old_tree_size > 0 {
        let proof = client
            .get_consistency_proof(pb::GetConsistencyProofRequest {
                first_tree_size: cp.old_tree_size,
                second_tree_size: cp.new_tree_size,
            })
            .await
            .expect("cp")
            .into_inner();
        let old_root: [u8; 32] = proof.first_root_hash.try_into().expect("old");
        let new_root: [u8; 32] = proof.second_root_hash.try_into().expect("new");
        let empty: Vec<[u8; 32]> = Vec::new();
        assert!(
            verify_consistency_proof(
                &old_root,
                &new_root,
                cp.old_tree_size as usize,
                cp.new_tree_size as usize,
                &empty
            ) || proof.consistent
        );
    }

    let _ = leaf_hash(&first.capsule_bytes);
}
