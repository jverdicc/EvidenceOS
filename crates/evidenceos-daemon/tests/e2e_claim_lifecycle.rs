use std::net::SocketAddr;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use evidenceos_protocol::DOMAIN_CAPSULE_HASH;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
}

const DOMAIN_STH_V1: &[u8] = b"evidenceos:sth:v1";
const DOMAIN_REVOCATIONS_V1: &[u8] = b"evidenceos:revocations:v1";

fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(payload);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

fn sth_payload_digest(tree_size: u64, root_hash: &[u8]) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&tree_size.to_be_bytes());
    payload.extend_from_slice(root_hash);
    sha256_domain(DOMAIN_STH_V1, &payload)
}

fn append_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn revocations_payload_digest(entries: &[pb::RevocationEntry]) -> [u8; 32] {
    let mut payload = Vec::new();
    for entry in entries {
        append_len_prefixed_bytes(&mut payload, &entry.claim_id);
        payload.extend_from_slice(&entry.timestamp_unix.to_be_bytes());
        append_len_prefixed_bytes(&mut payload, entry.reason.as_bytes());
    }
    sha256_domain(DOMAIN_REVOCATIONS_V1, &payload)
}

fn sha256(payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
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

fn rejected_wasm_modules() -> Vec<Vec<u8>> {
    vec![
        wat::parse_str(
            r#"(module
              (import "env" "not_allowed" (func))
              (memory (export "memory") 1)
              (func (export "run"))
            )"#,
        )
        .expect("wat"),
        wat::parse_str(
            r#"(module
              (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
              (type $t (func))
              (table 1 funcref)
              (elem (i32.const 0) $f)
              (memory (export "memory") 1)
              (func $f)
              (func (export "run")
                i32.const 0
                call_indirect (type $t))
            )"#,
        )
        .expect("wat"),
        wat::parse_str(
            r#"(module
              (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "run")
                i32.const 1
                memory.grow
                drop)
            )"#,
        )
        .expect("wat"),
        wat::parse_str(
            r#"(module
              (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "run")
                f32.const 1.0
                drop)
            )"#,
        )
        .expect("wat"),
    ]
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

async fn commit_freeze_seal(
    c: &mut EvidenceOsClient<Channel>,
    claim_id: Vec<u8>,
    wasm_module: Vec<u8>,
) {
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: vec![
            pb::Artifact {
                artifact_hash: sha256(&wasm_module),
                kind: "wasm".to_string(),
            },
            pb::Artifact {
                artifact_hash: hash(200),
                kind: "manifest".to_string(),
            },
        ],
        wasm_module,
    })
    .await
    .expect("commit artifacts");

    c.freeze_gates(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("freeze gates");

    c.seal_claim(pb::SealClaimRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("seal claim");
}

#[tokio::test]
async fn e2e_claim_lifecycle_blackbox() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let h = c
        .health(pb::HealthRequest {})
        .await
        .expect("health")
        .into_inner();
    assert_eq!(h.status, "SERVING");

    let unsealed_claim = create_claim_v2(&mut c, 10).await;
    let unsealed_exec_err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: unsealed_claim.clone(),
        })
        .await
        .expect_err("execute before seal should fail");
    assert_eq!(unsealed_exec_err.code(), tonic::Code::FailedPrecondition);

    let legacy_claim = create_claim_v2(&mut c, 11).await;
    commit_freeze_seal(&mut c, legacy_claim.clone(), valid_wasm()).await;
    let v1_disabled = c
        .execute_claim(pb::ExecuteClaimRequest {
            claim_id: legacy_claim,
            decision: pb::Decision::Approve as i32,
            reason_codes: vec![1],
            canonical_output: vec![1],
        })
        .await
        .expect_err("v1 execute disabled");
    assert_eq!(v1_disabled.code(), tonic::Code::InvalidArgument);

    for module in rejected_wasm_modules() {
        let bad_claim = create_claim_v2(&mut c, 20).await;
        let err = c
            .commit_artifacts(pb::CommitArtifactsRequest {
                claim_id: bad_claim,
                artifacts: vec![pb::Artifact {
                    artifact_hash: sha256(&module),
                    kind: "wasm".to_string(),
                }],
                wasm_module: module,
            })
            .await
            .expect_err("aspec reject");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    let mismatch_claim = create_claim_v2(&mut c, 30).await;
    let wasm_for_mismatch = valid_wasm();
    let mismatch_err = c
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id: mismatch_claim,
            artifacts: vec![pb::Artifact {
                artifact_hash: hash(99),
                kind: "wasm".to_string(),
            }],
            wasm_module: wasm_for_mismatch,
        })
        .await
        .expect_err("wasm hash mismatch should fail");
    assert_eq!(mismatch_err.code(), tonic::Code::FailedPrecondition);

    let claim_a = create_claim_v2(&mut c, 40).await;
    commit_freeze_seal(&mut c, claim_a.clone(), valid_wasm()).await;
    let exec_a = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_a.clone(),
        })
        .await
        .expect("execute claim a")
        .into_inner();
    assert!(!exec_a.capsule_hash.is_empty());

    let capsule_a = c
        .fetch_capsule(pb::FetchCapsuleRequest {
            claim_id: claim_a.clone(),
        })
        .await
        .expect("fetch capsule a")
        .into_inner();
    assert_eq!(
        capsule_a.capsule_hash,
        sha256_domain(DOMAIN_CAPSULE_HASH, &capsule_a.capsule_bytes)
    );

    let old_sth = capsule_a.signed_tree_head.clone().expect("sth a");
    let old_size = old_sth.tree_size;
    let old_root: [u8; 32] = old_sth.root_hash.clone().try_into().expect("old root len");

    let claim_b = create_claim_v2(&mut c, 50).await;
    commit_freeze_seal(&mut c, claim_b.clone(), valid_wasm()).await;
    c.execute_claim_v2(pb::ExecuteClaimV2Request {
        claim_id: claim_b.clone(),
    })
    .await
    .expect("execute claim b");

    let capsule_b = c
        .fetch_capsule(pb::FetchCapsuleRequest {
            claim_id: claim_b.clone(),
        })
        .await
        .expect("fetch capsule b")
        .into_inner();
    let new_sth = capsule_b.signed_tree_head.clone().expect("sth b");
    assert!(new_sth.tree_size > old_size);

    let inclusion = capsule_b.inclusion_proof.expect("inclusion");
    let leaf: [u8; 32] = inclusion
        .leaf_hash
        .clone()
        .try_into()
        .expect("leaf hash len");
    let new_root: [u8; 32] = new_sth.root_hash.clone().try_into().expect("new root len");
    let path: Vec<[u8; 32]> = inclusion
        .audit_path
        .iter()
        .map(|b| b.clone().try_into().expect("path hash len"))
        .collect();
    assert!(verify_inclusion_proof(
        &path,
        &leaf,
        inclusion.leaf_index as usize,
        inclusion.tree_size as usize,
        &new_root,
    ));

    let capsule_a_later = c
        .fetch_capsule(pb::FetchCapsuleRequest {
            claim_id: claim_a.clone(),
        })
        .await
        .expect("fetch capsule a later")
        .into_inner();
    let consistency = capsule_a_later
        .consistency_proof
        .expect("consistency proof");
    assert_eq!(consistency.old_tree_size, old_size);
    assert_eq!(consistency.new_tree_size, new_sth.tree_size);
    let consistency_path: Vec<[u8; 32]> = consistency
        .path
        .iter()
        .map(|b| b.clone().try_into().expect("cons hash len"))
        .collect();
    assert!(verify_consistency_proof(
        &old_root,
        &new_root,
        old_size as usize,
        new_sth.tree_size as usize,
        &consistency_path,
    ));

    let pubkey = c
        .get_public_key(pb::GetPublicKeyRequest {})
        .await
        .expect("get public key")
        .into_inner();
    let vk = VerifyingKey::from_bytes(
        pubkey
            .ed25519_public_key
            .as_slice()
            .try_into()
            .expect("pubkey len"),
    )
    .expect("vk");
    let key_id = Sha256::digest(&pubkey.ed25519_public_key);
    assert_eq!(pubkey.key_id, key_id.as_slice());
    let msg = sth_payload_digest(sth.tree_size, &sth.root_hash);
    let sig = Signature::from_slice(&sth.signature).expect("sig");
    let mut msg = Vec::new();
    msg.extend_from_slice(&new_sth.tree_size.to_be_bytes());
    msg.extend_from_slice(&new_sth.root_hash);
    let sig = Signature::from_slice(&new_sth.signature).expect("sig");
    vk.verify(&msg, &sig).expect("sth signature verify");

    let mut tampered = msg;
    tampered[0] ^= 0x01;
    assert!(vk.verify(&tampered, &sig).is_err());

    let mut stream = c
        .watch_revocations(pb::WatchRevocationsRequest {})
        .await
        .expect("watch")
        .into_inner();

    c.revoke_claim(pb::RevokeClaimRequest {
        claim_id: claim_b.clone(),
        reason: "test revoke".to_string(),
    })
    .await
    .expect("revoke");
    let event = stream.message().await.expect("stream ok").expect("event");
    assert!(event.entries.iter().any(|e| e.claim_id == claim_id));
    let rev_msg = revocations_payload_digest(&event.entries);
    let rev_sig = Signature::from_slice(&event.signature).expect("revocation signature");
    vk.verify(&rev_msg, &rev_sig)
        .expect("revocation signature verify");

    let mut tampered_rev = rev_msg;
    tampered_rev[0] ^= 0x01;
    assert!(vk.verify(&tampered_rev, &rev_sig).is_err());
    assert!(event.entries.iter().any(|e| e.claim_id == claim_b));

    handle.abort();
}

#[tokio::test]
async fn persistence_fetch_capsule_stable_after_restart() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 60).await;
    commit_freeze_seal(&mut c, claim_id.clone(), valid_wasm()).await;
    c.execute_claim_v2(pb::ExecuteClaimV2Request {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("execute");

    let before = c
        .fetch_capsule(pb::FetchCapsuleRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("fetch")
        .into_inner();

    handle.abort();

    let (addr2, handle2) = start_server(&data_dir.to_string_lossy()).await;
    let mut c2 = client(addr2).await;
    let after = c2
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch after")
        .into_inner();

    assert_eq!(before.tree_size, after.tree_size);
    assert_eq!(before.root_hash, after.root_hash);
    assert_eq!(before.capsule_hash, after.capsule_hash);

    let pubkey = c2
        .get_public_key(pb::GetPublicKeyRequest {})
        .await
        .expect("get public key")
        .into_inner();
    let vk = VerifyingKey::from_bytes(
        pubkey
            .ed25519_public_key
            .as_slice()
            .try_into()
            .expect("pubkey len"),
    )
    .expect("vk");
    let sth = after.signed_tree_head.expect("sth");
    let msg = sth_payload_digest(sth.tree_size, &sth.root_hash);
    let sig = Signature::from_slice(&sth.signature).expect("sig");
    vk.verify(&msg, &sig).expect("sth signature verify");

    handle2.abort();
}
