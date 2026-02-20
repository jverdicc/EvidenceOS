use ed25519_dalek::SigningKey;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb::{
    self, evidence_os_client::EvidenceOsClient, evidence_os_server::EvidenceOsServer,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::process::Command;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
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
    .expect("wat")
}

async fn start_server(
    data_dir: &str,
) -> (EvidenceOsService, SocketAddr, tokio::task::JoinHandle<()>) {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    let clone = svc.clone();
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("serve");
    });
    (clone, addr, handle)
}

async fn client(addr: SocketAddr) -> EvidenceOsClient<Channel> {
    EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect")
}

async fn create_claim_v2(c: &mut EvidenceOsClient<Channel>, claim_name: &str, seed: u8) -> Vec<u8> {
    c.create_claim_v2(pb::CreateClaimV2Request {
        claim_name: claim_name.to_string(),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch-ctl".to_string(),
            output_schema_id: "legacy/v1".to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: hash(seed),
            phys_hir_signature_hash: hash(seed.wrapping_add(1)),
            dependency_merkle_root: hash(seed.wrapping_add(2)),
        }),
        holdout_ref: "holdout-a".to_string(),
        epoch_size: 60,
        oracle_num_symbols: 4,
        access_credit: 64,
    })
    .await
    .expect("create")
    .into_inner()
    .claim_id
}

async fn commit_and_seal(c: &mut EvidenceOsClient<Channel>, claim_id: Vec<u8>) {
    let wasm_module = valid_wasm();
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts: vec![
            pb::Artifact {
                artifact_hash: sha256(&wasm_module),
                kind: "wasm".to_string(),
            },
            pb::Artifact {
                artifact_hash: hash(77),
                kind: "dependency".to_string(),
            },
        ],
        wasm_module,
    })
    .await
    .expect("commit");

    c.seal_claim(pb::SealClaimRequest { claim_id })
        .await
        .expect("seal");
}

fn run_ctl(args: &[&str]) {
    let output = Command::new("cargo")
        .args(["run", "-q", "-p", "evidenceosctl", "--"])
        .args(args)
        .output()
        .expect("run ctl");
    assert!(
        output.status.success(),
        "ctl failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn oracle_ttl_update_reload_applies_to_subsequent_claims() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk_hex = hex::encode(sk.verifying_key().to_bytes());
    std::fs::write(data_dir.join("signing.key"), [7u8; 32]).expect("seed");
    std::fs::write(
        data_dir.join("trusted_oracle_keys.json"),
        serde_json::to_vec(&serde_json::json!({"keys": {"ops-k1": vk_hex}})).expect("json"),
    )
    .expect("trusted keys");

    let (svc, addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    run_ctl(&[
        "epoch",
        "advance",
        "--data-dir",
        &data_dir.to_string_lossy(),
        "--to",
        "0",
        "--signing-key",
        &data_dir.join("signing.key").to_string_lossy(),
        "--key-id",
        "ops-k1",
    ]);
    svc.reload_operator_runtime_config().expect("reload epoch");

    let claim1 = create_claim_v2(&mut c, "oracle-A", 11).await;
    commit_and_seal(&mut c, claim1.clone()).await;

    run_ctl(&[
        "oracle",
        "set-ttl",
        "--data-dir",
        &data_dir.to_string_lossy(),
        "--oracle-id",
        "oracle-A",
        "--ttl-epochs",
        "5",
        "--signing-key",
        &data_dir.join("signing.key").to_string_lossy(),
        "--key-id",
        "ops-k1",
    ]);
    svc.reload_operator_runtime_config().expect("reload ttl");

    let claim2 = create_claim_v2(&mut c, "oracle-A", 31).await;
    commit_and_seal(&mut c, claim2.clone()).await;

    run_ctl(&[
        "epoch",
        "advance",
        "--data-dir",
        &data_dir.to_string_lossy(),
        "--to",
        "3",
        "--signing-key",
        &data_dir.join("signing.key").to_string_lossy(),
        "--key-id",
        "ops-k1",
    ]);
    svc.reload_operator_runtime_config()
        .expect("reload epoch 3");

    let err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id: claim1 })
        .await
        .expect_err("claim1 stale");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let claim2_err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id: claim2 })
        .await
        .expect_err("claim2 should fail later in execution path");
    assert_eq!(claim2_err.code(), tonic::Code::FailedPrecondition);
    assert_ne!(
        claim2_err.message(),
        "claim is stale; re-freeze before execution"
    );

    handle.abort();
}
