// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Server};
use tonic::{Request, Status};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
type RequestIdClient =
    EvidenceOsClient<InterceptedService<Channel, fn(Request<()>) -> Result<Request<()>, Status>>>;

#[allow(clippy::result_large_err)]
fn add_request_id(mut req: Request<()>) -> Result<Request<()>, Status> {
    req.metadata_mut().insert(
        "x-request-id",
        format!("req-{}", REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed))
            .parse()
            .expect("request id"),
    );
    req.metadata_mut().insert(
        "authorization",
        "Bearer lifecycle-token".parse().expect("authorization"),
    );
    req.metadata_mut().insert(
        "x-evidenceos-token-scopes",
        "auditor".parse().expect("auditor scope"),
    );
    Ok(req)
}

fn write_epoch_config(data_dir: &str, epoch_ref: &str, epoch_size: u64) {
    let epoch_dir = std::path::Path::new(data_dir).join("epoch_configs");
    std::fs::create_dir_all(&epoch_dir).expect("mkdir epoch configs");
    let payload = serde_json::json!({
        "epoch_size": epoch_size,
        "pln": {
            "target_fuel": 100,
            "max_fuel": 500,
            "lanes": {"fast": true, "heavy": true}
        }
    });
    std::fs::write(
        epoch_dir.join(format!("{epoch_ref}.json")),
        serde_json::to_vec(&payload).expect("enc"),
    )
    .expect("write");
}

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
    .expect("valid wat")
}

async fn start_server(data_dir: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
    for (ref_id, size) in [
        ("epoch-1", 10_u64),
        ("epoch-2", 10),
        ("epoch-3", 10),
        ("epoch-4", 1),
    ] {
        write_epoch_config(data_dir, ref_id, size);
    }
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

async fn client(addr: SocketAddr) -> RequestIdClient {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    EvidenceOsClient::with_interceptor(
        channel,
        add_request_id as fn(Request<()>) -> Result<Request<()>, Status>,
    )
}

async fn create_claim_v2(c: &mut RequestIdClient, seed: u8, epoch_size: u64) -> Vec<u8> {
    c.create_claim_v2(pb::CreateClaimV2Request {
        claim_name: format!("claim-{seed}"),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: format!("epoch-{seed}"),
            output_schema_id: "legacy/v1".to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: hash(seed),
            phys_hir_signature_hash: hash(seed.wrapping_add(1)),
            dependency_merkle_root: Vec::new(),
        }),
        holdout_ref: "synthetic-holdout".to_string(),
        epoch_size,
        oracle_num_symbols: 4,
        access_credit: 64,

        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: String::new(),
        dp_epsilon_budget: None,
        dp_delta_budget: None,
    })
    .await
    .expect("create claim v2")
    .into_inner()
    .claim_id
}

async fn commit(c: &mut RequestIdClient, claim_id: Vec<u8>) {
    let wasm_module = valid_wasm();
    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id,
        artifacts: vec![pb::Artifact {
            artifact_hash: sha256(&wasm_module),
            kind: "wasm".to_string(),
        }],
        wasm_module,
    })
    .await
    .expect("commit artifacts");
}

#[tokio::test]
async fn cannot_commit_after_freeze() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 1, 10).await;
    commit(&mut c, claim_id.clone()).await;
    c.freeze_gates(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("freeze");

    let wasm_module = valid_wasm();
    let err = c
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id,
            artifacts: vec![pb::Artifact {
                artifact_hash: sha256(&wasm_module),
                kind: "wasm".to_string(),
            }],
            wasm_module,
        })
        .await
        .expect_err("commit after freeze should fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    handle.abort();
}

#[tokio::test]
async fn cannot_execute_before_seal() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 2, 10).await;
    commit(&mut c, claim_id.clone()).await;

    let err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
        .await
        .expect_err("execute before seal should fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    handle.abort();
}

#[tokio::test]
async fn seal_is_idempotent() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 3, 10).await;
    commit(&mut c, claim_id.clone()).await;

    let s1 = c
        .seal_claim(pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("seal 1")
        .into_inner();
    let s2 = c
        .seal_claim(pb::SealClaimRequest { claim_id })
        .await
        .expect("seal 2")
        .into_inner();

    assert_eq!(s1.state, pb::ClaimState::Sealed as i32);
    assert_eq!(s2.state, pb::ClaimState::Sealed as i32);
    handle.abort();
}

#[tokio::test]
async fn stale_claim_requires_refreeze() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 4, 1).await;
    commit(&mut c, claim_id.clone()).await;
    c.seal_claim(pb::SealClaimRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("seal");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let stale_err = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect_err("stale execute should fail");
    assert_eq!(stale_err.code(), tonic::Code::FailedPrecondition);

    c.freeze_gates(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("refreeze");

    // Refreeze should succeed and allow lifecycle to continue from sealed/stale gate.
    handle.abort();
}
