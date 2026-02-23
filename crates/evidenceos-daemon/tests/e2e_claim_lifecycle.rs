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
#![allow(dead_code)]
use std::net::SocketAddr;
use std::sync::Arc;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_daemon::telemetry::Telemetry;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server, Code};

fn hash(seed: u8) -> Vec<u8> {
    [seed; 32].to_vec()
}

const LEGACY_SCHEMA_ID: &str = "legacy/v1";

fn sha256(payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
}

fn dependency_merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    if items.is_empty() {
        let mut out = [0u8; 32];
        out.copy_from_slice(&sha256(&[]));
        return out;
    }
    let mut layer: Vec<[u8; 32]> = items
        .iter()
        .copied()
        .map(|value| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&sha256(&value));
            out
        })
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                left
            };
            let mut concat = [0u8; 64];
            concat[..32].copy_from_slice(&left);
            concat[32..].copy_from_slice(&right);
            let mut out = [0u8; 32];
            out.copy_from_slice(&sha256(&concat));
            next.push(out);
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn trial_commitment_hash_from_fields(
    schema_version: u8,
    arm_id: u16,
    intervention_id: &str,
    trial_nonce: [u8; 16],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update([schema_version]);
    hasher.update(arm_id.to_be_bytes());
    hasher.update(intervention_id.as_bytes());
    hasher.update(trial_nonce);
    hex::encode(hasher.finalize())
}

fn valid_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit
            drop)
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
              (import "env" "emit_structured_claim" (func $emit (param i32 i32)))
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
              (import "env" "emit_structured_claim" (func $emit (param i32 i32)))
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
              (import "env" "emit_structured_claim" (func $emit (param i32 i32)))
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
            output_schema_id: "legacy/v1".to_string(),
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

async fn create_claim_v2_with_dependency_root(
    c: &mut EvidenceOsClient<Channel>,
    seed: u8,
    dependency_root: [u8; 32],
) -> Vec<u8> {
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
            dependency_merkle_root: dependency_root.to_vec(),
        }),
        holdout_ref: format!("holdout-{seed}"),
        epoch_size: 10,
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

async fn commit_freeze_seal(c: &mut EvidenceOsClient<Channel>, claim_id: Vec<u8>, wasm: Vec<u8>) {
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
    commit_freeze_seal(&mut c, claim_id.clone(), valid_wasm()).await;

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
async fn freeze_trial_commitment_hash_is_bound_into_capsule() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let claim_id = create_claim_v2(&mut c, 11).await;
    commit_freeze_seal(&mut c, claim_id.clone(), valid_wasm()).await;

    c.execute_claim_v2(pb::ExecuteClaimV2Request {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("execute");

    let capsule = c
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    let json: Value = serde_json::from_slice(&capsule.capsule_bytes).expect("capsule json");

    let hash_hex = json["trial_commitment_hash_hex"]
        .as_str()
        .expect("trial commitment hash");
    let schema_version = json["trial_commitment_schema_version"]
        .as_u64()
        .expect("trial schema") as u8;
    let arm_id = json["trial_arm_id"].as_u64().expect("trial arm") as u16;
    let intervention_id = json["trial_intervention_id"]
        .as_str()
        .expect("trial intervention id");
    let trial_nonce_hex = json["trial_nonce_hex"].as_str().expect("trial nonce hex");
    let trial_nonce_vec = hex::decode(trial_nonce_hex).expect("decode nonce");
    let trial_nonce: [u8; 16] = trial_nonce_vec
        .try_into()
        .expect("nonce has expected length");

    let recomputed =
        trial_commitment_hash_from_fields(schema_version, arm_id, intervention_id, trial_nonce);
    assert_eq!(hash_hex, recomputed);

    let changed_arm = trial_commitment_hash_from_fields(
        schema_version,
        arm_id.wrapping_add(1),
        intervention_id,
        trial_nonce,
    );
    assert_ne!(hash_hex, changed_arm);

    let changed_intervention = trial_commitment_hash_from_fields(
        schema_version,
        arm_id,
        &(intervention_id.to_string() + "-tampered"),
        trial_nonce,
    );
    assert_ne!(hash_hex, changed_intervention);

    let mut changed_nonce = trial_nonce;
    changed_nonce[0] ^= 0x01;
    let changed_nonce_hash =
        trial_commitment_hash_from_fields(schema_version, arm_id, intervention_id, changed_nonce);
    assert_ne!(hash_hex, changed_nonce_hash);

    let changed_schema = trial_commitment_hash_from_fields(
        schema_version.wrapping_add(1),
        arm_id,
        intervention_id,
        trial_nonce,
    );
    assert_ne!(hash_hex, changed_schema);

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

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        })
        .await
        .expect_err("empty claim_name rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    let err = c
        .create_claim_v2(pb::CreateClaimV2Request {
            claim_name: "bad-metadata".to_string(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".to_string(),
                alpha_micros: 50_000,
                epoch_config_ref: String::new(),
                output_schema_id: "legacy/v1".to_string(),
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

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        })
        .await
        .expect_err("empty metadata.epoch_config_ref rejected");
    assert_eq!(err.code(), Code::InvalidArgument);

    let err = c
        .create_claim_v2(pb::CreateClaimV2Request {
            claim_name: "bad-schema".to_string(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".to_string(),
                alpha_micros: 50_000,
                epoch_config_ref: "epoch".to_string(),
                output_schema_id: String::new(),
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

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        })
        .await
        .expect_err("empty metadata.output_schema_id rejected");
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
            decision: pb::Decision::Approve as i32,
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
    c.get_public_key(pb::GetPublicKeyRequest { key_id: vec![] })
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

#[tokio::test]
async fn capsule_includes_dependency_list() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let mut deps = vec![[9u8; 32], [2u8; 32], [7u8; 32]];
    deps.sort();
    let dependency_root = dependency_merkle_root(&deps);
    let claim_id = create_claim_v2_with_dependency_root(&mut c, 29, dependency_root).await;

    let mut artifacts = wasm_artifacts(&valid_wasm());
    artifacts.extend(deps.iter().rev().map(|dep| pb::Artifact {
        artifact_hash: dep.to_vec(),
        kind: "dependency".to_string(),
    }));

    c.commit_artifacts(pb::CommitArtifactsRequest {
        claim_id: claim_id.clone(),
        artifacts,
        wasm_module: valid_wasm(),
    })
    .await
    .expect("commit");

    c.freeze_gates(pb::FreezeGatesRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("freeze");

    c.seal_claim(pb::SealClaimRequest {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("seal");

    c.execute_claim_v2(pb::ExecuteClaimV2Request {
        claim_id: claim_id.clone(),
    })
    .await
    .expect("execute");

    let capsule = c
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    let json: Value = serde_json::from_slice(&capsule.capsule_bytes).expect("capsule json");
    let dependency_hashes = json["dependency_capsule_hashes"]
        .as_array()
        .expect("dependency list");
    assert_eq!(dependency_hashes.len(), deps.len());

    let expected_hex: Vec<String> = deps.iter().map(hex::encode).collect();
    let observed_hex: Vec<String> = dependency_hashes
        .iter()
        .map(|value| value.as_str().expect("hex").to_string())
        .collect();
    assert_eq!(observed_hex, expected_hex);

    let lineage_hex = json["lineage_root_hash_hex"]
        .as_str()
        .expect("lineage root");
    assert_eq!(lineage_hex, hex::encode(dependency_root));

    handle.abort();
}

#[tokio::test]
async fn topic_budget_is_shared_across_claims() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let (addr, handle) = start_server(&data_dir.to_string_lossy()).await;
    let mut c = client(addr).await;

    let req = |name: &str, holdout: &str| pb::CreateClaimV2Request {
        claim_name: name.to_string(),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "shared-epoch".to_string(),
            output_schema_id: LEGACY_SCHEMA_ID.to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: hash(41),
            phys_hir_signature_hash: hash(42),
            dependency_merkle_root: hash(43),
        }),
        holdout_ref: holdout.to_string(),
        epoch_size: 10,
        oracle_num_symbols: 4,
        access_credit: 16,

        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: String::new(),
        dp_epsilon_budget: None,
        dp_delta_budget: None,
    };

    let claim_a = c
        .create_claim_v2(req("claim-a", "holdout-a"))
        .await
        .expect("create a")
        .into_inner()
        .claim_id;
    let claim_b = c
        .create_claim_v2(req("claim-b", "holdout-b"))
        .await
        .expect("create b")
        .into_inner()
        .claim_id;

    commit_freeze_seal(&mut c, claim_a.clone(), valid_wasm()).await;
    commit_freeze_seal(&mut c, claim_b.clone(), valid_wasm()).await;

    let ok = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id: claim_a })
        .await;
    assert!(ok.is_ok());

    let second = c
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_b.clone(),
        })
        .await;
    match second {
        Ok(response) => {
            let second = response.into_inner();
            assert_eq!(second.state, pb::ClaimState::Revoked as i32);
        }
        Err(status) => {
            assert_eq!(status.code(), Code::FailedPrecondition);
            assert_eq!(status.message(), "topic budget exhausted");
        }
    }

    handle.abort();
}

#[tokio::test]
async fn metrics_endpoint_increments_after_lifecycle() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
    let metrics_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("metrics bind");
    let metrics_addr = metrics_listener.local_addr().expect("metrics addr");
    drop(metrics_listener);
    let _metrics = telemetry
        .clone()
        .spawn_metrics_server(metrics_addr)
        .await
        .expect("metrics server");

    let svc = EvidenceOsService::build_with_options(&data_dir.to_string_lossy(), false, telemetry)
        .expect("service");
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

    let mut c = client(addr).await;
    let claim_id = create_claim_v2(&mut c, 19).await;
    commit_freeze_seal(&mut c, claim_id.clone(), valid_wasm()).await;
    let _ = c
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
        .await
        .expect("execute");

    let mut stream = tokio::net::TcpStream::connect(metrics_addr)
        .await
        .expect("metrics connect");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("metrics write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("metrics read");
    let text = String::from_utf8(raw).expect("utf8");
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .expect("http body")
        .to_string();
    assert!(body.contains("oracle_calls_total"));
    assert!(body.contains("k_bits_remaining"));

    handle.abort();
}
