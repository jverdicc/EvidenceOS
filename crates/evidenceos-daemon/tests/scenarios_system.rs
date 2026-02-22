use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use evidenceos_core::crypto_transcripts::verify_sth_signature;
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

#[derive(Debug, Deserialize)]
struct ScenarioSpec {
    scenario_id: String,
    category: String,
    steps: Vec<ScenarioStep>,
    expected_outcome: String,
    expected_evidence: ExpectedEvidence,
    deterministic_seed: u64,
}

#[derive(Debug, Deserialize)]
struct ScenarioStep {
    rpc: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct ExpectedEvidence {
    verify_inclusion_proof: bool,
    verify_consistency_proof: bool,
    verify_sth_signature: bool,
}

#[derive(Debug, Serialize, Default)]
struct ScenarioArtifact {
    scenario_id: String,
    category: String,
    expected_outcome: String,
    observed_outcome: String,
    deterministic_seed: u64,
    request_response_summary: Vec<Value>,
    evidence: ExpectedEvidence,
}

struct TestServer {
    client: EvidenceOsClient<Channel>,
}

impl TestServer {
    async fn start(data_dir: &str) -> Self {
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

        let client = EvidenceOsClient::connect(format!("http://{addr}"))
            .await
            .expect("connect");
        Self { client }
    }
}

fn load_scenarios(root: &Path) -> Vec<(PathBuf, ScenarioSpec)> {
    let mut files: Vec<PathBuf> = fs::read_dir(root)
        .expect("read_dir")
        .map(|item| item.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();

    files
        .into_iter()
        .map(|path| {
            let raw = fs::read_to_string(&path).expect("scenario file");
            let scenario: ScenarioSpec = serde_json::from_str(&raw).expect("scenario json");
            (path, scenario)
        })
        .collect()
}

fn hex32(input: &str) -> Vec<u8> {
    let bytes = hex::decode(input).expect("hex decode");
    if bytes.len() == 1 {
        return vec![bytes[0]; 32];
    }
    bytes
}

#[tokio::test]
async fn scenarios_produce_deterministic_public_evidence() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let scenario_dir = repo_root.join("docs/scenarios");
    let out_dir = std::env::var("SCENARIO_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("artifacts/scenarios"));
    fs::create_dir_all(&out_dir).expect("artifact dir");

    let specs = load_scenarios(&scenario_dir);
    assert!(!specs.is_empty(), "at least one scenario file is required");

    let temp = TempDir::new().expect("temp");
    let mut server = TestServer::start(temp.path().to_str().expect("path")).await;
    let public_key = server
        .client
        .get_public_key(pb::GetPublicKeyRequest { key_id: vec![] })
        .await
        .expect("public key")
        .into_inner()
        .ed25519_public_key;
    let mut artifacts = Vec::new();

    for (_path, scenario) in specs {
        let mut claim_id = Vec::new();
        let mut observed_outcome = "PASS".to_string();
        let mut summary = Vec::new();
        let mut evidence = ExpectedEvidence::default();

        for step in &scenario.steps {
            match step.rpc.as_str() {
                "create_claim_v2" => {
                    let metadata = &step.params["metadata"];
                    let signals = &step.params["signals"];
                    let request = pb::CreateClaimV2Request {
                        claim_name: step.params["claim_name"]
                            .as_str()
                            .unwrap_or_default()
                            .into(),
                        metadata: Some(pb::ClaimMetadataV2 {
                            lane: metadata["lane"].as_str().unwrap_or("fast").into(),
                            alpha_micros: metadata["alpha_micros"].as_u64().unwrap_or(50_000)
                                as u32,
                            epoch_config_ref: metadata["epoch_config_ref"]
                                .as_str()
                                .unwrap_or("epoch/default")
                                .into(),
                            output_schema_id: metadata["output_schema_id"]
                                .as_str()
                                .unwrap_or("legacy/v1")
                                .into(),
                        }),
                        signals: Some(pb::TopicSignalsV2 {
                            semantic_hash: hex32(
                                signals["semantic_hash_hex"].as_str().unwrap_or("01"),
                            ),
                            phys_hir_signature_hash: hex32(
                                signals["phys_hir_signature_hash_hex"]
                                    .as_str()
                                    .unwrap_or("02"),
                            ),
                            dependency_merkle_root: hex32(
                                signals["dependency_merkle_root_hex"]
                                    .as_str()
                                    .unwrap_or("03"),
                            ),
                        }),
                        holdout_ref: step.params["holdout_ref"].as_str().unwrap_or("h").into(),
                        epoch_size: step.params["epoch_size"].as_u64().unwrap_or(16),
                        oracle_num_symbols: step.params["oracle_num_symbols"].as_u64().unwrap_or(4)
                            as u32,
                        access_credit: step.params["access_credit"].as_u64().unwrap_or(256),

                        oracle_id: "builtin.accuracy".to_string(),
                        nullspec_id: String::new(),
                        dp_epsilon_budget: None,
                        dp_delta_budget: None,
                    };
                    match server.client.create_claim_v2(request).await {
                        Ok(resp) => {
                            claim_id = resp.into_inner().claim_id;
                            summary.push(json!({"rpc": "create_claim_v2", "status": "ok"}));
                        }
                        Err(status) => {
                            observed_outcome = "REJECT".to_string();
                            summary.push(json!({"rpc": "create_claim_v2", "status": status.code().to_string()}));
                            break;
                        }
                    }
                }
                "commit_artifacts" => {
                    let wasm = wat::parse_str(step.params["wasm_wat"].as_str().expect("wat"))
                        .expect("wasm");
                    let artifact_hash = Sha256::digest(&wasm).to_vec();
                    server
                        .client
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
                    summary.push(json!({"rpc": "commit_artifacts", "status": "ok"}));
                }
                "freeze_gates" => {
                    server
                        .client
                        .freeze_gates(pb::FreezeGatesRequest {
                            claim_id: claim_id.clone(),
                        })
                        .await
                        .expect("freeze");
                    summary.push(json!({"rpc": "freeze_gates", "status": "ok"}));
                }
                "seal_claim" => {
                    server
                        .client
                        .seal_claim(pb::SealClaimRequest {
                            claim_id: claim_id.clone(),
                        })
                        .await
                        .expect("seal");
                    summary.push(json!({"rpc": "seal_claim", "status": "ok"}));
                }
                "execute_claim_v2" => {
                    server
                        .client
                        .execute_claim_v2(pb::ExecuteClaimV2Request {
                            claim_id: claim_id.clone(),
                        })
                        .await
                        .expect("execute");
                    summary.push(json!({"rpc": "execute_claim_v2", "status": "ok"}));
                }
                "fetch_capsule" => {
                    let response = server
                        .client
                        .fetch_capsule(pb::FetchCapsuleRequest {
                            claim_id: claim_id.clone(),
                        })
                        .await
                        .expect("fetch")
                        .into_inner();
                    let inclusion = response.inclusion_proof.expect("inclusion proof");
                    let leaf: [u8; 32] = inclusion.leaf_hash.try_into().expect("leaf");
                    let root: [u8; 32] = response.root_hash.clone().try_into().expect("root");
                    let path: Vec<[u8; 32]> = inclusion
                        .audit_path
                        .iter()
                        .map(|part| part.as_slice().try_into().expect("part"))
                        .collect();
                    evidence.verify_inclusion_proof = verify_inclusion_proof(
                        &path,
                        &leaf,
                        inclusion.leaf_index as usize,
                        inclusion.tree_size as usize,
                        &root,
                    );

                    let consistency = response.consistency_proof.expect("consistency proof");
                    let proof = server
                        .client
                        .get_consistency_proof(pb::GetConsistencyProofRequest {
                            first_tree_size: consistency.old_tree_size,
                            second_tree_size: consistency.new_tree_size,
                        })
                        .await
                        .expect("consistency roots")
                        .into_inner();
                    let consistency_path: Vec<[u8; 32]> = consistency
                        .path
                        .iter()
                        .map(|part| part.as_slice().try_into().expect("cp part"))
                        .collect();
                    evidence.verify_consistency_proof = verify_consistency_proof(
                        &proof.first_root_hash.try_into().expect("old"),
                        &proof.second_root_hash.try_into().expect("new"),
                        consistency.old_tree_size as usize,
                        consistency.new_tree_size as usize,
                        &consistency_path,
                    );

                    let sth = response.signed_tree_head.expect("sth");
                    evidence.verify_sth_signature = verify_sth_signature(&sth, &public_key).is_ok();
                    summary.push(json!({"rpc": "fetch_capsule", "status": "ok"}));
                }
                _ => panic!("unsupported step {}", step.rpc),
            }
        }

        assert_eq!(
            observed_outcome, scenario.expected_outcome,
            "scenario {} expected outcome mismatch",
            scenario.scenario_id
        );
        assert_eq!(
            evidence.verify_inclusion_proof, scenario.expected_evidence.verify_inclusion_proof,
            "scenario {} inclusion verification mismatch",
            scenario.scenario_id
        );
        assert_eq!(
            evidence.verify_consistency_proof, scenario.expected_evidence.verify_consistency_proof,
            "scenario {} consistency verification mismatch",
            scenario.scenario_id
        );
        assert_eq!(
            evidence.verify_sth_signature, scenario.expected_evidence.verify_sth_signature,
            "scenario {} sth verification mismatch",
            scenario.scenario_id
        );

        let artifact = ScenarioArtifact {
            scenario_id: scenario.scenario_id,
            category: scenario.category,
            expected_outcome: scenario.expected_outcome,
            observed_outcome,
            deterministic_seed: scenario.deterministic_seed,
            request_response_summary: summary,
            evidence,
        };

        fs::write(
            out_dir.join(format!("{}.json", artifact.scenario_id)),
            serde_json::to_string_pretty(&artifact).expect("artifact json"),
        )
        .expect("write scenario artifact");
        artifacts.push(artifact);
    }

    let mut summary = BTreeMap::new();
    summary.insert("scenario_count", json!(artifacts.len()));
    summary.insert(
        "scenarios",
        serde_json::to_value(&artifacts).expect("summary scenarios"),
    );
    fs::write(
        out_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("summary json"),
    )
    .expect("write summary");
}
