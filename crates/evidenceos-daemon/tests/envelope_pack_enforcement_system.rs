use ed25519_dalek::SigningKey;
use evidenceos_core::magnitude_envelope::{
    EnvelopePack, EnvelopePackMetadata, MagnitudeEnvelope, QuantityEnvelopeBound,
    MAGNITUDE_ENVELOPE_PACK_SCHEMA_V1,
};
use evidenceos_core::physhir::Dimension;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::time::sleep;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn with_request_id<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "x-request-id",
        MetadataValue::try_from(format!(
            "req-{}",
            REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("request id metadata"),
    );
    req
}

fn wat_string_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for b in bytes {
        out.push_str(&format!("\\{:02x}", b));
    }
    out
}

fn wasm_with_payload(payload: &[u8]) -> Vec<u8> {
    let escaped = wat_string_bytes(payload);
    wat::parse_str(format!(
        r#"(module
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{escaped}")
          (func (export "run")
            i32.const 0 i32.const {len} call $emit drop)
        )"#,
        len = payload.len()
    ))
    .expect("wat")
}

async fn create_and_seal(
    client: &mut EvidenceOsClient<Channel>,
    schema_id: &str,
    wasm: Vec<u8>,
) -> Vec<u8> {
    let claim_id = client
        .create_claim_v2(with_request_id(pb::CreateClaimV2Request {
            claim_name: "signed-pack-enforcement".into(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".into(),
                alpha_micros: 50_000,
                epoch_config_ref: "epoch".into(),
                output_schema_id: schema_id.into(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: vec![1; 32],
                phys_hir_signature_hash: vec![2; 32],
                dependency_merkle_root: Sha256::digest([]).to_vec(),
            }),
            holdout_ref: "synthetic-h".into(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            access_credit: 1_000_000,
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        }))
        .await
        .expect("create")
        .into_inner()
        .claim_id;

    client
        .commit_artifacts(with_request_id(pb::CommitArtifactsRequest {
            claim_id: claim_id.clone(),
            artifacts: vec![pb::Artifact {
                kind: "wasm".into(),
                artifact_hash: {
                    let mut h = Sha256::new();
                    h.update(&wasm);
                    h.finalize().to_vec()
                },
            }],
            wasm_module: wasm,
        }))
        .await
        .expect("commit");
    client
        .freeze_gates(with_request_id(pb::FreezeGatesRequest {
            claim_id: claim_id.clone(),
        }))
        .await
        .expect("freeze");
    client
        .seal_claim(with_request_id(pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        }))
        .await
        .expect("seal");
    claim_id
}

fn spawn_daemon(
    data_dir: &str,
    listen: &str,
    envelope_packs_dir: &str,
    trusted_keys_path: &str,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_evidenceos-daemon"))
        .args([
            "--listen",
            listen,
            "--data-dir",
            data_dir,
            "--envelope-packs-dir",
            envelope_packs_dir,
            "--trusted-envelope-issuer-keys",
            trusted_keys_path,
            "--require-signed-envelopes",
            "true",
            "--default-holdout-k-bits-budget",
            "1000000000",
            "--default-holdout-access-credit-budget",
            "1000000000",
        ])
        .env("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon")
}

fn write_epoch_config_fixture(dir: &TempDir, epoch_ref: &str) {
    let epoch_dir = dir.path().join("data").join("epoch_configs");
    fs::create_dir_all(&epoch_dir).expect("epoch dir");
    let payload = serde_json::json!({
        "epoch_size": 10,
        "pln": {
            "target_fuel": 100,
            "max_fuel": 500,
            "lanes": {
                "fast": true,
                "heavy": true
            }
        }
    });
    fs::write(
        epoch_dir.join(format!("{epoch_ref}.json")),
        serde_json::to_vec(&payload).expect("epoch json"),
    )
    .expect("write epoch config");
}

async fn connect_with_retry(listen: &str) -> EvidenceOsClient<Channel> {
    for _ in 0..100 {
        if let Ok(client) = EvidenceOsClient::connect(format!("http://{listen}")).await {
            return client;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("daemon did not become ready in time");
}

fn write_signed_pack_fixture(dir: &TempDir) {
    let packs_dir = dir.path().join("packs");
    fs::create_dir_all(&packs_dir).expect("packs dir");

    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let trusted_keys = serde_json::json!({
        "keys": {
            "issuer-a": verifying_key_hex,
        }
    });
    fs::write(
        dir.path().join("trusted-envelope-keys.json"),
        serde_json::to_vec_pretty(&trusted_keys).expect("trusted keys json"),
    )
    .expect("write trusted keys");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix")
        .as_secs();

    let mut pack = EnvelopePack {
        schema: MAGNITUDE_ENVELOPE_PACK_SCHEMA_V1.to_string(),
        metadata: EnvelopePackMetadata {
            pack_id: String::new(),
            version: 1,
            valid_from_unix: now.saturating_sub(60),
            valid_to_unix: now.saturating_add(3_600),
            issuer: "issuer-a".to_string(),
            signature_ed25519_b64: String::new(),
        },
        envelopes: vec![MagnitudeEnvelope {
            envelope_id: "cbrn.strict.v1".to_string(),
            profile_id: "cbrn.v1".to_string(),
            schema_id: "EVIDENCEOS_CBRN_SC_V1".to_string(),
            quantity_bounds: vec![QuantityEnvelopeBound {
                field: "quantities".to_string(),
                expected_dimension: Dimension::new(-3, 0, 0, 0, 0, 1, 0),
                min_value: -1,
                max_value: 10,
            }],
        }],
    };
    pack.sign_with_key(&signing_key).expect("sign pack");

    fs::write(
        packs_dir.join("strict-pack.json"),
        serde_json::to_vec_pretty(&pack).expect("pack json"),
    )
    .expect("write pack");
}

#[tokio::test]
async fn daemon_enforces_active_signed_envelope_pack_for_structured_claims() {
    let temp = TempDir::new().expect("tmp");
    write_signed_pack_fixture(&temp);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let listen = listener.local_addr().expect("addr").to_string();
    drop(listener);

    let data_dir = temp.path().join("data");
    fs::create_dir_all(&data_dir).expect("data dir");
    write_epoch_config_fixture(&temp, "epoch");
    let envelope_packs_dir = temp.path().join("packs");
    let trusted_keys_path = temp.path().join("trusted-envelope-keys.json");

    let mut child = spawn_daemon(
        data_dir.to_str().expect("utf8"),
        &listen,
        envelope_packs_dir.to_str().expect("utf8"),
        trusted_keys_path.to_str().expect("utf8"),
    );

    let test_result = async {
        let mut client = connect_with_retry(&listen).await;
        let payload = b"{\"version\":1,\"profile\":\"CBRN_SC_V1\",\"domain\":\"CHEMICAL\",\"claim_kind\":\"MEASUREMENT\",\"claim_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_id\":\"ABCDEFGH234567AB\",\"event_time_unix\":1,\"quantities\":[{\"kind\":\"CONCENTRATION\",\"value\":{\"value\":\"123\",\"scale\":0},\"unit\":\"ppm\"}],\"unit_system\":\"PHYSHIR_UCUM_SUBSET\",\"envelope_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"envelope_check\":\"PASS\",\"references\":[]}";
        let claim_id = create_and_seal(&mut client, "cbrn-sc.v1", wasm_with_payload(payload)).await;
        let err = client
            .execute_claim_v2(with_request_id(pb::ExecuteClaimV2Request { claim_id }))
            .await
            .expect_err("execute should fail closed when envelope policy is violated");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("operation blocked by policy"));
    }
    .await;

    let _ = child.kill();
    let _ = child.wait();

    test_result
}
