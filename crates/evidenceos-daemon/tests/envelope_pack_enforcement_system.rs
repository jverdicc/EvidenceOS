use ed25519_dalek::SigningKey;
use evidenceos_core::magnitude_envelope::{
    EnvelopePack, EnvelopePackMetadata, MagnitudeEnvelope, QuantityEnvelopeBound,
    MAGNITUDE_ENVELOPE_PACK_SCHEMA_V1,
};
use evidenceos_core::physhir::Dimension;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::Decision;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::time::sleep;
use tonic::transport::Channel;

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
        .create_claim_v2(pb::CreateClaimV2Request {
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
                dependency_merkle_root: vec![3; 32],
            }),
            holdout_ref: "h".into(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            access_credit: 4096,
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;

    client
        .commit_artifacts(pb::CommitArtifactsRequest {
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
        ])
        .env("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon")
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
        let resp = client
            .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
            .await
            .expect("execute")
            .into_inner();

        assert_eq!(resp.decision, Decision::Defer as i32);
        assert!(resp.reason_codes.contains(&9205));
    }
    .await;

    let _ = child.kill();
    let _ = child.wait();

    test_result
}
