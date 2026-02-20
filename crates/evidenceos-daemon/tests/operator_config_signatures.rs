use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::capsule::canonical_json;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::{
    sha256_domain, DOMAIN_EPOCH_CONTROL_V1, DOMAIN_ORACLE_OPERATOR_RECORD_V1,
};
use serde::Serialize;
use serde_json::json;
use tempfile::TempDir;

#[derive(Serialize)]
struct OracleOperatorRecordPayload<'a> {
    oracle_id: &'a str,
    schema_version: u32,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: &'a str,
    calibration_epoch: Option<u64>,
    disjointness_attestation: &'a str,
    nonoverlap_proof_uri: Option<&'a str>,
    updated_at_epoch: u64,
    key_id: &'a str,
}

#[derive(Serialize)]
struct EpochControlPayload<'a> {
    forced_epoch: u64,
    updated_at_epoch: u64,
    key_id: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn sign_oracle_record(
    sk: &SigningKey,
    oracle_id: &str,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: &str,
    calibration_epoch: Option<u64>,
    disjointness_attestation: &str,
    nonoverlap_proof_uri: Option<&str>,
    updated_at_epoch: u64,
    key_id: &str,
) -> String {
    let payload = OracleOperatorRecordPayload {
        oracle_id,
        schema_version: 1,
        ttl_epochs,
        calibration_manifest_hash_hex,
        calibration_epoch,
        disjointness_attestation,
        nonoverlap_proof_uri,
        updated_at_epoch,
        key_id,
    };
    let canonical = canonical_json(&payload).expect("canonical");
    let digest = sha256_domain(DOMAIN_ORACLE_OPERATOR_RECORD_V1, &canonical);
    hex::encode(sk.sign(&digest).to_bytes())
}

fn sign_epoch_control(
    sk: &SigningKey,
    forced_epoch: u64,
    updated_at_epoch: u64,
    key_id: &str,
) -> String {
    let payload = EpochControlPayload {
        forced_epoch,
        updated_at_epoch,
        key_id,
    };
    let canonical = canonical_json(&payload).expect("canonical");
    let digest = sha256_domain(DOMAIN_EPOCH_CONTROL_V1, &canonical);
    hex::encode(sk.sign(&digest).to_bytes())
}

fn setup_trusted_key(dir: &TempDir, key_id: &str, sk: &SigningKey) {
    let vk_hex = hex::encode(sk.verifying_key().to_bytes());
    std::fs::write(
        dir.path().join("trusted_oracle_keys.json"),
        serde_json::to_vec(&json!({"keys": {key_id: vk_hex}})).expect("trusted json"),
    )
    .expect("write trusted keys");
}

#[test]
fn valid_signature_passes() {
    let dir = TempDir::new().expect("tmp");
    let key_id = "ops-k1";
    let oracle_id = "oracle-a";
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    setup_trusted_key(&dir, key_id, &sk);

    let updated_at_epoch = 42;
    let signature = sign_oracle_record(
        &sk,
        oracle_id,
        12,
        &"ab".repeat(32),
        Some(10),
        "attested-disjoint",
        None,
        updated_at_epoch,
        key_id,
    );
    std::fs::write(
        dir.path().join("oracle_operator_config.json"),
        serde_json::to_vec(&json!({
            "oracles": {
                oracle_id: {
                    "schema_version": 1,
                    "ttl_epochs": 12,
                    "calibration_manifest_hash_hex": "abababababababababababababababababababababababababababababababab",
                    "calibration_epoch": 10,
                    "disjointness_attestation": "attested-disjoint",
                    "nonoverlap_proof_uri": null,
                    "updated_at_epoch": updated_at_epoch,
                    "key_id": key_id,
                    "signature_ed25519": signature,
                }
            }
        }))
        .expect("oracle json"),
    )
    .expect("write oracle");

    let force_sig = sign_epoch_control(&sk, 99, updated_at_epoch, key_id);
    std::fs::write(
        dir.path().join("epoch_control.json"),
        serde_json::to_vec(&json!({
            "forced_epoch": 99,
            "updated_at_epoch": updated_at_epoch,
            "key_id": key_id,
            "signature_ed25519": force_sig,
        }))
        .expect("epoch json"),
    )
    .expect("write epoch");

    let service = EvidenceOsService::build(dir.path().to_str().expect("utf8"));
    assert!(service.is_ok());
}

#[test]
fn mutation_fails_verification() {
    let dir = TempDir::new().expect("tmp");
    let key_id = "ops-k1";
    let oracle_id = "oracle-a";
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    setup_trusted_key(&dir, key_id, &sk);

    let signature = sign_oracle_record(
        &sk,
        oracle_id,
        4,
        &"11".repeat(32),
        None,
        "attested-disjoint",
        None,
        88,
        key_id,
    );
    std::fs::write(
        dir.path().join("oracle_operator_config.json"),
        serde_json::to_vec(&json!({
            "oracles": {
                oracle_id: {
                    "schema_version": 1,
                    "ttl_epochs": 5,
                    "calibration_manifest_hash_hex": "1111111111111111111111111111111111111111111111111111111111111111",
                    "disjointness_attestation": "attested-disjoint",
                    "updated_at_epoch": 88,
                    "key_id": key_id,
                    "signature_ed25519": signature,
                }
            }
        }))
        .expect("oracle json"),
    )
    .expect("write oracle");

    let service = EvidenceOsService::build(dir.path().to_str().expect("utf8"));
    assert!(service.is_err());
}

#[test]
fn unknown_key_id_fails_verification() {
    let dir = TempDir::new().expect("tmp");
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    setup_trusted_key(&dir, "ops-k1", &sk);

    let signature = sign_oracle_record(
        &sk,
        "oracle-a",
        7,
        &"22".repeat(32),
        None,
        "attested-disjoint",
        None,
        1,
        "ops-k2",
    );
    std::fs::write(
        dir.path().join("oracle_operator_config.json"),
        serde_json::to_vec(&json!({
            "oracles": {
                "oracle-a": {
                    "schema_version": 1,
                    "ttl_epochs": 7,
                    "calibration_manifest_hash_hex": "2222222222222222222222222222222222222222222222222222222222222222",
                    "disjointness_attestation": "attested-disjoint",
                    "updated_at_epoch": 1,
                    "key_id": "ops-k2",
                    "signature_ed25519": signature,
                }
            }
        }))
        .expect("oracle json"),
    )
    .expect("write oracle");

    let service = EvidenceOsService::build(dir.path().to_str().expect("utf8"));
    assert!(service.is_err());
}

#[test]
fn missing_epoch_signature_fails_when_forced_epoch_is_set() {
    let dir = TempDir::new().expect("tmp");
    let sk = SigningKey::from_bytes(&[12u8; 32]);
    setup_trusted_key(&dir, "ops-k1", &sk);
    std::fs::write(
        dir.path().join("epoch_control.json"),
        serde_json::to_vec(&json!({
            "forced_epoch": 5,
            "updated_at_epoch": 10,
            "key_id": "ops-k1"
        }))
        .expect("epoch json"),
    )
    .expect("write epoch");

    let service = EvidenceOsService::build(dir.path().to_str().expect("utf8"));
    assert!(service.is_err());
}
