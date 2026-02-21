use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::nullspec::NullSpecKind;
use evidenceos_core::nullspec::{
    EProcessKind, SignedNullSpecContractV1, TrustedAuthorities, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_registry::{NullSpecAuthorityKeyring, NullSpecRegistry};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn build_contract() -> SignedNullSpecContractV1 {
    SignedNullSpecContractV1 {
        schema: NULLSPEC_SCHEMA_V1.to_string(),
        nullspec_id: [0; 32],
        oracle_id: "accuracy.binary.v1".to_string(),
        oracle_resolution_hash: [1; 32],
        holdout_handle: "holdout-a".to_string(),
        epoch_created: 1,
        ttl_epochs: 10,
        kind: NullSpecKind::DiscreteBuckets { p0: vec![0.5, 0.5] },
        eprocess: EProcessKind::DirichletMultinomialMixture {
            alpha: vec![1.0, 1.0],
        },
        calibration_manifest_hash: None,
        created_by: "op1".to_string(),
        signature_ed25519: Vec::new(),
    }
}

#[test]
fn contract_id_is_sha256_of_signing_payload() {
    let c = build_contract();
    let mut h = Sha256::new();
    h.update(c.signing_payload_bytes().expect("payload"));
    let digest = h.finalize();
    let mut expected = [0_u8; 32];
    expected.copy_from_slice(&digest);
    assert_eq!(c.compute_id().expect("id"), expected);
}

#[test]
fn signature_verification_required() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let mut c = build_contract();
    let payload = c.signing_payload_bytes().expect("payload");
    c.signature_ed25519 = sk.sign(&payload).to_bytes().to_vec();
    c.nullspec_id = c.compute_id().expect("id");

    let ta = TrustedAuthorities::default();
    assert!(c.verify_signature(&ta).is_err());
}

#[test]
fn registry_load_accepts_signed_contract() {
    let dir = tempdir().expect("tmp");
    let registry_dir = dir.path().join("registry");
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(registry_dir.join("nullspecs/accuracy.binary.v1")).expect("mkdir");
    std::fs::create_dir_all(&key_dir).expect("mkdir keys");

    let sk = SigningKey::from_bytes(&[9u8; 32]);
    std::fs::write(
        key_dir.join("op1.pub"),
        hex::encode(sk.verifying_key().to_bytes()),
    )
    .expect("write key");

    let mut c = build_contract();
    let payload = c.signing_payload_bytes().expect("payload");
    c.signature_ed25519 = sk.sign(&payload).to_bytes().to_vec();
    c.nullspec_id = c.compute_id().expect("id");

    let canonical = c.canonical_bytes().expect("canonical");
    let sig = sk.sign(&canonical);

    let id = hex::encode(c.nullspec_id);
    let contract_path = registry_dir
        .join("nullspecs")
        .join(&c.oracle_id)
        .join(format!("{id}.json"));
    let sig_path = contract_path.with_extension("sig");
    std::fs::write(&contract_path, serde_json::to_vec_pretty(&c).expect("json")).expect("write");
    std::fs::write(sig_path, hex::encode(sig.to_bytes())).expect("write sig");

    let keyring = NullSpecAuthorityKeyring::load_from_dir(&key_dir).expect("keyring");
    let registry =
        NullSpecRegistry::load_from_dir(&registry_dir, &keyring, false).expect("registry");
    assert!(registry.get(&id).is_some());
}
