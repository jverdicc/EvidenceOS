use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::nullspec_contract::{EValueSpecV1, NullSpecContractV1};
use evidenceos_core::nullspec_registry::{NullSpecAuthorityKeyring, NullSpecRegistry};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn contract_id_is_sha256_of_canonical_json() {
    let mut c = NullSpecContractV1 {
        id: String::new(),
        domain: "accuracy.binary.v1".to_string(),
        null_accuracy: 0.5,
        e_value: EValueSpecV1::LikelihoodRatio { n_observations: 10 },
        created_at_unix: 1,
        version: 1,
    };
    c.id = c.compute_id().expect("compute id");
    let mut unsigned = c.clone();
    unsigned.id.clear();
    let canonical = unsigned.canonical_json_bytes().expect("canonical");
    let expected = hex::encode(Sha256::digest(canonical));
    assert_eq!(c.id, expected);
}

#[test]
fn rejects_null_accuracy_out_of_range() {
    let mut c = NullSpecContractV1 {
        id: String::new(),
        domain: "accuracy.binary.v1".to_string(),
        null_accuracy: 0.0,
        e_value: EValueSpecV1::LikelihoodRatio { n_observations: 10 },
        created_at_unix: 1,
        version: 1,
    };
    c.id = c.compute_id().expect("compute id");
    assert!(c.validate(false).is_err());
}

#[test]
fn signature_verification_required() {
    let dir = tempdir().expect("tmp");
    let registry_dir = dir.path().join("registry");
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(registry_dir.join("nullspecs/accuracy.binary.v1")).expect("mkdir");
    std::fs::create_dir_all(&key_dir).expect("mkdir keys");

    let sk = SigningKey::from_bytes(&[7u8; 32]);
    std::fs::write(
        key_dir.join("op1.pub"),
        hex::encode(sk.verifying_key().to_bytes()),
    )
    .expect("write key");

    let mut c = NullSpecContractV1 {
        id: String::new(),
        domain: "accuracy.binary.v1".to_string(),
        null_accuracy: 0.5,
        e_value: EValueSpecV1::LikelihoodRatio { n_observations: 10 },
        created_at_unix: 1,
        version: 1,
    };
    c.id = c.compute_id().expect("id");
    let contract_path = registry_dir
        .join("nullspecs")
        .join(&c.domain)
        .join(format!("{}.json", c.id));
    let sig_path = contract_path.with_extension("sig");
    std::fs::write(&contract_path, serde_json::to_vec_pretty(&c).expect("json")).expect("write");
    std::fs::write(sig_path, "deadbeef").expect("write sig");

    let keyring = NullSpecAuthorityKeyring::load_from_dir(&key_dir).expect("keyring");
    assert!(NullSpecRegistry::load_from_dir(&registry_dir, &keyring, false).is_err());
}

#[test]
fn registry_load_and_mixture_evalue_integration() {
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

    let mut c = NullSpecContractV1 {
        id: String::new(),
        domain: "accuracy.binary.v1".to_string(),
        null_accuracy: 0.5,
        e_value: EValueSpecV1::LikelihoodRatio { n_observations: 10 },
        created_at_unix: 1,
        version: 1,
    };
    c.id = c.compute_id().expect("id");
    let canonical = c.canonical_json_bytes().expect("canonical");
    let sig = sk.sign(&canonical);

    let contract_path = registry_dir
        .join("nullspecs")
        .join(&c.domain)
        .join(format!("{}.json", c.id));
    let sig_path = contract_path.with_extension("sig");
    std::fs::write(&contract_path, serde_json::to_vec_pretty(&c).expect("json")).expect("write");
    std::fs::write(sig_path, hex::encode(sig.to_bytes())).expect("write sig");

    let keyring = NullSpecAuthorityKeyring::load_from_dir(&key_dir).expect("keyring");
    let registry =
        NullSpecRegistry::load_from_dir(&registry_dir, &keyring, false).expect("registry");
    let loaded = registry.get(&c.id).expect("contract");

    let e_half = loaded.compute_e_value_with_n(0.5, 10).expect("e half");
    let e_high = loaded.compute_e_value_with_n(0.9, 10).expect("e high");
    assert!((e_half - 1.0).abs() < 1e-9);
    assert!(e_high > 1.0);
}
