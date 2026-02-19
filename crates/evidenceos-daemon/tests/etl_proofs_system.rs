use evidenceos_core::etl::{leaf_hash, verify_inclusion_proof_ct};

#[test]
fn etl_proofs_system() {
    let data = br#"{\"k\":1}"#;
    let leaf = leaf_hash(data);
    assert!(verify_inclusion_proof_ct(&leaf, 0, 1, &[], &leaf));
}
