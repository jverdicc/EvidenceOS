use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};

#[test]
fn etl_public_api_matrix() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("etl-matrix.log");
    let mut etl = Etl::open_or_create(&path).expect("etl");

    let (i0, l0) = etl.append(b"a").expect("append");
    let (_i1, _l1) = etl.append(b"b").expect("append");
    let (i2, l2) = etl.append(b"c").expect("append");

    let root2 = etl.root_at_size(2).expect("root2");
    let root3 = etl.root_hash();
    let p0 = etl.inclusion_proof(i0).expect("proof0");
    let p2 = etl.inclusion_proof(i2).expect("proof2");
    assert!(verify_inclusion_proof(&p0, &l0, i0 as usize, 3, &root3));
    assert!(verify_inclusion_proof(&p2, &l2, i2 as usize, 3, &root3));

    let cp = etl.consistency_proof(2, 3).expect("consistency");
    assert!(verify_consistency_proof(&root2, &root3, 2, 3, &cp));

    etl.revoke("root", "test").expect("revoke");
    assert!(etl.is_revoked("root"));
    let _ = etl.taint_descendants("root");
}
