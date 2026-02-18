use sha2::{Digest, Sha256};

#[test]
fn canonical_proto_checksum_matches_snapshot() {
    let proto = include_bytes!("../proto/evidenceos.proto");
    let digest = Sha256::digest(proto);
    let actual = hex::encode(digest);
    let expected = "8fbeb3c2ec3470f974c0ca4f413ef3aea32e27c00fc6a641d1df769907ef348f";
    assert_eq!(
        actual, expected,
        "canonical proto changed; update snapshot intentionally"
    );
}
