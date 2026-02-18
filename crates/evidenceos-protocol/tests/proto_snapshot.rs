use sha2::{Digest, Sha256};

#[test]
fn canonical_proto_checksum_matches_snapshot() {
    let proto = include_bytes!("../proto/evidenceos.proto");
    let digest = Sha256::digest(proto);
    let actual = hex::encode(digest);
    let expected = "62db9c9d68a016ec510d71e00d32d1a527fd864b20a9b27d5a0e7f63391f4506";
    assert_eq!(
        actual, expected,
        "canonical proto changed; update snapshot intentionally"
    );
}
