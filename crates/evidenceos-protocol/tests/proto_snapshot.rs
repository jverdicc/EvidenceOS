use sha2::{Digest, Sha256};

#[test]
fn canonical_proto_checksum_matches_snapshot() {
    let proto = include_bytes!("../proto/evidenceos.proto");
    let digest = Sha256::digest(proto);
    let actual = hex::encode(digest);
    let expected = "835b47e2635bed3b91d735ba2606789fef40e4fedbe17c077f601bc8f9e02087";
    assert_eq!(
        actual, expected,
        "canonical proto changed; update snapshot intentionally"
    );
}
