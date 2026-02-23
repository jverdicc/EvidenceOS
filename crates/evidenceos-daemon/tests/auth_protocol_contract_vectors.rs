use evidenceos_auth_protocol::{signature_header, signing_material};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    secret_hex: String,
    request_id: String,
    path: String,
    timestamp: Option<String>,
    material: String,
    signature_header: String,
}

#[test]
fn daemon_contract_vectors_match_shared_protocol() {
    let raw =
        include_str!("../../evidenceos-auth-protocol/tests/vectors/auth_signing_vectors.json");
    let vectors: Vec<Vector> = serde_json::from_str(raw).expect("valid vector json");

    for vector in vectors {
        let secret = hex::decode(&vector.secret_hex).expect("secret hex");
        let timestamp = vector.timestamp.as_deref();
        let material = signing_material(&vector.request_id, &vector.path, timestamp);
        assert_eq!(
            material, vector.material,
            "material mismatch for {}",
            vector.name
        );
        let signature = signature_header(&secret, &material);
        assert_eq!(
            signature, vector.signature_header,
            "signature mismatch for {}",
            vector.name
        );
    }
}
