use evidenceos_auth_protocol::{signature_header, signing_material, verify_signature};
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
fn golden_vectors_match_contract() {
    let raw = include_str!("vectors/auth_signing_vectors.json");
    let vectors: Vec<Vector> = serde_json::from_str(raw).expect("valid test vectors json");

    for vector in vectors {
        let secret = hex::decode(&vector.secret_hex).expect("secret hex");
        let timestamp = vector.timestamp.as_deref();

        let computed_material = signing_material(&vector.request_id, &vector.path, timestamp);
        assert_eq!(
            computed_material, vector.material,
            "material mismatch for {}",
            vector.name
        );

        let computed_header = signature_header(&secret, &computed_material);
        assert_eq!(
            computed_header, vector.signature_header,
            "signature mismatch for {}",
            vector.name
        );

        assert!(verify_signature(
            &secret,
            &vector.request_id,
            &vector.path,
            timestamp,
            &vector.signature_header
        ));
    }
}
