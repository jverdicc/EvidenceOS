// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};

/// Builds canonical EvidenceOS signing material.
///
/// Format:
/// - without timestamp: `{request_id}:{path}`
/// - with timestamp: `{request_id}:{path}:{timestamp}`
pub fn signing_material(request_id: &str, path: &str, timestamp: Option<&str>) -> String {
    match timestamp {
        Some(timestamp) => format!("{request_id}:{path}:{timestamp}"),
        None => format!("{request_id}:{path}"),
    }
}

/// Computes the HMAC-SHA256 digest as lowercase hex.
pub fn sign_hex(secret: &[u8], material: &str) -> String {
    hex::encode(hmac_sha256(secret, material.as_bytes()))
}

/// Computes the signature header value as `sha256=<hex>`.
pub fn signature_header(secret: &[u8], material: &str) -> String {
    format!("sha256={}", sign_hex(secret, material))
}

/// Verifies a `sha256=<hex>` signature header against canonical signing material.
pub fn verify_signature(
    secret: &[u8],
    request_id: &str,
    path: &str,
    timestamp: Option<&str>,
    provided_header: &str,
) -> bool {
    let Some(provided_hex) = provided_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(provided) = hex::decode(provided_hex) else {
        return false;
    };
    let material = signing_material(request_id, path, timestamp);
    let expected = hmac_sha256(secret, material.as_bytes());
    constant_time_eq(expected.as_slice(), provided.as_slice())
}

fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let digest = Sha256::digest(secret);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut o_key_pad = [0u8; BLOCK_SIZE];
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    let mut inner = Sha256::new();
    inner.update(i_key_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_key_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{signature_header, signing_material, verify_signature};

    #[test]
    fn signing_material_without_timestamp() {
        assert_eq!(
            signing_material("req-123", "/evidenceos.v1.EvidenceOS/Health", None),
            "req-123:/evidenceos.v1.EvidenceOS/Health"
        );
    }

    #[test]
    fn signing_material_with_timestamp() {
        assert_eq!(
            signing_material(
                "req-123",
                "/evidenceos.v1.EvidenceOS/Health",
                Some("1735689600")
            ),
            "req-123:/evidenceos.v1.EvidenceOS/Health:1735689600"
        );
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let secret = b"hmac-secret";
        let material = signing_material("req-1", "/evidenceos.v1.EvidenceOS/Health", Some("10"));
        let header = signature_header(secret, &material);
        assert!(verify_signature(
            secret,
            "req-1",
            "/evidenceos.v1.EvidenceOS/Health",
            Some("10"),
            &header
        ));
    }

    #[test]
    fn verify_signature_rejects_wrong_path() {
        let secret = b"hmac-secret";
        let material = signing_material("req-1", "/evidenceos.v1.EvidenceOS/Health", None);
        let header = signature_header(secret, &material);
        assert!(!verify_signature(
            secret,
            "req-1",
            "/evidenceos.v1.EvidenceOS/CreateClaimV2",
            None,
            &header
        ));
    }
}
