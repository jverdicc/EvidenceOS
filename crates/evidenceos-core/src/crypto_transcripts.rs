// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evidenceos_protocol::pb;
use sha2::{Digest, Sha256};

use crate::etl::leaf_hash;

const DOMAIN_STH_V1: &[u8] = b"evidenceos:sth:v1";
const DOMAIN_REVOCATIONS_V1: &[u8] = b"evidenceos:revocations:v1";

#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    #[error("signed tree head root hash must be 32 bytes")]
    InvalidSthRootHash,
    #[error("signed tree head key id must be 32 bytes")]
    InvalidSthKeyId,
    #[error("signed tree head signature must be 64 bytes")]
    InvalidSthSignature,
    #[error("response signing key must be 32 bytes")]
    InvalidVerifyingKey,
    #[error("revocation entry claim_id must be 32 bytes")]
    InvalidRevocationClaimId,
    #[error("missing signed tree head in revocations snapshot")]
    MissingSignedTreeHead,
    #[error("signature verification failed")]
    SignatureVerification,
}

fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    hasher.finalize().into()
}

fn append_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn append_len_prefixed_str(out: &mut Vec<u8>, value: &str) {
    append_len_prefixed_bytes(out, value.as_bytes());
}

pub fn etl_leaf_hash(capsule_bytes: &[u8]) -> [u8; 32] {
    leaf_hash(capsule_bytes)
}

pub fn sth_signature_digest(tree_size: u64, root_hash: [u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&tree_size.to_be_bytes());
    payload.extend_from_slice(&root_hash);
    sha256_domain(DOMAIN_STH_V1, &payload)
}

pub fn revocations_snapshot_digest(
    entries: &[pb::RevocationEntry],
    sth: &pb::SignedTreeHead,
) -> Result<[u8; 32], TranscriptError> {
    let root_hash: [u8; 32] = sth
        .root_hash
        .as_slice()
        .try_into()
        .map_err(|_| TranscriptError::InvalidSthRootHash)?;
    if sth.key_id.len() != 32 {
        return Err(TranscriptError::InvalidSthKeyId);
    }

    let mut payload = Vec::new();
    for entry in entries {
        if entry.claim_id.len() != 32 {
            return Err(TranscriptError::InvalidRevocationClaimId);
        }
        append_len_prefixed_bytes(&mut payload, &entry.claim_id);
        payload.extend_from_slice(&entry.timestamp_unix.to_be_bytes());
        append_len_prefixed_str(&mut payload, &entry.reason);
    }

    payload.extend_from_slice(&sth.tree_size.to_be_bytes());
    payload.extend_from_slice(&root_hash);
    append_len_prefixed_bytes(&mut payload, &sth.key_id);

    Ok(sha256_domain(DOMAIN_REVOCATIONS_V1, &payload))
}

pub fn verify_sth_signature(
    sth: &pb::SignedTreeHead,
    key_bytes: &[u8],
) -> Result<(), TranscriptError> {
    let root_hash: [u8; 32] = sth
        .root_hash
        .as_slice()
        .try_into()
        .map_err(|_| TranscriptError::InvalidSthRootHash)?;
    let signature =
        Signature::from_slice(&sth.signature).map_err(|_| TranscriptError::InvalidSthSignature)?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| TranscriptError::InvalidVerifyingKey)?;
    let key =
        VerifyingKey::from_bytes(&key_arr).map_err(|_| TranscriptError::InvalidVerifyingKey)?;
    let digest = sth_signature_digest(sth.tree_size, root_hash);
    key.verify(&digest, &signature)
        .map_err(|_| TranscriptError::SignatureVerification)
}

pub fn verify_revocations_snapshot(
    snapshot: &pb::WatchRevocationsResponse,
    key_bytes: &[u8],
) -> Result<(), TranscriptError> {
    let sth = snapshot
        .signed_tree_head
        .as_ref()
        .ok_or(TranscriptError::MissingSignedTreeHead)?;
    let digest = revocations_snapshot_digest(&snapshot.entries, sth)?;
    let signature = Signature::from_slice(&snapshot.signature)
        .map_err(|_| TranscriptError::InvalidSthSignature)?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| TranscriptError::InvalidVerifyingKey)?;
    let key =
        VerifyingKey::from_bytes(&key_arr).map_err(|_| TranscriptError::InvalidVerifyingKey)?;
    key.verify(&digest, &signature)
        .map_err(|_| TranscriptError::SignatureVerification)
}

#[cfg(test)]
mod tests {
    use super::{
        etl_leaf_hash, revocations_snapshot_digest, sth_signature_digest,
        verify_revocations_snapshot, verify_sth_signature,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use evidenceos_protocol::pb;

    #[test]
    fn etl_leaf_hash_matches_merkle_leaf_format() {
        let got = etl_leaf_hash(b"capsule");
        let expected = crate::etl::leaf_hash(b"capsule");
        assert_eq!(got, expected);
    }

    #[test]
    fn verifies_sth_and_revocations_snapshots() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let root = [9u8; 32];
        let sth_digest = sth_signature_digest(3, root);
        let sth_sig = signing_key.sign(&sth_digest).to_bytes().to_vec();
        let key_id = [1u8; 32].to_vec();

        let sth = pb::SignedTreeHead {
            tree_size: 3,
            root_hash: root.to_vec(),
            signature: sth_sig,
            key_id: key_id.clone(),
        };

        verify_sth_signature(&sth, &signing_key.verifying_key().to_bytes()).expect("valid sth");

        let snapshot = pb::WatchRevocationsResponse {
            entries: vec![pb::RevocationEntry {
                claim_id: vec![2u8; 32],
                timestamp_unix: 123,
                reason: "manual".to_string(),
            }],
            signature: {
                let digest = revocations_snapshot_digest(
                    &[pb::RevocationEntry {
                        claim_id: vec![2u8; 32],
                        timestamp_unix: 123,
                        reason: "manual".to_string(),
                    }],
                    &sth,
                )
                .expect("digest");
                signing_key.sign(&digest).to_bytes().to_vec()
            },
            signed_tree_head: Some(sth),
            key_id,
        };

        verify_revocations_snapshot(&snapshot, &signing_key.verifying_key().to_bytes())
            .expect("valid snapshot");
    }
}
