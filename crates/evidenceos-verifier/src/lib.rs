// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evidenceos_protocol::pb;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub type Hash32 = [u8; 32];

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

fn sha256(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn leaf_hash(data: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0u8);
    buf.extend_from_slice(data);
    sha256(&buf)
}

pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = [0u8; 65];
    buf[0] = 1;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256(&buf)
}

pub fn verify_inclusion_proof_ct(
    leaf_hash: &Hash32,
    leaf_index: usize,
    tree_size: usize,
    audit_path: &[Hash32],
    root: &Hash32,
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    let mut fn_idx = leaf_index;
    let mut sn_idx = tree_size - 1;
    let mut path_pos = 0usize;
    let mut hash = *leaf_hash;

    while sn_idx > 0 {
        if fn_idx % 2 == 1 {
            let Some(sibling) = audit_path.get(path_pos) else {
                return false;
            };
            hash = node_hash(sibling, &hash);
            path_pos += 1;
        } else if fn_idx < sn_idx {
            let Some(sibling) = audit_path.get(path_pos) else {
                return false;
            };
            hash = node_hash(&hash, sibling);
            path_pos += 1;
        }

        fn_idx /= 2;
        sn_idx /= 2;
    }

    path_pos == audit_path.len() && &hash == root
}

pub fn verify_inclusion_proof(
    proof: &[Hash32],
    leaf: &Hash32,
    leaf_index: usize,
    tree_size: usize,
    root: &Hash32,
) -> bool {
    verify_inclusion_proof_ct(leaf, leaf_index, tree_size, proof, root)
}

pub fn verify_consistency_proof_ct(
    old_root: &Hash32,
    new_root: &Hash32,
    old_size: usize,
    new_size: usize,
    path: &[Hash32],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == 0 {
        return path.is_empty() && *old_root == sha256(b"");
    }
    if old_size == new_size {
        return path.is_empty() && old_root == new_root;
    }

    let mut fn_idx = old_size - 1;
    let mut sn_idx = new_size - 1;
    while fn_idx & 1 == 1 {
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    let mut it = path.iter();
    let mut fr;
    let mut sr;
    if fn_idx == 0 {
        fr = *old_root;
        sr = *old_root;
    } else {
        let Some(first) = it.next() else {
            return false;
        };
        fr = *first;
        sr = *first;
    }

    while fn_idx > 0 {
        let Some(p) = it.next() else {
            return false;
        };
        if fn_idx & 1 == 1 {
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
        } else if fn_idx < sn_idx {
            sr = node_hash(&sr, p);
        }
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    while sn_idx > 0 {
        let Some(p) = it.next() else {
            return false;
        };
        sr = node_hash(&sr, p);
        sn_idx >>= 1;
    }

    it.next().is_none() && &fr == old_root && &sr == new_root
}

pub fn verify_consistency_proof(
    old_root: &Hash32,
    new_root: &Hash32,
    old_size: usize,
    new_size: usize,
    proof: &[Hash32],
) -> bool {
    verify_consistency_proof_ct(old_root, new_root, old_size, new_size, proof)
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

fn append_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn append_len_prefixed_str(out: &mut Vec<u8>, value: &str) {
    append_len_prefixed_bytes(out, value.as_bytes());
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

fn sort_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = Map::new();
            for (k, val) in entries {
                sorted.insert(k, sort_json(val));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json).collect()),
        other => other,
    }
}

pub fn canonical_json(v: &impl Serialize) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(v)?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted)
}

pub fn capsule_hash_hex(v: &impl Serialize) -> serde_json::Result<String> {
    Ok(hex::encode(sha256(&canonical_json(v)?)))
}
