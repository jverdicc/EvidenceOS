use crate::error::{EvidenceOSError, EvidenceOSResult};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const NULLSPEC_SCHEMA_V1: &str = "evidenceos.nullspec.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NullSpecKind {
    DiscreteBuckets { p0: Vec<f64> },
    ParametricBernoulli { p: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EProcessKind {
    LikelihoodRatioFixedAlt { alt: Vec<f64> },
    DirichletMultinomialMixture { alpha: Vec<f64> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedNullSpecContractV1 {
    pub schema: String,
    pub nullspec_id: [u8; 32],
    pub oracle_id: String,
    pub oracle_resolution_hash: [u8; 32],
    pub holdout_handle: String,
    pub epoch_created: u64,
    pub ttl_epochs: u64,
    pub kind: NullSpecKind,
    pub eprocess: EProcessKind,
    pub calibration_manifest_hash: Option<[u8; 32]>,
    pub created_by: String,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedAuthorities {
    pub keys: HashMap<String, VerifyingKey>,
}

impl TrustedAuthorities {
    pub fn insert(&mut self, key_id: String, key: VerifyingKey) {
        self.keys.insert(key_id, key);
    }

    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }
}

impl SignedNullSpecContractV1 {
    pub fn canonical_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        let value = serde_json::to_value(self).map_err(|_| EvidenceOSError::Internal)?;
        let sorted = sort_json(value);
        serde_json::to_vec(&sorted).map_err(|_| EvidenceOSError::Internal)
    }

    pub fn signing_payload_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature_ed25519.clear();
        unsigned.nullspec_id = [0_u8; 32];
        let value = serde_json::to_value(&unsigned).map_err(|_| EvidenceOSError::Internal)?;
        let sorted = sort_json(value);
        serde_json::to_vec(&sorted).map_err(|_| EvidenceOSError::Internal)
    }

    pub fn compute_id(&self) -> EvidenceOSResult<[u8; 32]> {
        let mut hasher = Sha256::new();
        let payload = self.signing_payload_bytes()?;
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    pub fn verify_signature(&self, trusted_keys: &TrustedAuthorities) -> EvidenceOSResult<()> {
        if self.schema != NULLSPEC_SCHEMA_V1 {
            return Err(EvidenceOSError::NullSpecInvalid(
                "invalid schema".to_string(),
            ));
        }
        let key = trusted_keys
            .get(&self.created_by)
            .ok_or_else(|| EvidenceOSError::NullSpecInvalid("unknown key id".to_string()))?;
        let sig_bytes: [u8; 64] = self
            .signature_ed25519
            .as_slice()
            .try_into()
            .map_err(|_| EvidenceOSError::SignatureInvalid)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let payload = self.signing_payload_bytes()?;
        key.verify(&payload, &sig)
            .map_err(|_| EvidenceOSError::SignatureInvalid)?;
        if self.nullspec_id != self.compute_id()? {
            return Err(EvidenceOSError::NullSpecInvalid(
                "nullspec id mismatch".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch > self.epoch_created.saturating_add(self.ttl_epochs)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_contract() -> SignedNullSpecContractV1 {
        SignedNullSpecContractV1 {
            schema: NULLSPEC_SCHEMA_V1.to_string(),
            nullspec_id: [0_u8; 32],
            oracle_id: "o1".to_string(),
            oracle_resolution_hash: [7_u8; 32],
            holdout_handle: "h1".to_string(),
            epoch_created: 10,
            ttl_epochs: 20,
            kind: NullSpecKind::DiscreteBuckets {
                p0: vec![0.2, 0.3, 0.5],
            },
            eprocess: EProcessKind::DirichletMultinomialMixture {
                alpha: vec![1.0, 1.0, 1.0],
            },
            calibration_manifest_hash: Some([9_u8; 32]),
            created_by: "op1".to_string(),
            signature_ed25519: Vec::new(),
        }
    }

    #[test]
    fn compute_id_matches_canonical_hash() {
        let c = sample_contract();
        let mut h = Sha256::new();
        h.update(c.canonical_bytes().expect("canonical"));
        let digest = h.finalize();
        let mut expected = [0_u8; 32];
        expected.copy_from_slice(&digest);
        assert_eq!(c.compute_id().expect("id"), expected);
    }

    #[test]
    fn signature_verification_passes_and_fails() {
        let sk = SigningKey::from_bytes(&[3_u8; 32]);
        let vk = sk.verifying_key();
        let mut c = sample_contract();
        let payload = c.signing_payload_bytes().expect("payload");
        c.signature_ed25519 = sk.sign(&payload).to_bytes().to_vec();
        c.nullspec_id = c.compute_id().expect("id");

        let mut ta = TrustedAuthorities::default();
        ta.insert("op1".to_string(), vk);
        assert!(c.verify_signature(&ta).is_ok());

        c.signature_ed25519[0] ^= 1;
        assert!(c.verify_signature(&ta).is_err());
    }

    #[test]
    fn ttl_boundary() {
        let c = sample_contract();
        assert!(!c.is_expired(30));
        assert!(c.is_expired(31));
    }
}
