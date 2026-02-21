use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::oracle::{NullSpec, OracleResolution};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Trusted Ed25519 authorities keyed by stable key id for oracle bundle validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustedOracleAuthorities {
    pub keys: BTreeMap<String, Vec<u8>>,
}

impl TrustedOracleAuthorities {
    pub fn verify_manifest(&self, manifest: &OracleBundleManifestV1) -> EvidenceOSResult<()> {
        manifest.verify_signature(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    OracleQuery,
}

/// Signed Oracle bundle manifest v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleBundleManifestV1 {
    pub oracle_id: String,
    pub version: String,
    pub kind: String,
    pub interface_version: u32,
    pub wasm_sha256: [u8; 32],
    pub holdout_handle: String,
    pub resolution: OracleResolution,
    pub null_spec: NullSpec,
    pub calibration_manifest_hash: Option<[u8; 32]>,
    pub capabilities: Vec<Capability>,
    pub signed_by: String,
    pub signature_ed25519: Vec<u8>,
}

impl OracleBundleManifestV1 {
    /// Canonical signed bytes for Oracle bundle manifests.
    ///
    /// This enforces deterministic signed serialization so signatures are not sensitive to
    /// map insertion ordering or JSON whitespace. The signature field is excluded per
    /// canonical realization requirements (§5.1) and OracleResolution contract pinning (§10.1).
    pub fn canonical_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        let mut value = serde_json::to_value(self).map_err(|_| EvidenceOSError::InvalidArgument)?;
        if let Value::Object(ref mut obj) = value {
            obj.remove("signature_ed25519");
        }
        let canonical = sort_json(value);
        serde_json::to_vec(&canonical).map_err(|_| EvidenceOSError::InvalidArgument)
    }

    pub fn verify_signature(&self, trusted: &TrustedOracleAuthorities) -> EvidenceOSResult<()> {
        let key_bytes = trusted
            .keys
            .get(&self.signed_by)
            .ok_or(EvidenceOSError::OracleViolation)?;
        let vk = VerifyingKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EvidenceOSError::OracleViolation)?,
        )
        .map_err(|_| EvidenceOSError::OracleViolation)?;
        let sig = Signature::from_slice(&self.signature_ed25519)
            .map_err(|_| EvidenceOSError::OracleViolation)?;
        let bytes = self.canonical_bytes()?;
        vk.verify(&bytes, &sig)
            .map_err(|_| EvidenceOSError::OracleViolation)
    }
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    sorted.insert(key, sort_json(v.clone()));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::LocalityPolicy;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_manifest() -> OracleBundleManifestV1 {
        OracleBundleManifestV1 {
            oracle_id: "acme.safety.v1".into(),
            version: "1.2.3".into(),
            kind: "wasm".into(),
            interface_version: 1,
            wasm_sha256: [7; 32],
            holdout_handle: "dataset-epoch-1".into(),
            resolution: OracleResolution::new(8, 0.01).unwrap_or_else(|_| unreachable!()),
            null_spec: NullSpec {
                domain: "labels".into(),
                null_accuracy: 0.5,
                e_value_fn: crate::oracle::EValueFn::Fixed(1.0),
            },
            calibration_manifest_hash: Some([9; 32]),
            capabilities: vec![Capability::OracleQuery],
            signed_by: "root".into(),
            signature_ed25519: vec![],
        }
    }

    #[test]
    fn manifest_canonical_bytes_stable() {
        let manifest = sample_manifest();
        let stable_1 = manifest
            .canonical_bytes()
            .unwrap_or_else(|_| unreachable!("canonical"));
        let mut value = serde_json::to_value(&manifest).unwrap_or_else(|_| unreachable!());
        let mut manual = serde_json::Map::new();
        if let Value::Object(obj) = value.take() {
            let mut keys: Vec<_> = obj.keys().cloned().collect();
            keys.reverse();
            for key in keys {
                if let Some(v) = obj.get(&key) {
                    manual.insert(key, v.clone());
                }
            }
        }
        let reordered: OracleBundleManifestV1 =
            serde_json::from_value(Value::Object(manual)).unwrap_or_else(|_| unreachable!());
        let stable_2 = reordered
            .canonical_bytes()
            .unwrap_or_else(|_| unreachable!("canonical"));
        assert_eq!(stable_1, stable_2);
    }

    #[test]
    fn manifest_signature_verification_ok() {
        let signing = SigningKey::from_bytes(&[1; 32]);
        let verifying = signing.verifying_key();
        let mut manifest = sample_manifest();
        let msg = manifest
            .canonical_bytes()
            .unwrap_or_else(|_| unreachable!("canonical"));
        manifest.signature_ed25519 = signing.sign(&msg).to_vec();

        let mut trusted = TrustedOracleAuthorities::default();
        trusted
            .keys
            .insert("root".into(), verifying.to_bytes().to_vec());
        assert!(manifest.verify_signature(&trusted).is_ok());
    }

    #[test]
    fn manifest_signature_verification_rejects_tamper() {
        let signing = SigningKey::from_bytes(&[2; 32]);
        let mut manifest = sample_manifest();
        let msg = manifest
            .canonical_bytes()
            .unwrap_or_else(|_| unreachable!("canonical"));
        manifest.signature_ed25519 = signing.sign(&msg).to_vec();
        manifest.version = "9.9.9".into();

        let mut trusted = TrustedOracleAuthorities::default();
        trusted
            .keys
            .insert("root".into(), signing.verifying_key().to_bytes().to_vec());
        assert!(manifest.verify_signature(&trusted).is_err());
    }

    #[test]
    fn manifest_canonical_bytes_pin_locality_policy() {
        let mut a = sample_manifest();
        let mut b = sample_manifest();
        a.resolution.locality_policy = LocalityPolicy::ExactMatchOnly;
        b.resolution.locality_policy = LocalityPolicy::Hamming { max_bits: 1 };

        let bytes_a = a
            .canonical_bytes()
            .unwrap_or_else(|_| unreachable!("canonical"));
        let bytes_b = b
            .canonical_bytes()
            .unwrap_or_else(|_| unreachable!("canonical"));

        assert_ne!(bytes_a, bytes_b);
    }
}
