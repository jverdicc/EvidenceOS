use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::physhir::{check_dimension, Dimension};
use crate::structured_claims::{CanonicalFieldValue, StructuredClaim, SCHEMA_ID};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

pub const MAGNITUDE_ENVELOPE_PACK_SCHEMA_V1: &str = "evidenceos.magnitude-envelope-pack.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuantityEnvelopeBound {
    pub field: String,
    pub expected_dimension: Dimension,
    pub min_value: i128,
    pub max_value: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MagnitudeEnvelope {
    pub envelope_id: String,
    pub profile_id: String,
    pub schema_id: String,
    pub quantity_bounds: Vec<QuantityEnvelopeBound>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopePackMetadata {
    pub pack_id: String,
    pub version: u32,
    pub valid_from_unix: u64,
    pub valid_to_unix: u64,
    pub issuer: String,
    pub signature_ed25519_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopePack {
    pub schema: String,
    pub metadata: EnvelopePackMetadata,
    pub envelopes: Vec<MagnitudeEnvelope>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedEnvelopeAuthorities {
    pub keys: HashMap<String, VerifyingKey>,
}

impl TrustedEnvelopeAuthorities {
    pub fn insert(&mut self, key_id: String, key: VerifyingKey) {
        self.keys.insert(key_id, key);
    }

    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    pub fn load_from_json(path: &Path) -> EvidenceOSResult<Self> {
        #[derive(Deserialize)]
        struct TrustedKeysFile {
            keys: HashMap<String, String>,
        }

        let payload = fs::read(path).map_err(|_| EvidenceOSError::InvalidArgument)?;
        let parsed: TrustedKeysFile =
            serde_json::from_slice(&payload).map_err(|_| EvidenceOSError::InvalidArgument)?;
        let mut out = Self::default();
        for (issuer, key_hex) in parsed.keys {
            let key_bytes = hex::decode(key_hex).map_err(|_| EvidenceOSError::InvalidArgument)?;
            let key = VerifyingKey::from_bytes(
                key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| EvidenceOSError::InvalidArgument)?,
            )
            .map_err(|_| EvidenceOSError::InvalidArgument)?;
            out.insert(issuer, key);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeViolation {
    pub profile_id: String,
    pub schema_id: String,
    pub field: String,
    pub min_value: i128,
    pub max_value: i128,
    pub observed_value: i128,
}

impl EnvelopePack {
    pub fn signing_payload_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.metadata.signature_ed25519_b64.clear();
        unsigned.metadata.pack_id.clear();
        let value = serde_json::to_value(&unsigned).map_err(|_| EvidenceOSError::Internal)?;
        let sorted = sort_json(value);
        serde_json::to_vec(&sorted).map_err(|_| EvidenceOSError::Internal)
    }

    pub fn compute_pack_id_hex(&self) -> EvidenceOSResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_payload_bytes()?);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn sign_with_key(&mut self, signing_key: &SigningKey) -> EvidenceOSResult<()> {
        let payload = self.signing_payload_bytes()?;
        let sig = signing_key.sign(&payload);
        self.metadata.signature_ed25519_b64 = B64.encode(sig.to_bytes());
        self.metadata.pack_id = self.compute_pack_id_hex()?;
        Ok(())
    }

    pub fn verify_signature(
        &self,
        trusted_keys: &TrustedEnvelopeAuthorities,
        now_unix: u64,
        require_signed: bool,
    ) -> EvidenceOSResult<()> {
        if self.schema != MAGNITUDE_ENVELOPE_PACK_SCHEMA_V1 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if self.metadata.valid_from_unix > self.metadata.valid_to_unix {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if now_unix < self.metadata.valid_from_unix || now_unix > self.metadata.valid_to_unix {
            return Err(EvidenceOSError::InvalidArgument);
        }

        let has_sig = !self.metadata.signature_ed25519_b64.is_empty();
        if !has_sig {
            if require_signed {
                return Err(EvidenceOSError::SignatureInvalid);
            }
            if !self.metadata.pack_id.is_empty()
                && self.metadata.pack_id != self.compute_pack_id_hex()?
            {
                return Err(EvidenceOSError::InvalidArgument);
            }
            return Ok(());
        }

        let key = trusted_keys
            .get(&self.metadata.issuer)
            .ok_or(EvidenceOSError::SignatureInvalid)?;
        let sig_bytes = B64
            .decode(self.metadata.signature_ed25519_b64.as_bytes())
            .map_err(|_| EvidenceOSError::SignatureInvalid)?;
        let sig = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EvidenceOSError::SignatureInvalid)?,
        );
        let payload = self.signing_payload_bytes()?;
        key.verify(&payload, &sig)
            .map_err(|_| EvidenceOSError::SignatureInvalid)?;
        if self.metadata.pack_id != self.compute_pack_id_hex()? {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EnvelopeRegistry {
    envelopes: HashMap<(String, String), MagnitudeEnvelope>,
}

impl EnvelopeRegistry {
    pub fn empty() -> Self {
        Self {
            envelopes: HashMap::new(),
        }
    }

    pub fn with_builtin_defaults() -> Self {
        let mut out = Self::empty();
        out.envelopes.insert(
            ("cbrn.v1".to_string(), SCHEMA_ID.to_string()),
            MagnitudeEnvelope {
                envelope_id: "builtin.cbrn.v1.measurement.v1".to_string(),
                profile_id: "cbrn.v1".to_string(),
                schema_id: SCHEMA_ID.to_string(),
                quantity_bounds: vec![QuantityEnvelopeBound {
                    field: "measurement".to_string(),
                    expected_dimension: Dimension::new(-3, 0, 0, 0, 0, 1, 0),
                    min_value: -1_000_000,
                    max_value: 1_000_000,
                }],
            },
        );
        out
    }

    pub fn insert_envelope(&mut self, envelope: MagnitudeEnvelope) {
        let key = (envelope.profile_id.clone(), envelope.schema_id.clone());
        self.envelopes.insert(key, envelope);
    }

    pub fn load_from_signed_packs_dir(
        packs_dir: &Path,
        trusted_keys: &TrustedEnvelopeAuthorities,
        now_unix: u64,
        require_signed: bool,
    ) -> EvidenceOSResult<Self> {
        let mut out = Self::empty();
        if !packs_dir.exists() {
            return if require_signed {
                Err(EvidenceOSError::NotFound)
            } else {
                Ok(Self::with_builtin_defaults())
            };
        }
        let mut entries = fs::read_dir(packs_dir)
            .map_err(|_| EvidenceOSError::InvalidArgument)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| EvidenceOSError::InvalidArgument)?;
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let payload = fs::read(&path).map_err(|_| EvidenceOSError::InvalidArgument)?;
            let pack: EnvelopePack =
                serde_json::from_slice(&payload).map_err(|_| EvidenceOSError::InvalidArgument)?;
            pack.verify_signature(trusted_keys, now_unix, require_signed)?;
            for envelope in &pack.envelopes {
                if envelope.envelope_id.trim().is_empty() {
                    return Err(EvidenceOSError::InvalidArgument);
                }
                let key = (envelope.profile_id.clone(), envelope.schema_id.clone());
                out.envelopes.insert(key, envelope.clone());
            }
        }

        if out.envelopes.is_empty() {
            if require_signed {
                return Err(EvidenceOSError::NotFound);
            }
            return Ok(Self::with_builtin_defaults());
        }
        Ok(out)
    }

    pub fn validate_claim(&self, claim: &StructuredClaim) -> Result<(), Box<EnvelopeViolation>> {
        let key = ("cbrn.v1".to_string(), claim.schema_id.clone());
        let Some(envelope) = self.envelopes.get(&key) else {
            return Ok(());
        };

        for bound in &envelope.quantity_bounds {
            let Some(field) = claim.fields.iter().find(|f| f.name == bound.field) else {
                continue;
            };
            match &field.value {
                CanonicalFieldValue::Quantity(quantity) => {
                    if check_dimension(quantity, bound.expected_dimension).is_err()
                        || quantity.value < bound.min_value
                        || quantity.value > bound.max_value
                    {
                        return Err(Box::new(EnvelopeViolation {
                            profile_id: envelope.profile_id.clone(),
                            schema_id: envelope.schema_id.clone(),
                            field: bound.field.clone(),
                            min_value: bound.min_value,
                            max_value: bound.max_value,
                            observed_value: quantity.value,
                        }));
                    }
                }
                CanonicalFieldValue::QuantityList(quantities) => {
                    for entry in quantities {
                        let quantity = &entry.quantity;
                        if check_dimension(quantity, bound.expected_dimension).is_err()
                            || quantity.value < bound.min_value
                            || quantity.value > bound.max_value
                        {
                            return Err(Box::new(EnvelopeViolation {
                                profile_id: envelope.profile_id.clone(),
                                schema_id: envelope.schema_id.clone(),
                                field: bound.field.clone(),
                                min_value: bound.min_value,
                                max_value: bound.max_value,
                                observed_value: quantity.value,
                            }));
                        }
                    }
                }
                _ => continue,
            }
        }
        Ok(())
    }
}

static ACTIVE_REGISTRY: OnceLock<RwLock<Option<Arc<EnvelopeRegistry>>>> = OnceLock::new();

fn production_mode_enabled() -> bool {
    std::env::var("EVIDENCEOS_PRODUCTION_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn active_registry() -> Arc<EnvelopeRegistry> {
    let lock = ACTIVE_REGISTRY.get_or_init(|| RwLock::new(None));
    match lock.read() {
        Ok(reg) => reg.clone().unwrap_or_else(|| {
            if production_mode_enabled() {
                Arc::new(EnvelopeRegistry::empty())
            } else {
                Arc::new(EnvelopeRegistry::with_builtin_defaults())
            }
        }),
        Err(_) => Arc::new(EnvelopeRegistry::empty()),
    }
}

pub fn set_active_registry(registry: EnvelopeRegistry) -> EvidenceOSResult<()> {
    let lock = ACTIVE_REGISTRY.get_or_init(|| RwLock::new(None));
    let mut guard = lock.write().map_err(|_| EvidenceOSError::Internal)?;
    *guard = Some(Arc::new(registry));
    Ok(())
}

#[cfg(test)]
pub fn clear_active_registry_for_tests() -> EvidenceOSResult<()> {
    let lock = ACTIVE_REGISTRY.get_or_init(|| RwLock::new(None));
    let mut guard = lock.write().map_err(|_| EvidenceOSError::Internal)?;
    *guard = None;
    Ok(())
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
    use crate::physhir::parse_quantity;
    use crate::structured_claims::{CanonicalFieldValue, StructuredField};

    fn base_pack() -> EnvelopePack {
        EnvelopePack {
            schema: MAGNITUDE_ENVELOPE_PACK_SCHEMA_V1.to_string(),
            metadata: EnvelopePackMetadata {
                pack_id: String::new(),
                version: 1,
                valid_from_unix: 1,
                valid_to_unix: u64::MAX,
                issuer: "issuer-a".to_string(),
                signature_ed25519_b64: String::new(),
            },
            envelopes: vec![MagnitudeEnvelope {
                envelope_id: "cbrn-main".to_string(),
                profile_id: "cbrn.v1".to_string(),
                schema_id: SCHEMA_ID.to_string(),
                quantity_bounds: vec![QuantityEnvelopeBound {
                    field: "measurement".to_string(),
                    expected_dimension: Dimension::new(-3, 0, 0, 0, 0, 1, 0),
                    min_value: -1_000_000,
                    max_value: 1_000_000,
                }],
            }],
        }
    }

    #[test]
    fn out_of_range_quantity_fails_envelope() {
        let claim = StructuredClaim {
            schema_id: SCHEMA_ID.to_string(),
            fields: vec![StructuredField {
                name: "measurement".to_string(),
                value: CanonicalFieldValue::Quantity(parse_quantity("1000001 mmol/L").expect("q")),
            }],
        };
        let reg = EnvelopeRegistry::with_builtin_defaults();
        assert!(reg.validate_claim(&claim).is_err());
    }

    #[test]
    fn in_range_quantity_passes_envelope() {
        let claim = StructuredClaim {
            schema_id: SCHEMA_ID.to_string(),
            fields: vec![StructuredField {
                name: "measurement".to_string(),
                value: CanonicalFieldValue::Quantity(parse_quantity("10 mmol/L").expect("q")),
            }],
        };
        let reg = EnvelopeRegistry::with_builtin_defaults();
        assert!(reg.validate_claim(&claim).is_ok());
    }

    #[test]
    fn bad_signature_rejected() {
        let signer = SigningKey::from_bytes(&[7_u8; 32]);
        let verify = signer.verifying_key();
        let mut trusted = TrustedEnvelopeAuthorities::default();
        trusted.insert("issuer-a".to_string(), verify);

        let mut pack = base_pack();
        pack.sign_with_key(&signer).expect("sign");
        pack.metadata.pack_id = "00".repeat(32);
        assert!(pack.verify_signature(&trusted, 2, true).is_err());
    }

    #[test]
    fn expired_pack_rejected() {
        let signer = SigningKey::from_bytes(&[8_u8; 32]);
        let verify = signer.verifying_key();
        let mut trusted = TrustedEnvelopeAuthorities::default();
        trusted.insert("issuer-a".to_string(), verify);

        let mut pack = base_pack();
        pack.metadata.valid_to_unix = 5;
        pack.sign_with_key(&signer).expect("sign");
        assert!(pack.verify_signature(&trusted, 6, true).is_err());
    }

    #[test]
    fn rotation_overlap_window_works() {
        let signer_a = SigningKey::from_bytes(&[1_u8; 32]);
        let signer_b = SigningKey::from_bytes(&[2_u8; 32]);
        let mut trusted = TrustedEnvelopeAuthorities::default();
        trusted.insert("issuer-a".to_string(), signer_a.verifying_key());
        trusted.insert("issuer-b".to_string(), signer_b.verifying_key());

        let mut old_pack = base_pack();
        old_pack.metadata.issuer = "issuer-a".to_string();
        old_pack.metadata.valid_from_unix = 10;
        old_pack.metadata.valid_to_unix = 100;
        old_pack.sign_with_key(&signer_a).expect("sign old");

        let mut new_pack = base_pack();
        new_pack.metadata.issuer = "issuer-b".to_string();
        new_pack.metadata.valid_from_unix = 50;
        new_pack.metadata.valid_to_unix = 200;
        new_pack.envelopes[0].envelope_id = "cbrn-main-v2".to_string();
        new_pack.sign_with_key(&signer_b).expect("sign new");

        assert!(old_pack.verify_signature(&trusted, 60, true).is_ok());
        assert!(new_pack.verify_signature(&trusted, 60, true).is_ok());
    }
}
