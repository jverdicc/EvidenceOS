use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::physhir::{check_dimension, Dimension};
use crate::structured_claims::{CanonicalFieldValue, StructuredClaim, SCHEMA_ID};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const MAGNITUDE_ENVELOPE_SCHEMA_V1: &str = "evidenceos.magnitude-envelope.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuantityEnvelopeBound {
    pub field: String,
    pub expected_dimension: Dimension,
    pub min_value: i128,
    pub max_value: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MagnitudeEnvelopePackV1 {
    pub schema: String,
    pub envelope_id: [u8; 32],
    pub profile_id: String,
    pub schema_id: String,
    pub created_by: String,
    pub quantity_bounds: Vec<QuantityEnvelopeBound>,
    pub signature_ed25519: Vec<u8>,
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

impl MagnitudeEnvelopePackV1 {
    pub fn signing_payload_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature_ed25519.clear();
        unsigned.envelope_id = [0_u8; 32];
        let value = serde_json::to_value(&unsigned).map_err(|_| EvidenceOSError::Internal)?;
        let sorted = sort_json(value);
        serde_json::to_vec(&sorted).map_err(|_| EvidenceOSError::Internal)
    }

    pub fn compute_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_payload_bytes().unwrap_or_default());
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn verify_signature(
        &self,
        trusted_keys: &TrustedEnvelopeAuthorities,
    ) -> EvidenceOSResult<()> {
        if self.schema != MAGNITUDE_ENVELOPE_SCHEMA_V1 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let key = trusted_keys
            .get(&self.created_by)
            .ok_or(EvidenceOSError::InvalidArgument)?;
        let sig_bytes: [u8; 64] = self
            .signature_ed25519
            .as_slice()
            .try_into()
            .map_err(|_| EvidenceOSError::SignatureInvalid)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let payload = self.signing_payload_bytes()?;
        key.verify(&payload, &sig)
            .map_err(|_| EvidenceOSError::SignatureInvalid)?;
        if self.envelope_id != self.compute_id() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EnvelopeRegistry {
    packs: HashMap<(String, String), MagnitudeEnvelopePackV1>,
}

impl EnvelopeRegistry {
    pub fn with_defaults() -> Self {
        let mut packs = HashMap::new();
        let mut cbrn = MagnitudeEnvelopePackV1 {
            schema: MAGNITUDE_ENVELOPE_SCHEMA_V1.to_string(),
            envelope_id: [0_u8; 32],
            profile_id: "cbrn.v1".to_string(),
            schema_id: SCHEMA_ID.to_string(),
            created_by: "builtin".to_string(),
            quantity_bounds: vec![QuantityEnvelopeBound {
                field: "measurement".to_string(),
                expected_dimension: Dimension::new(-3, 0, 0, 0, 0, 1, 0),
                min_value: -1_000_000,
                max_value: 1_000_000,
            }],
            signature_ed25519: Vec::new(),
        };
        cbrn.envelope_id = cbrn.compute_id();
        packs.insert((cbrn.profile_id.clone(), cbrn.schema_id.clone()), cbrn);
        Self { packs }
    }

    pub fn validate_claim(&self, claim: &StructuredClaim) -> Result<(), Box<EnvelopeViolation>> {
        let key = ("cbrn.v1".to_string(), claim.schema_id.clone());
        let Some(pack) = self.packs.get(&key) else {
            return Ok(());
        };

        for bound in &pack.quantity_bounds {
            let Some(field) = claim.fields.iter().find(|f| f.name == bound.field) else {
                continue;
            };
            let CanonicalFieldValue::Quantity(quantity) = &field.value else {
                continue;
            };
            if check_dimension(quantity, bound.expected_dimension).is_err()
                || quantity.value < bound.min_value
                || quantity.value > bound.max_value
            {
                return Err(Box::new(EnvelopeViolation {
                    profile_id: pack.profile_id.clone(),
                    schema_id: pack.schema_id.clone(),
                    field: bound.field.clone(),
                    min_value: bound.min_value,
                    max_value: bound.max_value,
                    observed_value: quantity.value,
                }));
            }
        }
        Ok(())
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
    use crate::physhir::parse_quantity;
    use crate::structured_claims::{CanonicalFieldValue, StructuredField};

    #[test]
    fn out_of_range_quantity_fails_envelope() {
        let claim = StructuredClaim {
            schema_id: SCHEMA_ID.to_string(),
            fields: vec![StructuredField {
                name: "measurement".to_string(),
                value: CanonicalFieldValue::Quantity(parse_quantity("1000001 mmol/L").expect("q")),
            }],
        };
        let reg = EnvelopeRegistry::with_defaults();
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
        let reg = EnvelopeRegistry::with_defaults();
        assert!(reg.validate_claim(&claim).is_ok());
    }
}
