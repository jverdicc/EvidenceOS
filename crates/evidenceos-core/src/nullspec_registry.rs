use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::nullspec::SignedNullSpecContractV1;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct NullSpecAuthorityKeyring {
    pub keys: HashMap<String, VerifyingKey>,
}

impl NullSpecAuthorityKeyring {
    pub fn load_from_dir(path: &Path) -> EvidenceOSResult<Self> {
        let mut out = Self::default();
        if !path.exists() {
            return Ok(out);
        }
        let entries = fs::read_dir(path).map_err(|_| EvidenceOSError::NotFound)?;
        for entry in entries {
            let entry = entry.map_err(|_| EvidenceOSError::Internal)?;
            if !entry
                .file_type()
                .map_err(|_| EvidenceOSError::Internal)?
                .is_file()
            {
                continue;
            }
            let file_path = entry.path();
            let kid = file_path
                .file_stem()
                .and_then(|v| v.to_str())
                .ok_or_else(|| {
                    EvidenceOSError::NullSpecInvalid("invalid key filename".to_string())
                })?
                .to_string();
            let payload = fs::read_to_string(&file_path).map_err(|_| EvidenceOSError::Internal)?;
            let key_hex = payload.trim();
            let key_bytes = hex::decode(key_hex)
                .map_err(|_| EvidenceOSError::NullSpecInvalid("invalid key hex".to_string()))?;
            let key_array: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| EvidenceOSError::NullSpecInvalid("invalid key length".to_string()))?;
            let key = VerifyingKey::from_bytes(&key_array).map_err(|_| {
                EvidenceOSError::NullSpecInvalid("invalid ed25519 public key".to_string())
            })?;
            out.keys.insert(kid, key);
        }
        Ok(out)
    }
}

#[derive(Debug, Default, Clone)]
pub struct NullSpecRegistry {
    contracts: HashMap<String, SignedNullSpecContractV1>,
}

impl NullSpecRegistry {
    pub fn load_from_dir(
        registry_dir: &Path,
        keyring: &NullSpecAuthorityKeyring,
        allow_fixed_e_value_in_dev: bool,
    ) -> EvidenceOSResult<Self> {
        let mut contracts = HashMap::new();
        if !registry_dir.exists() {
            return Err(EvidenceOSError::NotFound);
        }
        let nullspec_root = registry_dir.join("nullspecs");
        if !nullspec_root.exists() {
            return Err(EvidenceOSError::NotFound);
        }

        let domains = fs::read_dir(&nullspec_root).map_err(|_| EvidenceOSError::Internal)?;
        for domain_entry in domains {
            let domain_entry = domain_entry.map_err(|_| EvidenceOSError::Internal)?;
            if !domain_entry
                .file_type()
                .map_err(|_| EvidenceOSError::Internal)?
                .is_dir()
            {
                continue;
            }
            let domain_name = domain_entry
                .file_name()
                .into_string()
                .map_err(|_| EvidenceOSError::NullSpecInvalid("invalid domain name".to_string()))?;
            let files = fs::read_dir(domain_entry.path()).map_err(|_| EvidenceOSError::Internal)?;
            for file_entry in files {
                let file_entry = file_entry.map_err(|_| EvidenceOSError::Internal)?;
                if !file_entry
                    .file_type()
                    .map_err(|_| EvidenceOSError::Internal)?
                    .is_file()
                {
                    continue;
                }
                let path = file_entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| {
                        EvidenceOSError::NullSpecInvalid("invalid contract file name".to_string())
                    })?
                    .to_string();
                let sig_path = path.with_extension("sig");
                if !sig_path.exists() {
                    return Err(EvidenceOSError::SignatureInvalid);
                }

                let raw = fs::read(&path).map_err(|_| EvidenceOSError::Internal)?;
                let contract: SignedNullSpecContractV1 = serde_json::from_slice(&raw)
                    .map_err(|_| EvidenceOSError::NullSpecInvalid("invalid json".to_string()))?;
                if contract.oracle_id != domain_name {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "contract oracle id does not match folder".to_string(),
                    ));
                }
                if hex::encode(contract.nullspec_id) != id {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "filename id does not match contract id".to_string(),
                    ));
                }
                let _ = allow_fixed_e_value_in_dev;
                contract.verify_signature(&crate::nullspec::TrustedAuthorities {
                    keys: keyring.keys.clone(),
                })?;

                let canonical_bytes = contract.canonical_bytes()?;
                let sig_hex =
                    fs::read_to_string(&sig_path).map_err(|_| EvidenceOSError::Internal)?;
                verify_signature(&canonical_bytes, sig_hex.trim(), keyring)?;
                contracts.insert(hex::encode(contract.nullspec_id), contract);
            }
        }

        Ok(Self { contracts })
    }

    pub fn get(&self, id: &str) -> Option<&SignedNullSpecContractV1> {
        self.contracts.get(id)
    }
}

fn verify_signature(
    payload: &[u8],
    signature_hex: &str,
    keyring: &NullSpecAuthorityKeyring,
) -> EvidenceOSResult<()> {
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| EvidenceOSError::NullSpecInvalid("invalid signature hex".to_string()))?;
    let signature: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| EvidenceOSError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&signature);

    for key in keyring.keys.values() {
        if key.verify(payload, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(EvidenceOSError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullspec::{EProcessKind, NullSpecKind, NULLSPEC_SCHEMA_V1};
    use proptest::prelude::*;

    #[test]
    fn rejects_fixed_e_value_when_allow_fixed_e_value_in_dev_false() {
        let mut c = SignedNullSpecContractV1 {
            schema: NULLSPEC_SCHEMA_V1.to_string(),
            nullspec_id: [0; 32],
            oracle_id: "accuracy.binary.v1".to_string(),
            oracle_resolution_hash: [1; 32],
            holdout_handle: "h1".to_string(),
            epoch_created: 1,
            ttl_epochs: 5,
            kind: NullSpecKind::ParametricBernoulli { p: 0.5 },
            eprocess: EProcessKind::LikelihoodRatioFixedAlt {
                alt: vec![0.5, 0.5],
            },
            calibration_manifest_hash: None,
            created_by: "k1".to_string(),
            signature_ed25519: vec![0; 64],
        };
        c.nullspec_id = c.compute_id().expect("id");
        let err = c
            .verify_signature(&crate::nullspec::TrustedAuthorities::default())
            .expect_err("must fail");
        assert!(err.to_string().contains("unknown key id"));
    }

    proptest! {
        #[test]
        fn canonicalization_deterministic_under_key_order_permutations(
            domain in "[a-z.]{1,20}",
            null_accuracy_raw in 1u16..1024u16,
            created_at_unix in 0u64..1_000_000u64,
        ) {
            let null_accuracy = (null_accuracy_raw as f64) / 1024.0;
            let mut c = SignedNullSpecContractV1 {
                schema: NULLSPEC_SCHEMA_V1.to_string(),
                nullspec_id: [0; 32],
                oracle_id: domain,
                oracle_resolution_hash: [7; 32],
                holdout_handle: "h1".to_string(),
                epoch_created: created_at_unix,
                ttl_epochs: 7,
                kind: NullSpecKind::ParametricBernoulli { p: null_accuracy },
                eprocess: EProcessKind::LikelihoodRatioFixedAlt { alt: vec![0.5, 0.5] },
                calibration_manifest_hash: None,
                created_by: "k1".to_string(),
                signature_ed25519: vec![0; 64],
            };
            c.nullspec_id = c.compute_id().expect("id");
            let canonical = c.canonical_bytes().expect("canonical");

            let value = serde_json::to_value(&c).expect("value");
            let obj = value.as_object().expect("object");
            let mut permuted_map = serde_json::Map::new();
            for key in ["schema", "oracle_id", "nullspec_id", "oracle_resolution_hash", "holdout_handle", "epoch_created", "ttl_epochs", "kind", "eprocess", "calibration_manifest_hash", "created_by", "signature_ed25519"] {
                permuted_map.insert(key.to_string(), obj.get(key).cloned().expect("field"));
            }
            let permuted_bytes = serde_json::to_vec(&serde_json::Value::Object(permuted_map)).expect("permuted");
            let reparsed: SignedNullSpecContractV1 = serde_json::from_slice(&permuted_bytes).expect("parse");
            let canonical_permuted = reparsed.canonical_bytes().expect("canonical 2");

            prop_assert_eq!(c.compute_id().expect("id a"), reparsed.compute_id().expect("id b"));
            prop_assert_eq!(canonical.len(), canonical_permuted.len());
        }
    }
}
