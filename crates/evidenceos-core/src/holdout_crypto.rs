// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::env;
use thiserror::Error;

const HOLDOUT_MAGIC: [u8; 4] = *b"EHLD";
const HOLDOUT_VERSION: u8 = 1;
const HOLDOUT_ALG_AES_256_GCM: u8 = 2;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + 1 + NONCE_LEN;
const TAG_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum HoldoutCryptoError {
    #[error("holdout payload too short")]
    PayloadTooShort,
    #[error("unsupported holdout encryption format")]
    UnsupportedFormat,
    #[error("holdout decrypt failed")]
    DecryptFailed,
    #[error("holdout labels must be non-empty binary bytes")]
    InvalidLabels,
}

#[derive(Debug, Error)]
pub enum HoldoutKeyProviderError {
    #[error("invalid holdout encryption_key_id")]
    InvalidKeyId,
    #[error("holdout key for encryption_key_id not found")]
    KeyNotFound,
    #[error("invalid holdout key material")]
    InvalidKeyMaterial,
    #[error("kms provider not implemented: {0}")]
    Unimplemented(&'static str),
}

pub trait HoldoutKeyProvider: Send + Sync {
    fn key_for_id(&self, key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError>;
}

#[derive(Debug, Default)]
pub struct EnvKeyProvider;

impl EnvKeyProvider {
    pub fn new() -> Self {
        Self
    }
}

impl HoldoutKeyProvider for EnvKeyProvider {
    fn key_for_id(&self, key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        let var_suffix = sanitize_key_id(key_id)?;
        let var_name = format!("EVIDENCEOS_HOLDOUT_KEY_{var_suffix}");
        let key_hex = env::var(var_name).map_err(|_| HoldoutKeyProviderError::KeyNotFound)?;
        let key_bytes =
            hex::decode(key_hex).map_err(|_| HoldoutKeyProviderError::InvalidKeyMaterial)?;
        let key_arr: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| HoldoutKeyProviderError::InvalidKeyMaterial)?;
        Ok(key_arr)
    }
}

#[derive(Debug, Default)]
pub struct AwsKmsKeyProvider;
#[derive(Debug, Default)]
pub struct GcpKmsKeyProvider;
#[derive(Debug, Default)]
pub struct AzureKmsKeyProvider;

impl HoldoutKeyProvider for AwsKmsKeyProvider {
    fn key_for_id(&self, _key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        Err(HoldoutKeyProviderError::Unimplemented(
            "aws kms holdout provider (TODO: envelope decrypt data key by key_id)",
        ))
    }
}

impl HoldoutKeyProvider for GcpKmsKeyProvider {
    fn key_for_id(&self, _key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        Err(HoldoutKeyProviderError::Unimplemented(
            "gcp kms holdout provider (TODO: cloud kms decrypt data key by key_id)",
        ))
    }
}

impl HoldoutKeyProvider for AzureKmsKeyProvider {
    fn key_for_id(&self, _key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        Err(HoldoutKeyProviderError::Unimplemented(
            "azure key vault holdout provider (TODO: key vault unwrap data key by key_id)",
        ))
    }
}

pub fn encrypt_holdout_labels(
    labels: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, HoldoutCryptoError> {
    if labels.is_empty() || labels.iter().any(|v| *v > 1) {
        return Err(HoldoutCryptoError::InvalidLabels);
    }
    let cipher = make_cipher(key)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = labels.to_vec();
    in_out.reserve(TAG_LEN);
    cipher
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| HoldoutCryptoError::DecryptFailed)?;

    let mut out = Vec::with_capacity(HEADER_LEN + in_out.len());
    out.extend_from_slice(&HOLDOUT_MAGIC);
    out.push(HOLDOUT_VERSION);
    out.push(HOLDOUT_ALG_AES_256_GCM);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

pub fn decrypt_holdout_labels(
    payload: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, HoldoutCryptoError> {
    if payload.len() < HEADER_LEN + TAG_LEN {
        return Err(HoldoutCryptoError::PayloadTooShort);
    }
    if payload[0..4] != HOLDOUT_MAGIC
        || payload[4] != HOLDOUT_VERSION
        || payload[5] != HOLDOUT_ALG_AES_256_GCM
    {
        return Err(HoldoutCryptoError::UnsupportedFormat);
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&payload[6..HEADER_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let cipher = make_cipher(key)?;
    let mut in_out = payload[HEADER_LEN..].to_vec();
    let plain = cipher
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| HoldoutCryptoError::DecryptFailed)?;
    let labels = plain.to_vec();
    if labels.is_empty() || labels.iter().any(|v| *v > 1) {
        return Err(HoldoutCryptoError::InvalidLabels);
    }
    Ok(labels)
}

fn make_cipher(key: &[u8; 32]) -> Result<LessSafeKey, HoldoutCryptoError> {
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| HoldoutCryptoError::DecryptFailed)?;
    Ok(LessSafeKey::new(unbound))
}

fn sanitize_key_id(key_id: &str) -> Result<String, HoldoutKeyProviderError> {
    if key_id.is_empty() || key_id.len() > 128 {
        return Err(HoldoutKeyProviderError::InvalidKeyId);
    }
    if !key_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(HoldoutKeyProviderError::InvalidKeyId);
    }
    Ok(key_id
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holdout_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let labels = vec![0, 1, 1, 0, 1];
        let encrypted = encrypt_holdout_labels(&labels, &key).expect("encrypt");
        let decrypted = decrypt_holdout_labels(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, labels);
    }
}
