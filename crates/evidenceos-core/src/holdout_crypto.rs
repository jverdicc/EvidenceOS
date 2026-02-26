use base64::Engine as _;
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
const MAX_KMS_KEY_REF_LEN: usize = 4096;

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
    #[error("kms decrypt failed")]
    KmsDecryptFailed,
    #[error("kms provider unavailable: {0}")]
    KmsProviderUnavailable(&'static str),
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

pub trait KmsDecryptClient: Send + Sync {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError>;
}

struct MissingFeatureClient {
    feature_name: &'static str,
}

impl KmsDecryptClient for MissingFeatureClient {
    fn decrypt(
        &self,
        _key_resource: &str,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        Err(HoldoutKeyProviderError::KmsProviderUnavailable(
            self.feature_name,
        ))
    }
}

pub struct AwsKmsKeyProvider {
    client: Box<dyn KmsDecryptClient>,
}

pub struct GcpKmsKeyProvider {
    client: Box<dyn KmsDecryptClient>,
}

pub struct AzureKmsKeyProvider {
    client: Box<dyn KmsDecryptClient>,
}

impl AwsKmsKeyProvider {
    pub fn new() -> Self {
        Self {
            client: Box::new(AwsSdkClient::new()),
        }
    }

    pub fn with_client(client: Box<dyn KmsDecryptClient>) -> Self {
        Self { client }
    }
}

impl Default for AwsKmsKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpKmsKeyProvider {
    pub fn new() -> Self {
        Self {
            client: Box::new(GcpSdkClient::new()),
        }
    }

    pub fn with_client(client: Box<dyn KmsDecryptClient>) -> Self {
        Self { client }
    }
}

impl Default for GcpKmsKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AzureKmsKeyProvider {
    pub fn new() -> Self {
        Self {
            client: Box::new(AzureSdkClient::new()),
        }
    }

    pub fn with_client(client: Box<dyn KmsDecryptClient>) -> Self {
        Self { client }
    }
}

impl Default for AzureKmsKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HoldoutKeyProvider for AwsKmsKeyProvider {
    fn key_for_id(&self, key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        decrypt_kms_material(&*self.client, key_id)
    }
}

impl HoldoutKeyProvider for GcpKmsKeyProvider {
    fn key_for_id(&self, key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        decrypt_kms_material(&*self.client, key_id)
    }
}

impl HoldoutKeyProvider for AzureKmsKeyProvider {
    fn key_for_id(&self, key_id: &str) -> Result<[u8; 32], HoldoutKeyProviderError> {
        decrypt_kms_material(&*self.client, key_id)
    }
}

fn decrypt_kms_material(
    client: &dyn KmsDecryptClient,
    key_id: &str,
) -> Result<[u8; 32], HoldoutKeyProviderError> {
    let (key_resource, ciphertext) = parse_kms_key_ref(key_id)?;
    let plaintext = client.decrypt(key_resource, &ciphertext)?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| HoldoutKeyProviderError::InvalidKeyMaterial)
}

fn parse_kms_key_ref(key_id: &str) -> Result<(&str, Vec<u8>), HoldoutKeyProviderError> {
    if key_id.is_empty() || key_id.len() > MAX_KMS_KEY_REF_LEN {
        return Err(HoldoutKeyProviderError::InvalidKeyId);
    }
    let (key_resource, ciphertext_b64) = key_id
        .split_once('|')
        .ok_or(HoldoutKeyProviderError::InvalidKeyId)?;
    if key_resource.is_empty() || ciphertext_b64.is_empty() {
        return Err(HoldoutKeyProviderError::InvalidKeyId);
    }
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| HoldoutKeyProviderError::InvalidKeyMaterial)?;
    if ciphertext.is_empty() {
        return Err(HoldoutKeyProviderError::InvalidKeyMaterial);
    }
    Ok((key_resource, ciphertext))
}

#[cfg(feature = "kms-aws")]
struct AwsSdkClient;

#[cfg(feature = "kms-aws")]
impl AwsSdkClient {
    fn new() -> Self {
        Self
    }
}

#[cfg(feature = "kms-aws")]
impl KmsDecryptClient for AwsSdkClient {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
        runtime.block_on(async {
            let config = aws_config::load_from_env().await;
            let client = aws_sdk_kms::Client::new(&config);
            let out = client
                .decrypt()
                .key_id(key_resource)
                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext.to_vec()))
                .send()
                .await
                .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
            out.plaintext()
                .map(|blob| blob.as_ref().to_vec())
                .ok_or(HoldoutKeyProviderError::KmsDecryptFailed)
        })
    }
}

#[cfg(not(feature = "kms-aws"))]
struct AwsSdkClient;

#[cfg(not(feature = "kms-aws"))]
impl AwsSdkClient {
    fn build_missing_feature_client() -> MissingFeatureClient {
        MissingFeatureClient {
            feature_name: "kms-aws",
        }
    }

    fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "kms-aws"))]
impl KmsDecryptClient for AwsSdkClient {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        Self::build_missing_feature_client().decrypt(key_resource, ciphertext)
    }
}

#[cfg(feature = "kms-gcp")]
struct GcpSdkClient;

#[cfg(feature = "kms-gcp")]
impl GcpSdkClient {
    fn new() -> Self {
        Self
    }
}

#[cfg(feature = "kms-gcp")]
impl KmsDecryptClient for GcpSdkClient {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
        runtime.block_on(async {
            let config = google_cloud_kms::client::ClientConfig::default()
                .with_auth()
                .await
                .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
            let client = google_cloud_kms::client::Client::new(config)
                .await
                .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
            let req = google_cloud_googleapis::cloud::kms::v1::DecryptRequest {
                name: key_resource.to_string(),
                ciphertext: ciphertext.to_vec(),
                ..Default::default()
            };
            let out = client
                .decrypt(req)
                .await
                .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
            if out.plaintext.is_empty() {
                return Err(HoldoutKeyProviderError::KmsDecryptFailed);
            }
            Ok(out.plaintext)
        })
    }
}

#[cfg(not(feature = "kms-gcp"))]
struct GcpSdkClient;

#[cfg(not(feature = "kms-gcp"))]
impl GcpSdkClient {
    fn build_missing_feature_client() -> MissingFeatureClient {
        MissingFeatureClient {
            feature_name: "kms-gcp",
        }
    }

    fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "kms-gcp"))]
impl KmsDecryptClient for GcpSdkClient {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        Self::build_missing_feature_client().decrypt(key_resource, ciphertext)
    }
}

#[cfg(feature = "kms-azure")]
struct AzureSdkClient;

#[cfg(feature = "kms-azure")]
impl AzureSdkClient {
    fn new() -> Self {
        Self
    }
}

#[cfg(feature = "kms-azure")]
impl KmsDecryptClient for AzureSdkClient {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
        runtime.block_on(async {
            let credential = azure_identity::DefaultAzureCredential::default();
            let client = azure_security_keyvault_keys::CryptographyClient::new(
                key_resource,
                credential,
                None,
            )
            .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
            let out = client
                .unwrap_key(
                    azure_security_keyvault_keys::models::KeyEncryptionAlgorithm::RsaOaep256,
                    ciphertext.to_vec(),
                    None,
                )
                .await
                .map_err(|_| HoldoutKeyProviderError::KmsDecryptFailed)?;
            let value = out
                .result
                .value
                .ok_or(HoldoutKeyProviderError::KmsDecryptFailed)?;
            Ok(value)
        })
    }
}

#[cfg(not(feature = "kms-azure"))]
struct AzureSdkClient;

#[cfg(not(feature = "kms-azure"))]
impl AzureSdkClient {
    fn build_missing_feature_client() -> MissingFeatureClient {
        MissingFeatureClient {
            feature_name: "kms-azure",
        }
    }

    fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "kms-azure"))]
impl KmsDecryptClient for AzureSdkClient {
    fn decrypt(
        &self,
        key_resource: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        Self::build_missing_feature_client().decrypt(key_resource, ciphertext)
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

    struct MockClient {
        plaintext: Vec<u8>,
    }

    impl KmsDecryptClient for MockClient {
        fn decrypt(
            &self,
            _key_resource: &str,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
            Ok(self.plaintext.clone())
        }
    }

    #[test]
    fn holdout_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let labels = vec![0, 1, 1, 0, 1];
        let encrypted = encrypt_holdout_labels(&labels, &key).expect("encrypt");
        let decrypted = decrypt_holdout_labels(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, labels);
    }

    #[test]
    fn aws_provider_decrypts_key_material_with_mock_client() {
        let expected = [7u8; 32];
        let ref_value = format!(
            "arn:aws:kms:us-east-1:123456789012:key/x|{}",
            base64::engine::general_purpose::STANDARD.encode([1, 2, 3])
        );
        let provider = AwsKmsKeyProvider::with_client(Box::new(MockClient {
            plaintext: expected.to_vec(),
        }));

        let actual = provider.key_for_id(&ref_value).expect("kms key");
        assert_eq!(actual, expected);
    }

    #[test]
    fn kms_provider_rejects_invalid_key_ref() {
        let provider = GcpKmsKeyProvider::with_client(Box::new(MockClient {
            plaintext: vec![9; 32],
        }));
        let err = provider
            .key_for_id("missing-separator")
            .expect_err("invalid");
        assert!(matches!(err, HoldoutKeyProviderError::InvalidKeyId));
    }
}
