use base64::Engine as _;
use evidenceos_core::holdout_crypto::{
    AwsKmsKeyProvider, GcpKmsKeyProvider, HoldoutKeyProvider, HoldoutKeyProviderError,
    KmsDecryptClient,
};

struct MockDecryptClient {
    plaintext: Vec<u8>,
}

impl KmsDecryptClient for MockDecryptClient {
    fn decrypt(
        &self,
        _key_resource: &str,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, HoldoutKeyProviderError> {
        Ok(self.plaintext.clone())
    }
}

#[test]
fn aws_kms_provider_supports_mocked_client_roundtrip() {
    let key_ref = format!(
        "arn:aws:kms:us-east-1:123456789012:key/id|{}",
        base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4])
    );
    let provider = AwsKmsKeyProvider::with_client(Box::new(MockDecryptClient {
        plaintext: vec![3u8; 32],
    }));

    let key = provider.key_for_id(&key_ref).expect("key");
    assert_eq!(key, [3u8; 32]);
}

#[test]
fn gcp_kms_provider_rejects_malformed_ref() {
    let provider = GcpKmsKeyProvider::with_client(Box::new(MockDecryptClient {
        plaintext: vec![3u8; 32],
    }));

    let err = provider
        .key_for_id("malformed")
        .expect_err("invalid key ref");
    assert!(matches!(err, HoldoutKeyProviderError::InvalidKeyId));
}
