use base64::Engine as _;
use evidenceos_daemon::key_management::{
    AwsKmsProvider, GcpKmsProvider, KmsDecryptClient, KmsSigningKeyProvider,
};
use tonic::Code;

struct MockDecryptClient {
    plaintext: Vec<u8>,
}

impl KmsDecryptClient for MockDecryptClient {
    fn decrypt(&self, _key_resource: &str, _ciphertext: &[u8]) -> Result<Vec<u8>, tonic::Status> {
        Ok(self.plaintext.clone())
    }
}

#[test]
fn aws_kms_provider_loads_signing_key_from_mocked_client() {
    let key_ref = format!(
        "arn:aws:kms:us-east-1:123456789012:key/id|{}",
        base64::engine::general_purpose::STANDARD.encode([9u8, 8, 7])
    );
    let provider = AwsKmsProvider::with_client(Box::new(MockDecryptClient {
        plaintext: vec![0xAB; 32],
    }));

    let signing_key = provider
        .load_signing_key(Some(&key_ref))
        .expect("signing key");
    assert_eq!(signing_key.to_bytes(), [0xAB; 32]);
}

#[test]
fn gcp_kms_provider_rejects_bad_key_ref() {
    let provider = GcpKmsProvider::with_client(Box::new(MockDecryptClient {
        plaintext: vec![0xAB; 32],
    }));

    let err = provider
        .load_signing_key(Some("bad-format"))
        .expect_err("should fail");
    assert_eq!(err.code(), Code::FailedPrecondition);
}
