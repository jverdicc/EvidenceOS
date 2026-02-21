use ed25519_dalek::SigningKey;
use tonic::Status;

pub const KEY_PROVIDER_ENV: &str = "EVIDENCEOS_KEY_PROVIDER";
pub const KMS_PROVIDER_ENV: &str = "EVIDENCEOS_KMS_PROVIDER";
pub const KMS_MOCK_KEY_HEX_ENV: &str = "EVIDENCEOS_KMS_MOCK_KEY_HEX";
pub const KMS_KEY_ID_ENV: &str = "EVIDENCEOS_KMS_KEY_ID";

pub trait KmsSigningKeyProvider {
    fn load_signing_key(&self, key_id: Option<&str>) -> Result<SigningKey, Status>;
}

pub enum SigningKeySource {
    File,
    Kms,
}

impl SigningKeySource {
    pub fn from_env() -> Result<Self, Status> {
        match std::env::var(KEY_PROVIDER_ENV) {
            Ok(value) if value.eq_ignore_ascii_case("kms") => Ok(Self::Kms),
            Ok(value) if value.eq_ignore_ascii_case("file") => Ok(Self::File),
            Ok(_) => Err(Status::failed_precondition(
                "invalid key provider; expected file or kms",
            )),
            Err(_) => Ok(Self::File),
        }
    }
}

pub fn load_signing_key_from_kms() -> Result<SigningKey, Status> {
    let provider = std::env::var(KMS_PROVIDER_ENV).map_err(|_| {
        Status::failed_precondition("kms provider is required when key provider=kms")
    })?;
    let key_id = std::env::var(KMS_KEY_ID_ENV).ok();
    provider_for_name(&provider)?.load_signing_key(key_id.as_deref())
}

fn provider_for_name(provider: &str) -> Result<Box<dyn KmsSigningKeyProvider>, Status> {
    if provider.eq_ignore_ascii_case("mock") {
        return Ok(Box::new(MockKmsProvider));
    }
    if provider.eq_ignore_ascii_case("aws") {
        return Ok(Box::new(AwsKmsProvider));
    }
    if provider.eq_ignore_ascii_case("gcp") {
        return Ok(Box::new(GcpKmsProvider));
    }
    if provider.eq_ignore_ascii_case("azure") {
        return Ok(Box::new(AzureKmsProvider));
    }

    Err(Status::failed_precondition(
        "invalid kms provider; expected mock, aws, gcp, or azure",
    ))
}

struct MockKmsProvider;

impl KmsSigningKeyProvider for MockKmsProvider {
    fn load_signing_key(&self, _key_id: Option<&str>) -> Result<SigningKey, Status> {
        let value = std::env::var(KMS_MOCK_KEY_HEX_ENV)
            .map_err(|_| Status::failed_precondition("mock kms key env is missing"))?;
        let bytes = hex::decode(value)
            .map_err(|_| Status::failed_precondition("mock kms key must be valid hex"))?;
        if bytes.len() != 32 {
            return Err(Status::failed_precondition(
                "mock kms key must decode to 32 bytes",
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&seed))
    }
}

struct AwsKmsProvider;

impl KmsSigningKeyProvider for AwsKmsProvider {
    fn load_signing_key(&self, _key_id: Option<&str>) -> Result<SigningKey, Status> {
        Err(Status::unimplemented(
            "aws kms signing provider hook is not yet implemented",
        ))
    }
}

struct GcpKmsProvider;

impl KmsSigningKeyProvider for GcpKmsProvider {
    fn load_signing_key(&self, _key_id: Option<&str>) -> Result<SigningKey, Status> {
        Err(Status::unimplemented(
            "gcp kms signing provider hook is not yet implemented",
        ))
    }
}

struct AzureKmsProvider;

impl KmsSigningKeyProvider for AzureKmsProvider {
    fn load_signing_key(&self, _key_id: Option<&str>) -> Result<SigningKey, Status> {
        Err(Status::unimplemented(
            "azure key vault signing provider hook is not yet implemented",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_source_defaults_to_file() {
        unsafe {
            std::env::remove_var(KEY_PROVIDER_ENV);
        }
        let source = SigningKeySource::from_env().expect("source");
        assert!(matches!(source, SigningKeySource::File));
    }

    #[test]
    fn mock_kms_loads_signing_key() {
        unsafe {
            std::env::set_var(KMS_PROVIDER_ENV, "mock");
            std::env::set_var(KMS_MOCK_KEY_HEX_ENV, "11".repeat(32));
        }

        let key = load_signing_key_from_kms().expect("kms key");
        assert_eq!(key.to_bytes().len(), 32);

        unsafe {
            std::env::remove_var(KMS_PROVIDER_ENV);
            std::env::remove_var(KMS_MOCK_KEY_HEX_ENV);
        }
    }
}
