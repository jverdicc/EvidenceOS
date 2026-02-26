use base64::Engine as _;
use ed25519_dalek::SigningKey;
use tonic::Status;

pub const KEY_PROVIDER_ENV: &str = "EVIDENCEOS_KEY_PROVIDER";
pub const KMS_PROVIDER_ENV: &str = "EVIDENCEOS_KMS_PROVIDER";
pub const KMS_MOCK_KEY_HEX_ENV: &str = "EVIDENCEOS_KMS_MOCK_KEY_HEX";
pub const KMS_KEY_ID_ENV: &str = "EVIDENCEOS_KMS_KEY_ID";
const MAX_KMS_KEY_REF_LEN: usize = 4096;

pub trait KmsSigningKeyProvider {
    fn load_signing_key(&self, key_id: Option<&str>) -> Result<SigningKey, Status>;
}

pub trait KmsDecryptClient: Send + Sync {
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status>;
}

pub enum SigningKeySource {
    File,
    Kms,
}

impl SigningKeySource {
    pub fn from_env() -> Result<Self, Status> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Result<Self, Status> {
        match get(KEY_PROVIDER_ENV) {
            Some(value) if value.eq_ignore_ascii_case("kms") => Ok(Self::Kms),
            Some(value) if value.eq_ignore_ascii_case("file") => Ok(Self::File),
            Some(_) => Err(Status::failed_precondition(
                "invalid key provider; expected file or kms",
            )),
            None => Ok(Self::File),
        }
    }
}

pub fn load_signing_key_from_kms() -> Result<SigningKey, Status> {
    load_signing_key_source_with(|name| std::env::var(name).ok())
}

pub fn load_signing_key_source_with(
    get: impl Fn(&str) -> Option<String>,
) -> Result<SigningKey, Status> {
    let provider = get(KMS_PROVIDER_ENV).ok_or_else(|| {
        Status::failed_precondition("kms provider is required when key provider=kms")
    })?;
    if provider.eq_ignore_ascii_case("mock") {
        let value = get(KMS_MOCK_KEY_HEX_ENV)
            .ok_or_else(|| Status::failed_precondition("mock kms key env is missing"))?;
        return signing_key_from_hex(&value);
    }
    let key_id = get(KMS_KEY_ID_ENV);
    provider_for_name(&provider)?.load_signing_key(key_id.as_deref())
}

fn signing_key_from_hex(value: &str) -> Result<SigningKey, Status> {
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

fn provider_for_name(provider: &str) -> Result<Box<dyn KmsSigningKeyProvider>, Status> {
    if provider.eq_ignore_ascii_case("mock") {
        return Ok(Box::new(MockKmsProvider));
    }
    if provider.eq_ignore_ascii_case("aws") {
        return Ok(Box::new(AwsKmsProvider::new()));
    }
    if provider.eq_ignore_ascii_case("gcp") {
        return Ok(Box::new(GcpKmsProvider::new()));
    }
    if provider.eq_ignore_ascii_case("azure") {
        return Ok(Box::new(AzureKmsProvider::new()));
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
        signing_key_from_hex(&value)
    }
}

struct MissingFeatureClient {
    feature_name: &'static str,
}

impl KmsDecryptClient for MissingFeatureClient {
    fn decrypt(&self, _key_resource: &str, _ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
        Err(Status::failed_precondition(format!(
            "kms feature is disabled for provider; enable {}",
            self.feature_name
        )))
    }
}

pub struct AwsKmsProvider {
    client: Box<dyn KmsDecryptClient>,
}

impl Default for AwsKmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsKmsProvider {
    pub fn new() -> Self {
        Self {
            client: Box::new(AwsSdkClient::new()),
        }
    }

    pub fn with_client(client: Box<dyn KmsDecryptClient>) -> Self {
        Self { client }
    }
}

impl KmsSigningKeyProvider for AwsKmsProvider {
    fn load_signing_key(&self, key_id: Option<&str>) -> Result<SigningKey, Status> {
        decrypt_signing_key(&*self.client, key_id)
    }
}

pub struct GcpKmsProvider {
    client: Box<dyn KmsDecryptClient>,
}

impl Default for GcpKmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpKmsProvider {
    pub fn new() -> Self {
        Self {
            client: Box::new(GcpSdkClient::new()),
        }
    }

    pub fn with_client(client: Box<dyn KmsDecryptClient>) -> Self {
        Self { client }
    }
}

impl KmsSigningKeyProvider for GcpKmsProvider {
    fn load_signing_key(&self, key_id: Option<&str>) -> Result<SigningKey, Status> {
        decrypt_signing_key(&*self.client, key_id)
    }
}

pub struct AzureKmsProvider {
    client: Box<dyn KmsDecryptClient>,
}

impl Default for AzureKmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AzureKmsProvider {
    pub fn new() -> Self {
        Self {
            client: Box::new(AzureSdkClient::new()),
        }
    }

    pub fn with_client(client: Box<dyn KmsDecryptClient>) -> Self {
        Self { client }
    }
}

impl KmsSigningKeyProvider for AzureKmsProvider {
    fn load_signing_key(&self, key_id: Option<&str>) -> Result<SigningKey, Status> {
        decrypt_signing_key(&*self.client, key_id)
    }
}

fn decrypt_signing_key(
    client: &dyn KmsDecryptClient,
    key_id: Option<&str>,
) -> Result<SigningKey, Status> {
    let key_ref = key_id.ok_or_else(|| {
        Status::failed_precondition("kms key id must be set when key provider=kms")
    })?;
    let (key_resource, ciphertext) = parse_kms_key_ref(key_ref)?;
    let plaintext = client.decrypt(key_resource, &ciphertext)?;
    if plaintext.len() != 32 {
        return Err(Status::failed_precondition(
            "kms plaintext must decode to 32 bytes",
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(SigningKey::from_bytes(&seed))
}

fn parse_kms_key_ref(key_ref: &str) -> Result<(&str, Vec<u8>), Status> {
    if key_ref.is_empty() || key_ref.len() > MAX_KMS_KEY_REF_LEN {
        return Err(Status::failed_precondition("invalid kms key id format"));
    }
    let (resource, ciphertext_b64) = key_ref
        .split_once('|')
        .ok_or_else(|| Status::failed_precondition("invalid kms key id format"))?;
    if resource.is_empty() || ciphertext_b64.is_empty() {
        return Err(Status::failed_precondition("invalid kms key id format"));
    }
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| Status::failed_precondition("kms key ciphertext must be valid base64"))?;
    if ciphertext.is_empty() {
        return Err(Status::failed_precondition(
            "kms key ciphertext must be non-empty",
        ));
    }
    Ok((resource, ciphertext))
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
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| Status::internal("unable to initialize runtime for aws kms"))?;
        runtime.block_on(async {
            let config = aws_config::load_from_env().await;
            let client = aws_sdk_kms::Client::new(&config);
            let out = client
                .decrypt()
                .key_id(key_resource)
                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext.to_vec()))
                .send()
                .await
                .map_err(|_| Status::permission_denied("aws kms decrypt failed"))?;
            out.plaintext()
                .map(|blob| blob.as_ref().to_vec())
                .ok_or_else(|| Status::permission_denied("aws kms returned empty plaintext"))
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
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
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
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| Status::internal("unable to initialize runtime for gcp kms"))?;
        runtime.block_on(async {
            let config = google_cloud_kms::client::ClientConfig::default()
                .with_auth()
                .await
                .map_err(|_| Status::permission_denied("gcp kms auth initialization failed"))?;
            let client = google_cloud_kms::client::Client::new(config)
                .await
                .map_err(|_| Status::permission_denied("gcp kms client initialization failed"))?;
            let req = google_cloud_googleapis::cloud::kms::v1::DecryptRequest {
                name: key_resource.to_string(),
                ciphertext: ciphertext.to_vec(),
                ..Default::default()
            };
            let out = client
                .decrypt(req)
                .await
                .map_err(|_| Status::permission_denied("gcp kms decrypt failed"))?;
            if out.plaintext.is_empty() {
                return Err(Status::permission_denied(
                    "gcp kms returned empty plaintext",
                ));
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
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
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
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| Status::internal("unable to initialize runtime for azure key vault"))?;
        runtime.block_on(async {
            let credential = azure_identity::DefaultAzureCredential::default();
            let client = azure_security_keyvault_keys::CryptographyClient::new(
                key_resource,
                credential,
                None,
            )
            .map_err(|_| Status::permission_denied("azure key vault client init failed"))?;
            let out = client
                .unwrap_key(
                    azure_security_keyvault_keys::models::KeyEncryptionAlgorithm::RsaOaep256,
                    ciphertext.to_vec(),
                    None,
                )
                .await
                .map_err(|_| Status::permission_denied("azure key vault unwrap failed"))?;
            out.result.value.ok_or_else(|| {
                Status::permission_denied("azure key vault returned empty plaintext")
            })
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
    fn decrypt(&self, key_resource: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
        Self::build_missing_feature_client().decrypt(key_resource, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDecryptClient {
        plaintext: Vec<u8>,
    }

    impl KmsDecryptClient for MockDecryptClient {
        fn decrypt(&self, _key_resource: &str, _ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
            Ok(self.plaintext.clone())
        }
    }

    #[test]
    fn key_source_defaults_to_file() {
        let env = std::collections::HashMap::<String, String>::new();
        let source = SigningKeySource::from_env_with(|key| env.get(key).cloned()).expect("source");
        assert!(matches!(source, SigningKeySource::File));
    }

    #[test]
    fn mock_kms_loads_signing_key() {
        let env = std::collections::HashMap::from([
            (KMS_PROVIDER_ENV.to_string(), "mock".to_string()),
            (KMS_MOCK_KEY_HEX_ENV.to_string(), "11".repeat(32)),
        ]);

        let key = load_signing_key_source_with(|key| env.get(key).cloned()).expect("kms key");
        assert_eq!(key.to_bytes().len(), 32);
    }

    #[test]
    fn aws_provider_decrypts_signing_key_with_mock_client() {
        let key_ref = format!(
            "arn:aws:kms:us-east-1:123456789012:key/x|{}",
            base64::engine::general_purpose::STANDARD.encode([1, 2, 3, 4])
        );
        let provider = AwsKmsProvider::with_client(Box::new(MockDecryptClient {
            plaintext: vec![9; 32],
        }));

        let key = provider.load_signing_key(Some(&key_ref)).expect("kms key");
        assert_eq!(key.to_bytes(), [9; 32]);
    }

    #[test]
    fn gcp_provider_rejects_invalid_kms_key_format() {
        let provider = GcpKmsProvider::with_client(Box::new(MockDecryptClient {
            plaintext: vec![9; 32],
        }));

        let err = provider
            .load_signing_key(Some("invalid-format"))
            .expect_err("invalid");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}
