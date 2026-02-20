//! TEE integration placeholder interfaces.

pub trait TeeAttestor: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn attest_measurement(&self, measurement: &[u8]) -> Result<Vec<u8>, TeeError>;
}

#[derive(Debug)]
pub enum TeeError {
    Unsupported,
    InvalidInput,
    BackendFailure,
}
