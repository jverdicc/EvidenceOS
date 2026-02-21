//! TEE attestation backends.

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};

pub trait TeeAttestor: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn attest_measurement(&self, measurement: &[u8]) -> Result<Vec<u8>, TeeError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeAttestation {
    pub backend_name: String,
    pub measurement_hex: String,
    pub attestation_blob_b64: String,
}

pub fn measurement_sha256_hex(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    hex::encode(h.finalize())
}

pub fn collect_attestation(
    attestor: &dyn TeeAttestor,
    measurement: &[u8],
) -> Result<TeeAttestation, TeeError> {
    if measurement.is_empty() {
        return Err(TeeError::InvalidInput("measurement is empty".to_string()));
    }
    let blob = attestor.attest_measurement(measurement)?;
    if blob.is_empty() {
        return Err(TeeError::BackendFailure(
            "backend returned empty attestation blob".to_string(),
        ));
    }
    Ok(TeeAttestation {
        backend_name: attestor.backend_name().to_string(),
        measurement_hex: measurement_sha256_hex(measurement),
        attestation_blob_b64: base64::engine::general_purpose::STANDARD.encode(blob),
    })
}

#[derive(Debug)]
pub enum TeeBackend {
    Disabled,
    Noop,
    AmdSevSnp,
}

impl TeeBackend {
    pub fn from_env() -> Result<Self, TeeError> {
        let backend =
            std::env::var("EVIDENCEOS_TEE_BACKEND").unwrap_or_else(|_| "disabled".to_string());
        match backend.to_ascii_lowercase().as_str() {
            "" | "disabled" | "none" => Ok(Self::Disabled),
            "noop" => Ok(Self::Noop),
            "amd-sev-snp" | "sev-snp" => Ok(Self::AmdSevSnp),
            _ => Err(TeeError::InvalidInput(format!(
                "unsupported tee backend: {backend}"
            ))),
        }
    }
}

pub fn attestor_from_env() -> Result<Option<Box<dyn TeeAttestor>>, TeeError> {
    match TeeBackend::from_env()? {
        TeeBackend::Disabled => Ok(None),
        TeeBackend::Noop => {
            let allow_noop = std::env::var("EVIDENCEOS_TEE_ALLOW_NOOP")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow_noop {
                return Err(TeeError::NoopNotAllowed);
            }
            Ok(Some(Box::new(NoopAttestor)))
        }
        TeeBackend::AmdSevSnp => Ok(Some(Box::new(AmdSevSnpAttestor::default()))),
    }
}

#[derive(Debug, Default)]
pub struct NoopAttestor;

impl TeeAttestor for NoopAttestor {
    fn backend_name(&self) -> &'static str {
        "noop"
    }

    fn attest_measurement(&self, measurement: &[u8]) -> Result<Vec<u8>, TeeError> {
        if measurement.is_empty() {
            return Err(TeeError::InvalidInput("measurement is empty".to_string()));
        }
        let mut payload = b"NOOP_ATTESTATION_DO_NOT_USE_IN_PRODUCTION:".to_vec();
        payload.extend_from_slice(measurement);
        Ok(payload)
    }
}

#[derive(Debug, Clone)]
pub struct AmdSevSnpAttestor {
    helper_path: String,
}

impl Default for AmdSevSnpAttestor {
    fn default() -> Self {
        Self {
            helper_path: std::env::var("EVIDENCEOS_SEV_SNP_HELPER")
                .unwrap_or_else(|_| "/usr/local/bin/evidenceos-sev-snp-attest".to_string()),
        }
    }
}

impl TeeAttestor for AmdSevSnpAttestor {
    fn backend_name(&self) -> &'static str {
        "amd-sev-snp"
    }

    fn attest_measurement(&self, measurement: &[u8]) -> Result<Vec<u8>, TeeError> {
        if measurement.is_empty() {
            return Err(TeeError::InvalidInput("measurement is empty".to_string()));
        }
        let measurement_hex = measurement_sha256_hex(measurement);
        let output = Command::new(&self.helper_path)
            .arg("--report-data")
            .arg(&measurement_hex)
            .output()
            .map_err(|_| {
                TeeError::BackendFailure("failed to execute sev-snp helper".to_string())
            })?;
        if !output.status.success() {
            return Err(TeeError::BackendFailure(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        if output.stdout.is_empty() {
            return Err(TeeError::BackendFailure(
                "sev-snp helper returned empty report".to_string(),
            ));
        }
        Ok(output.stdout)
    }
}

#[derive(Debug)]
pub enum TeeError {
    Unsupported,
    InvalidInput(String),
    BackendFailure(String),
    NoopNotAllowed,
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[test]
    fn noop_attestor_requires_explicit_opt_in() {
        let _env_lock = env_lock();
        let _guard = EnvGuard::new();
        std::env::set_var("EVIDENCEOS_TEE_BACKEND", "noop");
        std::env::remove_var("EVIDENCEOS_TEE_ALLOW_NOOP");
        assert!(matches!(attestor_from_env(), Err(TeeError::NoopNotAllowed)));
    }

    #[test]
    fn noop_attestor_opt_in_works() {
        let _env_lock = env_lock();
        let _guard = EnvGuard::new();
        std::env::set_var("EVIDENCEOS_TEE_BACKEND", "noop");
        std::env::set_var("EVIDENCEOS_TEE_ALLOW_NOOP", "1");
        let attestor = attestor_from_env()
            .expect("backend should parse")
            .expect("attestor should exist");
        let report =
            collect_attestation(attestor.as_ref(), b"abc").expect("attestation should work");
        assert_eq!(report.backend_name, "noop");
        assert_eq!(report.measurement_hex, measurement_sha256_hex(b"abc"));
        assert!(!report.attestation_blob_b64.is_empty());
    }

    struct EnvGuard {
        backend: Option<String>,
        allow_noop: Option<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self {
                backend: std::env::var("EVIDENCEOS_TEE_BACKEND").ok(),
                allow_noop: std::env::var("EVIDENCEOS_TEE_ALLOW_NOOP").ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.backend {
                Some(v) => std::env::set_var("EVIDENCEOS_TEE_BACKEND", v),
                None => std::env::remove_var("EVIDENCEOS_TEE_BACKEND"),
            }
            match &self.allow_noop {
                Some(v) => std::env::set_var("EVIDENCEOS_TEE_ALLOW_NOOP", v),
                None => std::env::remove_var("EVIDENCEOS_TEE_ALLOW_NOOP"),
            }
        }
    }
}
