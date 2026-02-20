use evidenceos_core::oracle_bundle::TrustedOracleAuthorities;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub preflight_http_listen: Option<String>,
    pub preflight_max_body_bytes: usize,
    pub preflight_require_bearer_token: Option<String>,
    pub preflight_fail_open_for_low_risk: bool,
    pub preflight_high_risk_tools: Vec<String>,
    pub preflight_timeout_ms: u64,
    pub preflight_rate_limit_rps: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            preflight_http_listen: None,
            preflight_max_body_bytes: 16_384,
            preflight_require_bearer_token: None,
            preflight_fail_open_for_low_risk: true,
            preflight_high_risk_tools: vec![
                "exec".to_string(),
                "shell.exec".to_string(),
                "fs.write".to_string(),
                "fs.delete_tree".to_string(),
                "email.send".to_string(),
                "payment.charge".to_string(),
            ],
            preflight_timeout_ms: 120,
            preflight_rate_limit_rps: 50,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DaemonOracleConfig {
    pub oracle_dir: PathBuf,
    pub trusted_authorities: TrustedOracleAuthorities,
    pub oracle_plusplus_backends: Vec<evidenceos_core::oracle_plusplus::OraclePlusPlusConfig>,
    pub nullspec_registry_dir: PathBuf,
    pub trusted_nullspec_keys_dir: PathBuf,
    pub default_nullspec_id: String,
    pub allow_fixed_e_value_in_dev: bool,
}

#[derive(Debug, Deserialize)]
struct TrustedKeysFile {
    pub keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleTtlPolicy {
    RejectExpired,
    EscalateToHeavy,
}

impl OracleTtlPolicy {
    pub fn from_env() -> Self {
        match std::env::var("EVIDENCEOS_ORACLE_TTL_POLICY") {
            Ok(v) if v.eq_ignore_ascii_case("escalate_to_heavy") => Self::EscalateToHeavy,
            _ => Self::RejectExpired,
        }
    }
}

impl DaemonOracleConfig {
    pub fn load(
        oracle_dir: impl AsRef<Path>,
        trusted_keys_path: Option<impl AsRef<Path>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let trusted_authorities = if let Some(path) = trusted_keys_path {
            let payload = fs::read(path)?;
            let file: TrustedKeysFile = serde_json::from_slice(&payload)?;
            let mut out = TrustedOracleAuthorities::default();
            for (kid, key_hex) in file.keys {
                out.keys.insert(kid, hex::decode(key_hex)?);
            }
            out
        } else {
            TrustedOracleAuthorities::default()
        };

        Ok(Self {
            oracle_dir: oracle_dir.as_ref().to_path_buf(),
            trusted_authorities,
            oracle_plusplus_backends: Vec::new(),
            nullspec_registry_dir: PathBuf::from("./nullspec-registry"),
            trusted_nullspec_keys_dir: PathBuf::from("./trusted-nullspec-keys"),
            default_nullspec_id: String::new(),
            allow_fixed_e_value_in_dev: false,
        })
    }
}
