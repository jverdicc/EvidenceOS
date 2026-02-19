use evidenceos_core::oracle_bundle::TrustedOracleAuthorities;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DaemonOracleConfig {
    pub oracle_dir: PathBuf,
    pub trusted_authorities: TrustedOracleAuthorities,
}

#[derive(Debug, Deserialize)]
struct TrustedKeysFile {
    pub keys: BTreeMap<String, String>,
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
        })
    }
}
