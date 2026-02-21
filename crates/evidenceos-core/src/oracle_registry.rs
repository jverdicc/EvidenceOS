use crate::aspec::AspecPolicy;
use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::oracle::{NullSpec, OracleResolution};
use crate::oracle_bundle::{Capability, OracleBundleManifestV1, TrustedOracleAuthorities};
use crate::oracle_wasm::{WasmOracleSandbox, WasmOracleSandboxPolicy};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub trait OracleBackend: Send {
    fn oracle_id(&self) -> &str;
    fn resolution(&self) -> &OracleResolution;
    fn null_spec(&self) -> &NullSpec;
    fn holdout_handle(&self) -> &str;
    fn query_raw_metric(&mut self, preds: &[u8]) -> EvidenceOSResult<f64>;
}

pub struct OracleRegistry {
    backends: BTreeMap<String, Box<dyn OracleBackend>>,
}

impl OracleRegistry {
    pub fn empty() -> Self {
        Self {
            backends: BTreeMap::new(),
        }
    }

    pub fn load_from_dir(
        path: &Path,
        trusted_keys: &TrustedOracleAuthorities,
        _aspec_policy: &AspecPolicy,
        sandbox_policy: WasmOracleSandboxPolicy,
    ) -> EvidenceOSResult<Self> {
        let mut backends: BTreeMap<String, Box<dyn OracleBackend>> = BTreeMap::new();
        if !path.exists() {
            return Ok(Self { backends });
        }
        for oracle_entry in fs::read_dir(path).map_err(|_| EvidenceOSError::OracleViolation)? {
            let oracle_entry = oracle_entry.map_err(|_| EvidenceOSError::OracleViolation)?;
            if !oracle_entry.path().is_dir() {
                continue;
            }
            for version_entry in
                fs::read_dir(oracle_entry.path()).map_err(|_| EvidenceOSError::OracleViolation)?
            {
                let version_entry = version_entry.map_err(|_| EvidenceOSError::OracleViolation)?;
                if !version_entry.path().is_dir() {
                    continue;
                }
                let manifest_path = version_entry.path().join("manifest.json");
                let wasm_path = version_entry.path().join("oracle.wasm");
                if !manifest_path.exists() || !wasm_path.exists() {
                    continue;
                }
                let manifest_bytes =
                    fs::read(&manifest_path).map_err(|_| EvidenceOSError::OracleViolation)?;
                let manifest: OracleBundleManifestV1 = serde_json::from_slice(&manifest_bytes)
                    .map_err(|_| EvidenceOSError::OracleViolation)?;
                manifest.verify_signature(trusted_keys)?;
                if manifest.kind != "wasm" || manifest.interface_version != 1 {
                    return Err(EvidenceOSError::OracleViolation);
                }
                if !manifest
                    .capabilities
                    .iter()
                    .all(|cap| matches!(cap, Capability::OracleQuery))
                {
                    return Err(EvidenceOSError::OracleViolation);
                }
                let wasm = fs::read(&wasm_path).map_err(|_| EvidenceOSError::OracleViolation)?;
                let digest = Sha256::digest(&wasm);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&digest);
                if hash != manifest.wasm_sha256 {
                    return Err(EvidenceOSError::OracleViolation);
                }
                let sandbox = WasmOracleSandbox::new(&wasm, sandbox_policy.clone())?;
                let backend = WasmOracleBackend {
                    manifest: manifest.clone(),
                    sandbox,
                };
                backends.insert(manifest.oracle_id.clone(), Box::new(backend));
            }
        }
        Ok(Self { backends })
    }

    pub fn register_backend(&mut self, backend: Box<dyn OracleBackend>) {
        self.backends
            .insert(backend.oracle_id().to_owned(), backend);
    }

    pub fn get(&self, oracle_id: &str) -> Option<&dyn OracleBackend> {
        self.backends.get(oracle_id).map(std::boxed::Box::as_ref)
    }

    pub fn get_mut(&mut self, oracle_id: &str) -> Option<&mut dyn OracleBackend> {
        if let Some(backend) = self.backends.get_mut(oracle_id) {
            Some(backend.as_mut())
        } else {
            None
        }
    }

    pub fn oracle_ids(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }
}

struct WasmOracleBackend {
    manifest: OracleBundleManifestV1,
    sandbox: WasmOracleSandbox,
}

impl OracleBackend for WasmOracleBackend {
    fn oracle_id(&self) -> &str {
        &self.manifest.oracle_id
    }
    fn resolution(&self) -> &OracleResolution {
        &self.manifest.resolution
    }
    fn null_spec(&self) -> &NullSpec {
        &self.manifest.null_spec
    }
    fn holdout_handle(&self) -> &str {
        &self.manifest.holdout_handle
    }
    fn query_raw_metric(&mut self, preds: &[u8]) -> EvidenceOSResult<f64> {
        self.sandbox.query_raw_metric(preds)
    }
}
