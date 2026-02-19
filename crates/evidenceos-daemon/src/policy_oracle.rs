#![allow(clippy::result_large_err)]

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evidenceos_core::capsule::{canonical_json, PolicyOracleReceiptLike};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tonic::Status;
use wasmtime::{
    Config, Engine, ExternType, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc, ValType,
};

const POLICY_ORACLE_SCHEMA: &str = "evidenceos.v1.policy_oracle_manifest";
const TRUSTED_KEYS_FILENAME: &str = "trusted_keys.json";
const REASON_CODE_MIN: u32 = 9000;
const REASON_CODE_MAX: u32 = 9999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOracleDecision {
    Pass,
    DeferToHeavy,
    Reject,
}

impl PolicyOracleDecision {
    fn from_code(code: i32) -> Result<Self, Status> {
        match code {
            0 => Ok(Self::Pass),
            1 => Ok(Self::DeferToHeavy),
            2 => Ok(Self::Reject),
            _ => Err(Status::failed_precondition("policy oracle failure")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::DeferToHeavy => "defer",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyOracleReceipt {
    pub oracle_id: String,
    pub manifest_hash_hex: String,
    pub wasm_hash_hex: String,
    pub decision: String,
    pub reason_code: u32,
}

impl From<PolicyOracleReceipt> for PolicyOracleReceiptLike {
    fn from(value: PolicyOracleReceipt) -> Self {
        Self {
            oracle_id: value.oracle_id,
            manifest_hash_hex: value.manifest_hash_hex,
            wasm_hash_hex: value.wasm_hash_hex,
            decision: value.decision,
            reason_code: value.reason_code,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOracleManifest {
    pub schema: String,
    pub oracle_id: String,
    pub vendor: String,
    pub version: String,
    pub description: String,
    pub wasm_filename: String,
    pub wasm_sha256_hex: String,
    pub reason_code: u32,
    pub decision_mode: String,
    pub max_fuel: u64,
    pub max_memory_bytes: u64,
    pub max_input_bytes: u32,
    pub require_signature: bool,
    pub signer_pubkey_ed25519_hex: Option<String>,
    pub signature_ed25519_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TrustedKeys {
    trusted_ed25519_pubkeys_hex: Vec<String>,
}

#[derive(Clone)]
pub struct PolicyOracleEngine {
    engine: Engine,
    module: Module,
    pub manifest: PolicyOracleManifest,
    wasm_hash: [u8; 32],
    manifest_hash: [u8; 32],
}

#[derive(Debug)]
struct OracleStoreData {
    limits: StoreLimits,
}

impl PolicyOracleEngine {
    pub fn load_from_dir(dir: &Path) -> Result<Vec<PolicyOracleEngine>, Status> {
        let trusted = load_trusted_keys(dir)?;
        let mut manifests: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "json")
                    && path.file_name().and_then(|f| f.to_str()) != Some(TRUSTED_KEYS_FILENAME)
            })
            .collect();
        manifests.sort();

        let mut loaded = Vec::new();
        for manifest_path in manifests {
            loaded.push(Self::load_one(dir, &manifest_path, &trusted)?);
        }
        Ok(loaded)
    }

    fn load_one(
        dir: &Path,
        manifest_path: &Path,
        trusted: &TrustedKeys,
    ) -> Result<PolicyOracleEngine, Status> {
        enforce_secure_file_permissions(manifest_path)?;
        let manifest_bytes = fs::read(manifest_path)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        let manifest: PolicyOracleManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        validate_manifest(&manifest, trusted)?;

        let wasm_path = dir.join(&manifest.wasm_filename);
        enforce_secure_file_permissions(&wasm_path)?;
        let wasm = fs::read(&wasm_path)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        let wasm_hash = sha256_array(&wasm);
        if hex::encode(wasm_hash) != manifest.wasm_sha256_hex.to_lowercase() {
            return Err(Status::failed_precondition("policy oracle failure"));
        }

        let manifest_hash = sha256_array(&canonical_manifest_bytes(&manifest, false)?);

        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.cranelift_nan_canonicalization(true);
        cfg.wasm_simd(false);
        cfg.wasm_relaxed_simd(false);
        cfg.wasm_multi_memory(false);
        cfg.wasm_memory64(false);

        let engine =
            Engine::new(&cfg).map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        let module = Module::new(&engine, &wasm)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        validate_module_exports(&module)?;

        tracing::info!(
            oracle_id = %manifest.oracle_id,
            version = %manifest.version,
            "loaded policy oracle"
        );

        Ok(Self {
            engine,
            module,
            manifest,
            wasm_hash,
            manifest_hash,
        })
    }

    pub fn evaluate(
        &self,
        input: &[u8],
    ) -> Result<(PolicyOracleDecision, PolicyOracleReceipt), Status> {
        if input.len() > self.manifest.max_input_bytes as usize {
            return Err(Status::failed_precondition("policy oracle failure"));
        }

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.manifest.max_memory_bytes as usize)
            .table_elements(0)
            .tables(0)
            .build();
        let mut store = Store::new(
            &self.engine,
            OracleStoreData {
                limits: store_limits,
            },
        );
        store.limiter(|data| &mut data.limits);
        store
            .set_fuel(self.manifest.max_fuel)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;

        let linker = Linker::<OracleStoreData>::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;

        let memory = get_memory(&mut store, &instance)?;
        let alloc = get_func_i32_to_i32(&mut store, &instance, "alloc")?;
        let decide = get_func_i32_i32_to_i32(&mut store, &instance, "policy_oracle_decide")?;

        let len = i32::try_from(input.len())
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        let ptr = alloc
            .call(&mut store, len)
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        write_input_to_memory(&mut store, &memory, ptr, input)?;

        let raw = decide
            .call(&mut store, (ptr, len))
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        let decision = PolicyOracleDecision::from_code(raw)?;

        Ok((
            decision,
            PolicyOracleReceipt {
                oracle_id: self.manifest.oracle_id.clone(),
                manifest_hash_hex: hex::encode(self.manifest_hash),
                wasm_hash_hex: hex::encode(self.wasm_hash),
                decision: decision.as_str().to_string(),
                reason_code: self.manifest.reason_code,
            },
        ))
    }

    pub fn fail_closed_receipt(&self) -> PolicyOracleReceipt {
        PolicyOracleReceipt {
            oracle_id: self.manifest.oracle_id.clone(),
            manifest_hash_hex: hex::encode(self.manifest_hash),
            wasm_hash_hex: hex::encode(self.wasm_hash),
            decision: PolicyOracleDecision::DeferToHeavy.as_str().to_string(),
            reason_code: self.manifest.reason_code,
        }
    }
}

fn get_memory(store: &mut Store<OracleStoreData>, instance: &Instance) -> Result<Memory, Status> {
    instance
        .get_memory(store, "memory")
        .ok_or_else(|| Status::failed_precondition("policy oracle failure"))
}

fn get_func_i32_to_i32(
    store: &mut Store<OracleStoreData>,
    instance: &Instance,
    name: &str,
) -> Result<TypedFunc<i32, i32>, Status> {
    instance
        .get_typed_func::<i32, i32>(store, name)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))
}

fn get_func_i32_i32_to_i32(
    store: &mut Store<OracleStoreData>,
    instance: &Instance,
    name: &str,
) -> Result<TypedFunc<(i32, i32), i32>, Status> {
    instance
        .get_typed_func::<(i32, i32), i32>(store, name)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))
}

fn write_input_to_memory(
    store: &mut Store<OracleStoreData>,
    memory: &Memory,
    ptr: i32,
    input: &[u8],
) -> Result<(), Status> {
    let start =
        usize::try_from(ptr).map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    let end = start
        .checked_add(input.len())
        .ok_or_else(|| Status::failed_precondition("policy oracle failure"))?;
    if end > memory.data_size(&mut *store) {
        return Err(Status::failed_precondition("policy oracle failure"));
    }
    memory
        .write(store, start, input)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))
}

fn validate_manifest(manifest: &PolicyOracleManifest, trusted: &TrustedKeys) -> Result<(), Status> {
    if manifest.schema != POLICY_ORACLE_SCHEMA
        || manifest.oracle_id.is_empty()
        || manifest.wasm_filename.is_empty()
        || manifest.decision_mode != "veto_only"
        || manifest.max_fuel == 0
        || manifest.max_memory_bytes == 0
        || manifest.max_input_bytes == 0
    {
        return Err(Status::failed_precondition("policy oracle failure"));
    }
    if !(REASON_CODE_MIN..=REASON_CODE_MAX).contains(&manifest.reason_code) {
        return Err(Status::failed_precondition("policy oracle failure"));
    }

    if manifest.wasm_filename.contains("..") || Path::new(&manifest.wasm_filename).is_absolute() {
        return Err(Status::failed_precondition("policy oracle failure"));
    }

    if let Some(signer) = &manifest.signer_pubkey_ed25519_hex {
        if !trusted
            .trusted_ed25519_pubkeys_hex
            .iter()
            .any(|k| k == signer)
        {
            return Err(Status::failed_precondition("policy oracle failure"));
        }
    }

    if manifest.require_signature {
        let signer_hex = manifest
            .signer_pubkey_ed25519_hex
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("policy oracle failure"))?;
        let signature_hex = manifest
            .signature_ed25519_hex
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("policy oracle failure"))?;
        verify_manifest_signature(manifest, signer_hex, signature_hex)?;
    } else if let (Some(signer_hex), Some(signature_hex)) = (
        manifest.signer_pubkey_ed25519_hex.as_ref(),
        manifest.signature_ed25519_hex.as_ref(),
    ) {
        verify_manifest_signature(manifest, signer_hex, signature_hex)?;
    }

    Ok(())
}

fn verify_manifest_signature(
    manifest: &PolicyOracleManifest,
    signer_hex: &str,
    signature_hex: &str,
) -> Result<(), Status> {
    let pubkey_bytes = hex::decode(signer_hex)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    let pubkey = VerifyingKey::from_bytes(
        &pubkey_bytes
            .try_into()
            .map_err(|_| Status::failed_precondition("policy oracle failure"))?,
    )
    .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    let payload = canonical_manifest_bytes(manifest, true)?;
    pubkey
        .verify(&payload, &signature)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))
}

fn canonical_manifest_bytes(
    manifest: &PolicyOracleManifest,
    exclude_signature: bool,
) -> Result<Vec<u8>, Status> {
    let mut value = serde_json::to_value(manifest)
        .map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    if exclude_signature {
        if let Value::Object(map) = &mut value {
            map.remove("signature_ed25519_hex");
        }
    }
    canonical_json(&value).map_err(|_| Status::failed_precondition("policy oracle failure"))
}

fn load_trusted_keys(dir: &Path) -> Result<TrustedKeys, Status> {
    let path = dir.join(TRUSTED_KEYS_FILENAME);
    if !path.exists() {
        return Ok(TrustedKeys {
            trusted_ed25519_pubkeys_hex: Vec::new(),
        });
    }
    enforce_secure_file_permissions(&path)?;
    let bytes = fs::read(path).map_err(|_| Status::failed_precondition("policy oracle failure"))?;
    serde_json::from_slice(&bytes).map_err(|_| Status::failed_precondition("policy oracle failure"))
}

fn validate_module_exports(module: &Module) -> Result<(), Status> {
    if module.imports().next().is_some() {
        return Err(Status::failed_precondition("policy oracle failure"));
    }

    let memory = module
        .get_export("memory")
        .ok_or_else(|| Status::failed_precondition("policy oracle failure"))?;
    if !matches!(memory, ExternType::Memory(_)) {
        return Err(Status::failed_precondition("policy oracle failure"));
    }

    let alloc = module
        .get_export("alloc")
        .ok_or_else(|| Status::failed_precondition("policy oracle failure"))?;
    if !matches_func_signature(&alloc, &[ValType::I32], &[ValType::I32]) {
        return Err(Status::failed_precondition("policy oracle failure"));
    }

    let decide = module
        .get_export("policy_oracle_decide")
        .ok_or_else(|| Status::failed_precondition("policy oracle failure"))?;
    if !matches_func_signature(&decide, &[ValType::I32, ValType::I32], &[ValType::I32]) {
        return Err(Status::failed_precondition("policy oracle failure"));
    }

    Ok(())
}

fn matches_func_signature(export: &ExternType, params: &[ValType], results: &[ValType]) -> bool {
    match export {
        ExternType::Func(func) => {
            let p: Vec<_> = func.params().collect();
            let r: Vec<_> = func.results().collect();
            p.len() == params.len()
                && r.len() == results.len()
                && p.iter()
                    .zip(params.iter())
                    .all(|(a, b)| matches!((a, b), (ValType::I32, ValType::I32)))
                && r.iter()
                    .zip(results.iter())
                    .all(|(a, b)| matches!((a, b), (ValType::I32, ValType::I32)))
        }
        _ => false,
    }
}

fn sha256_array(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn enforce_secure_file_permissions(path: &Path) -> Result<(), Status> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            fs::metadata(path).map_err(|_| Status::failed_precondition("policy oracle failure"))?;
        let mode = metadata.permissions().mode();
        if (mode & 0o022) != 0 {
            return Err(Status::failed_precondition("policy oracle failure"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn minimal_wasm(decision: i32) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (global $next (mut i32) (i32.const 0))
                (func (export "alloc") (param $len i32) (result i32)
                  global.get $next
                  global.get $next
                  local.get $len
                  i32.add
                  global.set $next)
                (func (export "policy_oracle_decide") (param i32 i32) (result i32)
                  i32.const {decision}))"#
        ))
        .expect("wat")
    }

    fn write_oracle(dir: &Path, wasm: &[u8], mut manifest: PolicyOracleManifest) {
        let wasm_path = dir.join("oracle.wasm");
        fs::write(&wasm_path, wasm).expect("write wasm");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wasm_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        manifest.wasm_sha256_hex = hex::encode(sha256_array(wasm));
        let manifest_path = dir.join("oracle.json");
        fs::write(
            manifest_path,
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("write manifest");
    }

    fn base_manifest() -> PolicyOracleManifest {
        PolicyOracleManifest {
            schema: POLICY_ORACLE_SCHEMA.to_string(),
            oracle_id: "oracle.test".to_string(),
            vendor: "vendor".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            wasm_filename: "oracle.wasm".to_string(),
            wasm_sha256_hex: String::new(),
            reason_code: 9001,
            decision_mode: "veto_only".to_string(),
            max_fuel: 1_000_000,
            max_memory_bytes: 65_536,
            max_input_bytes: 2048,
            require_signature: false,
            signer_pubkey_ed25519_hex: None,
            signature_ed25519_hex: None,
        }
    }

    #[test]
    fn policy_oracle_wasm_accepts_minimal_pass_plugin() {
        let dir = TempDir::new().expect("tmp");
        let wasm = minimal_wasm(0);
        write_oracle(dir.path(), &wasm, base_manifest());
        let loaded = PolicyOracleEngine::load_from_dir(dir.path()).expect("load");
        let (decision, _) = loaded[0].evaluate(b"{}").expect("eval");
        assert_eq!(decision, PolicyOracleDecision::Pass);
    }

    #[test]
    fn policy_oracle_wasm_rejects_imports() {
        let dir = TempDir::new().expect("tmp");
        let wasm = wat::parse_str(
            r#"(module
            (import "env" "x" (func $x))
            (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) i32.const 0)
            (func (export "policy_oracle_decide") (param i32 i32) (result i32) i32.const 0))"#,
        )
        .expect("wat");
        write_oracle(dir.path(), &wasm, base_manifest());
        assert!(PolicyOracleEngine::load_from_dir(dir.path()).is_err());
    }

    #[test]
    fn policy_oracle_wasm_rejects_missing_exports() {
        let dir = TempDir::new().expect("tmp");
        let wasm = wat::parse_str(r#"(module (memory (export "memory") 1))"#).expect("wat");
        write_oracle(dir.path(), &wasm, base_manifest());
        assert!(PolicyOracleEngine::load_from_dir(dir.path()).is_err());
    }

    #[test]
    fn policy_oracle_loader_rejects_hash_mismatch() {
        let dir = TempDir::new().expect("tmp");
        let wasm = minimal_wasm(0);
        let mut manifest = base_manifest();
        manifest.wasm_sha256_hex = "00".repeat(32);
        let wasm_path = dir.path().join("oracle.wasm");
        fs::write(&wasm_path, &wasm).expect("write wasm");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wasm_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        fs::write(
            dir.path().join("oracle.json"),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("write");
        assert!(PolicyOracleEngine::load_from_dir(dir.path()).is_err());
    }

    #[test]
    fn policy_oracle_signature_required_rejects_missing_signature() {
        let dir = TempDir::new().expect("tmp");
        let wasm = minimal_wasm(0);
        let mut manifest = base_manifest();
        manifest.require_signature = true;
        write_oracle(dir.path(), &wasm, manifest);
        assert!(PolicyOracleEngine::load_from_dir(dir.path()).is_err());
    }

    #[test]
    fn policy_oracle_signature_rejects_untrusted_signer() {
        let dir = TempDir::new().expect("tmp");
        let wasm = minimal_wasm(0);
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut manifest = base_manifest();
        manifest.require_signature = true;
        manifest.signer_pubkey_ed25519_hex = Some(hex::encode(key.verifying_key().to_bytes()));
        let payload = canonical_manifest_bytes(&manifest, true).expect("payload");
        manifest.signature_ed25519_hex = Some(hex::encode(key.sign(&payload).to_bytes()));
        write_oracle(dir.path(), &wasm, manifest);
        assert!(PolicyOracleEngine::load_from_dir(dir.path()).is_err());
    }

    #[test]
    fn policy_oracle_invalid_return_code_fails_closed() {
        let dir = TempDir::new().expect("tmp");
        let wasm = minimal_wasm(7);
        write_oracle(dir.path(), &wasm, base_manifest());
        let loaded = PolicyOracleEngine::load_from_dir(dir.path()).expect("load");
        assert!(loaded[0].evaluate(b"{}").is_err());
    }

    #[test]
    fn policy_oracle_memory_oob_write_fails_closed() {
        let dir = TempDir::new().expect("tmp");
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) i32.const 70000)
                (func (export "policy_oracle_decide") (param i32 i32) (result i32) i32.const 0))"#,
        )
        .expect("wat");
        write_oracle(dir.path(), &wasm, base_manifest());
        let loaded = PolicyOracleEngine::load_from_dir(dir.path()).expect("load");
        assert!(loaded[0].evaluate(&[1, 2, 3]).is_err());
    }

    #[test]
    fn policy_oracle_fuel_exhaustion_fails_closed() {
        let dir = TempDir::new().expect("tmp");
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) i32.const 0)
                (func (export "policy_oracle_decide") (param i32 i32) (result i32)
                  (loop br 0)
                  i32.const 0))"#,
        )
        .expect("wat");
        let mut manifest = base_manifest();
        manifest.max_fuel = 1_000;
        write_oracle(dir.path(), &wasm, manifest);
        let loaded = PolicyOracleEngine::load_from_dir(dir.path()).expect("load");
        assert!(loaded[0].evaluate(b"{}").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn policy_oracle_rejects_world_writable_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tmp");
        let wasm = minimal_wasm(0);
        let wasm_path = dir.path().join("oracle.wasm");
        fs::write(&wasm_path, &wasm).expect("write");
        fs::set_permissions(&wasm_path, fs::Permissions::from_mode(0o666)).expect("chmod");
        let mut manifest = base_manifest();
        manifest.wasm_sha256_hex = hex::encode(sha256_array(&wasm));
        fs::write(
            dir.path().join("oracle.json"),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("write manifest");
        assert!(PolicyOracleEngine::load_from_dir(dir.path()).is_err());
    }

    proptest! {
        #[test]
        fn proptest_policy_oracle_never_panics_and_decision_in_range(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let dir = TempDir::new().expect("tmp");
            let wasm = minimal_wasm(1);
            write_oracle(dir.path(), &wasm, base_manifest());
            let loaded = PolicyOracleEngine::load_from_dir(dir.path()).expect("load");
            let result = loaded[0].evaluate(&input);
            prop_assert!(result.is_ok());
            let (decision, _) = result.expect("eval");
            prop_assert!(matches!(decision, PolicyOracleDecision::Pass | PolicyOracleDecision::DeferToHeavy | PolicyOracleDecision::Reject));
        }
    }
}
