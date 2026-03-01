use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::aspec::AspecPolicy;
use evidenceos_core::oracle::{EValueFn, NullSpec, OracleResolution};
use evidenceos_core::oracle_bundle::{
    Capability, OracleBundleManifestV1, TrustedOracleAuthorities,
};
use evidenceos_core::oracle_registry::OracleRegistry;
use evidenceos_core::oracle_wasm::WasmOracleSandboxPolicy;
use evidenceos_core::EvidenceOSError;
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;

fn oracle_aspec_policy() -> AspecPolicy {
    AspecPolicy::oracle_v1()
}

fn build_wasm_fraction() -> Vec<u8> {
    wat::parse_str(
        r#"(module
        (memory (export "memory") 1)
        (func (export "oracle_query") (param $ptr i32) (param $len i32) (result f64)
            f64.const 0.75))"#,
    )
    .unwrap_or_else(|_| unreachable!())
}

fn write_bundle(
    root: &std::path::Path,
    wasm: &[u8],
    tamper_hash: bool,
) -> TrustedOracleAuthorities {
    let bundle = root.join("oracles/acme.safety.v1/1.0.0");
    fs::create_dir_all(&bundle).unwrap_or_else(|_| unreachable!());
    fs::write(bundle.join("oracle.wasm"), wasm).unwrap_or_else(|_| unreachable!());

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(wasm));
    if tamper_hash {
        digest[0] ^= 0xFF;
    }

    let signing = SigningKey::from_bytes(&[7; 32]);
    let mut manifest = OracleBundleManifestV1 {
        oracle_id: "acme.safety.v1".into(),
        version: "1.0.0".into(),
        kind: "wasm".into(),
        interface_version: 1,
        wasm_sha256: digest,
        holdout_handle: "holdout-epoch-1".into(),
        resolution: OracleResolution::new(4, 0.0).unwrap_or_else(|_| unreachable!()),
        null_spec: NullSpec {
            domain: "labels".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::Fixed(1.0),
        },
        calibration_manifest_hash: None,
        capabilities: vec![Capability::OracleQuery],
        signed_by: "root".into(),
        signature_ed25519: vec![],
    };
    let msg = manifest
        .canonical_bytes()
        .unwrap_or_else(|_| unreachable!("canonical"));
    manifest.signature_ed25519 = signing.sign(&msg).to_vec();
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_else(|_| unreachable!()),
    )
    .unwrap_or_else(|_| unreachable!());

    let mut trusted = TrustedOracleAuthorities::default();
    trusted
        .keys
        .insert("root".into(), signing.verifying_key().to_bytes().to_vec());
    trusted
}

#[test]
fn wasm_hash_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let wasm = build_wasm_fraction();
    let trusted = write_bundle(dir.path(), &wasm, true);
    let registry = OracleRegistry::load_from_dir(
        &dir.path().join("oracles"),
        &trusted,
        &oracle_aspec_policy(),
        WasmOracleSandboxPolicy::default(),
    );
    assert!(matches!(registry, Err(EvidenceOSError::OracleViolation)));
}

#[test]
fn integration_wasm_oracle_query_and_quantize() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let wasm = build_wasm_fraction();
    let trusted = write_bundle(dir.path(), &wasm, false);
    let mut registry = OracleRegistry::load_from_dir(
        &dir.path().join("oracles"),
        &trusted,
        &oracle_aspec_policy(),
        WasmOracleSandboxPolicy::default(),
    )
    .unwrap_or_else(|_| unreachable!());
    let backend = registry
        .get_mut("acme.safety.v1")
        .unwrap_or_else(|| unreachable!());
    let raw = backend
        .query_raw_metric(&[1, 0, 1, 1])
        .unwrap_or_else(|_| unreachable!());
    assert!((raw - 0.75).abs() < 1e-12);
    let bucket = backend
        .resolution()
        .quantize_unit_interval(raw)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(bucket, 2);
}

#[test]
fn fail_closed_nan_and_trap_and_fuel() {
    let wasm_nan = wat::parse_str(
        "(module (memory (export \"memory\") 1) (func (export \"oracle_query\") (param i32 i32) (result f64) f64.const 0.0 f64.const 0.0 f64.div))",
    )
    .unwrap_or_else(|_| unreachable!());
    let sandbox = evidenceos_core::oracle_wasm::WasmOracleSandbox::new(
        &wasm_nan,
        WasmOracleSandboxPolicy::default(),
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        sandbox.query_raw_metric(&[1]),
        Err(EvidenceOSError::OracleViolation)
    ));

    let wasm_trap = wat::parse_str(
        "(module (memory (export \"memory\") 1) (func (export \"oracle_query\") (param i32 i32) (result f64) unreachable f64.const 0))",
    )
    .unwrap_or_else(|_| unreachable!());
    let sandbox_trap = evidenceos_core::oracle_wasm::WasmOracleSandbox::new(
        &wasm_trap,
        WasmOracleSandboxPolicy::default(),
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        sandbox_trap.query_raw_metric(&[1]),
        Err(EvidenceOSError::OracleViolation)
    ));

    let wasm_loop = wat::parse_str(
        "(module (memory (export \"memory\") 1) (func (export \"oracle_query\") (param i32 i32) (result f64) (loop br 0) f64.const 0.0))",
    )
    .unwrap_or_else(|_| unreachable!());
    let sandbox_loop = evidenceos_core::oracle_wasm::WasmOracleSandbox::new(
        &wasm_loop,
        WasmOracleSandboxPolicy {
            max_memory_bytes: 1 << 20,
            max_fuel: 100,
        },
    );
    match sandbox_loop {
        Ok(sandbox_loop) => {
            assert!(matches!(
                sandbox_loop.query_raw_metric(&[1]),
                Err(EvidenceOSError::OracleViolation)
            ));
        }
        Err(EvidenceOSError::AspecRejected) => {}
        Err(other) => panic!("unexpected loop sandbox error: {other:?}"),
    }
}

proptest! {
    #[test]
    fn random_manifest_parser_no_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = serde_json::from_slice::<OracleBundleManifestV1>(&data);
    }

    #[test]
    fn random_wasm_loader_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = evidenceos_core::oracle_wasm::WasmOracleSandbox::new(
            &bytes,
            WasmOracleSandboxPolicy::default(),
        );
    }

    #[test]
    fn random_preds_rejected_when_invalid(preds in prop::collection::vec(0u8..4u8, 0..32)) {
        let wasm = wat::parse_str("(module (memory (export \"memory\") 1) (func (export \"oracle_query\") (param i32 i32) (result f64) f64.const 0.0))")
            .unwrap_or_else(|_| unreachable!());
        let sandbox = evidenceos_core::oracle_wasm::WasmOracleSandbox::new(&wasm, WasmOracleSandboxPolicy::default()).unwrap_or_else(|_| unreachable!());
        let result = sandbox.query_raw_metric(&preds);
        let is_valid = !preds.is_empty() && preds.iter().all(|p| *p <= 1);
        if is_valid {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(matches!(result, Err(EvidenceOSError::InvalidArgument)));
        }
    }
}
