use evidenceos_core::aspec::{verify_aspec, AspecPolicy};
use evidenceos_core::nullspec::{
    EProcessKind, NullSpecKind, SignedNullSpecContractV1, NULLSPEC_SCHEMA_V1,
};
use evidenceos_daemon::vault::{VaultConfig, VaultEngine, VaultExecutionContext};
use evidenceos_guest_abi::{IMPORT_EMIT_STRUCTURED_CLAIM, IMPORT_ORACLE_QUERY, MODULE_ENV};

fn test_nullspec() -> SignedNullSpecContractV1 {
    let mut spec = SignedNullSpecContractV1 {
        schema: NULLSPEC_SCHEMA_V1.to_string(),
        nullspec_id: [0u8; 32],
        oracle_id: "builtin.accuracy".to_string(),
        oracle_resolution_hash: [0u8; 32],
        holdout_handle: "holdout".to_string(),
        epoch_created: 1,
        ttl_epochs: 1,
        kind: NullSpecKind::ParametricBernoulli { p: 0.5 },
        eprocess: EProcessKind::LikelihoodRatioFixedAlt {
            alt: vec![0.5, 0.5],
        },
        calibration_manifest_hash: None,
        created_by: "test".to_string(),
        signature_ed25519: vec![0u8; 64],
    };
    spec.nullspec_id = spec.compute_id().expect("id");
    spec
}

#[test]
fn golden_guest_abi_conformance_builder_shape() {
    let wat = format!(
        r#"(module
          (import "{module}" "{oracle}" (func $oracle (param i32 i32) (result i32)))
          (import "{module}" "{emit}" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\00\01\01")
          (func (export "run")
            i32.const 0
            i32.const 4
            call $oracle
            drop
            i32.const 0
            i32.const 1
            call $emit
            drop))"#,
        module = MODULE_ENV,
        oracle = IMPORT_ORACLE_QUERY,
        emit = IMPORT_EMIT_STRUCTURED_CLAIM,
    );
    let wasm = wat::parse_str(wat).expect("wat");

    let report = verify_aspec(&wasm, &AspecPolicy::default());
    assert!(
        report.ok,
        "ASPEC should accept canonical guest ABI: {report:?}"
    );

    let engine = VaultEngine::new().expect("engine");
    let result = engine
        .execute(
            &wasm,
            &VaultExecutionContext {
                holdout_labels: vec![1, 0, 1, 1],
                oracle_num_buckets: 4,
                oracle_delta_sigma: 0.01,
                null_spec: test_nullspec(),
                output_schema_id: "legacy/v1".to_string(),
            },
            VaultConfig {
                max_fuel: 200_000,
                max_memory_bytes: 65_536,
                max_output_bytes: 4,
                max_oracle_calls: 1,
            },
        )
        .expect("execute");

    assert_eq!(result.canonical_output, vec![1]);
    assert_eq!(result.oracle_calls, 1);
}
