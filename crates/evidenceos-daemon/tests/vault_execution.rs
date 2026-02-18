use evidenceos_daemon::vault::{VaultConfig, VaultEngine, VaultError, VaultExecutionContext};

fn config() -> VaultConfig {
    VaultConfig {
        max_fuel: 200_000,
        max_memory_bytes: 65_536,
        max_output_bytes: 4,
        max_oracle_calls: 1,
    }
}

fn context() -> VaultExecutionContext {
    VaultExecutionContext {
        holdout_labels: vec![1, 0, 1, 1],
        oracle_num_buckets: 4,
        oracle_delta_sigma: 0.01,
        oracle_null_accuracy: 0.5,
    }
}

#[test]
fn vault_happy_path_single_oracle_single_output() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
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
    )
    .expect("wat");

    let engine = VaultEngine::new().expect("engine");
    let first = engine
        .execute(&wasm, &context(), config())
        .expect("first execution");
    let second = engine
        .execute(&wasm, &context(), config())
        .expect("second execution");

    assert_eq!(first.oracle_calls, 1);
    assert_eq!(first.canonical_output, vec![1]);
    assert_eq!(first.judge_trace_hash, second.judge_trace_hash);
    assert_eq!(first.fuel_used, second.fuel_used);
}

#[test]
fn vault_rejects_second_emit_structured_claim() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\00")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit
            drop
            i32.const 1
            i32.const 1
            call $emit
            drop))"#,
    )
    .expect("wat");

    let engine = VaultEngine::new().expect("engine");
    let err = engine
        .execute(&wasm, &context(), config())
        .expect_err("second emit must fail");

    assert_eq!(err, VaultError::OutputAlreadyEmitted);
}

#[test]
fn vault_oob_memory_read_is_fail_closed() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "run")
            i32.const 65535
            i32.const 8
            call $emit
            drop))"#,
    )
    .expect("wat");

    let engine = VaultEngine::new().expect("engine");
    let err = engine
        .execute(&wasm, &context(), config())
        .expect_err("oob must fail");

    assert_eq!(err, VaultError::MemoryOob);
}

#[test]
fn vault_fuel_exhaustion_is_fail_closed() {
    let wasm = wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (func (export "run")
            (loop br 0)))"#,
    )
    .expect("wat");

    let engine = VaultEngine::new().expect("engine");
    let err = engine
        .execute(
            &wasm,
            &context(),
            VaultConfig {
                max_fuel: 10_000,
                ..config()
            },
        )
        .expect_err("fuel exhaustion must fail");

    assert_eq!(err, VaultError::FuelExhausted);
}

#[test]
fn vault_rejects_missing_run_export() {
    let wasm = wat::parse_str(
        r#"(module
          (memory (export "memory") 1))"#,
    )
    .expect("wat");

    let engine = VaultEngine::new().expect("engine");
    let err = engine
        .execute(&wasm, &context(), config())
        .expect_err("missing run export should fail");

    assert_eq!(err, VaultError::MissingRunExport);
}
