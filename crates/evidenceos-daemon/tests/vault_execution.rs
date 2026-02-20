// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
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
        output_schema_id: "legacy/v1".to_string(),
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

    assert!(matches!(
        err,
        VaultError::FuelExhausted | VaultError::Trap(_)
    ));
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

#[test]
fn vault_oracle_multibyte_bucket_encoding() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\00\01\01")
          (func (export "run")
            i32.const 0 i32.const 4 call $oracle drop
            i32.const 0 i32.const 2 call $emit drop))"#,
    )
    .expect("wat");
    let engine = VaultEngine::new().expect("engine");
    let mut ctx = context();
    ctx.oracle_num_buckets = 1024;
    let out = engine.execute(&wasm, &ctx, config()).expect("execute");
    assert_eq!(out.canonical_output.len(), 2);
}

#[test]
fn vault_hysteresis_local_stalls_system() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\00\01\01")
          (func (export "run")
            i32.const 0 i32.const 4 call $oracle drop
            i32.const 0 i32.const 1 call $emit drop))"#,
    )
    .expect("wat");
    let engine = VaultEngine::new().expect("engine");
    let c1 = context();
    let mut c2 = context();
    c2.holdout_labels = vec![1, 0, 1, 0];
    c2.oracle_delta_sigma = 1.0;
    let a = engine.execute(&wasm, &c1, config()).expect("a");
    let b = engine.execute(&wasm, &c2, config()).expect("b");
    assert_eq!(a.canonical_output, b.canonical_output);
}

#[test]
fn vault_rejects_invalid_holdout_labels() {
    let wasm = wat::parse_str("(module (memory (export \"memory\") 1) (func (export \"run\")))")
        .expect("wat");
    let engine = VaultEngine::new().expect("engine");
    let mut bad = context();
    bad.holdout_labels = vec![2, 2, 2, 2];
    let err = engine
        .execute(&wasm, &bad, config())
        .expect_err("invalid labels");
    assert!(matches!(err, VaultError::InvalidConfig(_)));
}

#[test]
fn vault_rejects_invalid_null_accuracy() {
    let wasm = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run")))"#)
        .expect("wat");
    let engine = VaultEngine::new().expect("engine");
    for acc in [0.0, -0.1, 1.1, f64::NAN, f64::INFINITY] {
        let mut bad = context();
        bad.oracle_null_accuracy = acc;
        let err = engine
            .execute(&wasm, &bad, config())
            .expect_err("invalid null accuracy");
        assert!(matches!(err, VaultError::InvalidConfig(_)));
    }
}

#[test]
fn vault_e_value_becomes_zero_when_accuracy_is_zero() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "oracle_bucket" (func $oracle (param i32 i32) (result i32)))
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\00\00\00\00")
          (func (export "run")
            i32.const 0 i32.const 4 call $oracle drop
            i32.const 0 i32.const 1 call $emit drop))"#,
    )
    .expect("wat");
    let engine = VaultEngine::new().expect("engine");
    let mut ctx = context();
    ctx.holdout_labels = vec![1, 1, 1, 1];
    ctx.oracle_null_accuracy = 0.5;
    let out = engine.execute(&wasm, &ctx, config()).expect("execute");
    assert_eq!(out.e_value_total, 0.0);
}

#[test]
fn structured_schema_output_near_bound_succeeds_and_plus_one_fails() {
    let payload = br#"{"schema_id":"cbrn-sc.v1","claim_id":"c1","event_time_unix":1,"sensor_id":"s","location_id":"l","measurement":"1 mmol/L","confidence_bps":9000,"reason_code":"ALERT"}"#;

    let wasm_ok = wat::parse_str(format!(
        r#"(module (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32))) (memory (export "memory") 1) (data (i32.const 0) "{}") (func (export "run") i32.const 0 i32.const {} call $emit drop))"#,
        payload
            .iter()
            .map(|b| format!("\\{:02x}", b))
            .collect::<String>(),
        payload.len()
    ))
    .expect("wat ok");
    let mut ctx = context();
    ctx.output_schema_id = evidenceos_core::structured_claims::SCHEMA_ID.to_string();
    let engine = VaultEngine::new().expect("engine");
    let ok = engine.execute(
        &wasm_ok,
        &ctx,
        VaultConfig {
            max_output_bytes: payload.len() as u32,
            ..config()
        },
    );
    assert!(ok.is_ok(), "{ok:?}");

    let mut payload_big = payload.to_vec();
    payload_big.push(b' ');
    let wasm_fail = wat::parse_str(format!(
        r#"(module (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32))) (memory (export "memory") 1) (data (i32.const 0) "{}") (func (export "run") i32.const 0 i32.const {} call $emit drop))"#,
        payload_big
            .iter()
            .map(|b| format!("\\{:02x}", b))
            .collect::<String>(),
        payload_big.len()
    ))
    .expect("wat fail");
    let err = engine
        .execute(
            &wasm_fail,
            &ctx,
            VaultConfig {
                max_output_bytes: payload.len() as u32,
                ..config()
            },
        )
        .expect_err("+1 must fail");
    assert_eq!(err, VaultError::OutputTooLarge);
}

#[test]
fn legacy_schema_output_larger_than_symbol_length_fails() {
    let wasm = wat::parse_str(
        r#"(module
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\02")
          (func (export "run")
            i32.const 0 i32.const 2 call $emit drop))"#,
    )
    .expect("wat");
    let engine = VaultEngine::new().expect("engine");
    let err = engine
        .execute(
            &wasm,
            &context(),
            VaultConfig {
                max_output_bytes: 1,
                ..config()
            },
        )
        .expect_err("legacy > canonical length");
    assert_eq!(err, VaultError::OutputTooLarge);
}
