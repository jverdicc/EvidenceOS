use evidenceos_daemon::executor::{ExecutionError, ExecutionLimits, WasmExecutor};

fn limits(max_output_bytes: usize) -> ExecutionLimits {
    ExecutionLimits {
        max_fuel: 100_000,
        max_memory_bytes: 65_536,
        max_output_bytes,
        max_output_calls: 1,
        max_host_calls: 8,
    }
}

fn exec(
    wat: &str,
    epoch: u64,
    limits: ExecutionLimits,
) -> Result<evidenceos_daemon::executor::ExecutionResult, ExecutionError> {
    let wasm = wat::parse_str(wat).expect("wat compile");
    let executor = WasmExecutor::new().expect("executor");
    executor.execute(&wasm, epoch, limits)
}

#[test]
fn emit_one_byte_success() {
    let result = exec(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit)
        )"#,
        7,
        limits(1),
    )
    .expect("execute");

    assert_eq!(result.output, vec![1]);
    assert_eq!(result.output_calls, 1);
}

#[test]
fn emit_zero_bytes_is_rejected_as_missing() {
    let err = exec(
        r#"(module
          (memory (export "memory") 1)
          (func (export "run"))
        )"#,
        7,
        limits(1),
    )
    .expect_err("missing output should fail");

    assert_eq!(err, ExecutionError::OutputMissing);
}

#[test]
fn emit_twice_rejected() {
    let err = exec(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\02")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit
            i32.const 1
            i32.const 1
            call $emit)
        )"#,
        7,
        limits(2),
    )
    .expect_err("second emit should fail");

    assert_eq!(err, ExecutionError::TooManyOutputs);
}

#[test]
fn emit_too_large_rejected() {
    let err = exec(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01\02")
          (func (export "run")
            i32.const 0
            i32.const 2
            call $emit)
        )"#,
        7,
        limits(1),
    )
    .expect_err("oversized output should fail");

    assert_eq!(err, ExecutionError::OutputTooLarge);
}

#[test]
fn emit_oob_rejected() {
    let err = exec(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            i32.const 65535
            i32.const 2
            call $emit)
        )"#,
        7,
        limits(2),
    )
    .expect_err("oob should fail");

    assert_eq!(err, ExecutionError::MemoryOob);
}

#[test]
fn infinite_loop_exhausts_fuel() {
    let err = exec(
        r#"(module
          (func (export "run")
            (loop br 0))
        )"#,
        7,
        ExecutionLimits {
            max_fuel: 10_000,
            ..limits(1)
        },
    )
    .expect_err("loop should exhaust fuel");

    assert_eq!(err, ExecutionError::FuelExhausted);
}

#[test]
fn logical_epoch_changes_output_and_trace_deterministically() {
    let wat = r#"(module
      (import "env" "get_logical_epoch" (func $epoch (result i64)))
      (import "env" "emit_structured_claim" (func $emit (param i32 i32)))
      (memory (export "memory") 1)
      (func (export "run")
        i32.const 0
        call $epoch
        i64.store
        i32.const 0
        i32.const 8
        call $emit)
    )"#;

    let first = exec(wat, 5, limits(8)).expect("execute 1");
    let first_repeat = exec(wat, 5, limits(8)).expect("execute 1 repeat");
    let second = exec(wat, 6, limits(8)).expect("execute 2");

    assert_eq!(first.output, first_repeat.output);
    assert_eq!(first.trace_hash, first_repeat.trace_hash);
    assert_eq!(first.output, 5_u64.to_le_bytes().to_vec());
    assert_eq!(second.output, 6_u64.to_le_bytes().to_vec());
    assert_ne!(first.output, second.output);
    assert_ne!(first.trace_hash, second.trace_hash);
}

#[test]
fn fuel_usage_is_monotonic_with_more_work() {
    let light = exec(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            i32.const 0
            i32.const 1
            call $emit)
        )"#,
        1,
        limits(1),
    )
    .expect("light run");

    let heavy = exec(
        r#"(module
          (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "\01")
          (func (export "run")
            (local $i i32)
            i32.const 0
            local.set $i
            (loop
              local.get $i
              i32.const 500
              i32.lt_s
              if
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                br 1
              end)
            i32.const 0
            i32.const 1
            call $emit)
        )"#,
        1,
        limits(1),
    )
    .expect("heavy run");

    assert!(heavy.fuel_used > light.fuel_used);
}
