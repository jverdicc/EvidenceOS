use evidenceos_core::aspec::{verify_aspec, AspecLane, AspecPolicy, FloatPolicy};

fn base_module(body: &str) -> Vec<u8> {
    wat::parse_str(format!("(module (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32))) (func (export \"run\") {body}))")).expect("wat")
}

fn canonical_bounded_loop(bound: u32) -> String {
    format!(
        "(local $i i32) i32.const 0 local.set $i loop \
         local.get $i i32.const 1 i32.add local.set $i \
         local.get $i i32.const {bound} i32.lt_u br_if 0 end"
    )
}

#[test]
fn invalid_wasm_fail_closed() {
    let report = verify_aspec(&[0u8, 1, 2], &AspecPolicy::default());
    assert!(!report.ok);
}

#[test]
fn lane_fp_and_loop_matrix() {
    let mut low = AspecPolicy {
        lane: AspecLane::LowAssurance,
        float_policy: FloatPolicy::Allow,
        ..AspecPolicy::default()
    };
    low.max_loop_bound = 1;
    let float_loop = base_module(&format!("{} f32.const 1.0 drop", canonical_bounded_loop(1)));
    assert!(!verify_aspec(&float_loop, &AspecPolicy::default()).ok);
    assert!(verify_aspec(&float_loop, &low).ok);
}

#[test]
fn output_proxy_integration() {
    let wasm = base_module("nop nop nop nop nop nop nop nop nop nop nop");
    let fail = AspecPolicy {
        max_output_bytes: 1,
        ..AspecPolicy::default()
    };
    let pass = AspecPolicy {
        max_output_bytes: 2,
        ..AspecPolicy::default()
    };
    assert!(!verify_aspec(&wasm, &fail).ok);
    assert!(verify_aspec(&wasm, &pass).ok);
}

#[test]
fn low_assurance_loop_bound_matrix() {
    let mut p = AspecPolicy {
        lane: AspecLane::LowAssurance,
        float_policy: FloatPolicy::Allow,
        ..AspecPolicy::default()
    };
    p.max_loop_bound = 1;
    let one = base_module(&canonical_bounded_loop(1));
    let over = base_module(&canonical_bounded_loop(2));
    assert!(verify_aspec(&one, &p).ok);
    assert!(!verify_aspec(&over, &p).ok);
}

#[test]
fn low_assurance_rejects_data_dependent_loop_bound_matrix() {
    let p = AspecPolicy {
        lane: AspecLane::LowAssurance,
        float_policy: FloatPolicy::Allow,
        max_loop_bound: 100,
        ..AspecPolicy::default()
    };
    let dep = base_module(
        "(local $i i32) (local $b i32) i32.const 0 local.set $i i32.const 3 local.set $b loop \
         local.get $i i32.const 1 i32.add local.set $i \
         local.get $i local.get $b i32.lt_u br_if 0 end",
    );
    assert!(!verify_aspec(&dep, &p).ok);
}
