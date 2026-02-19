use evidenceos_core::aspec::{verify_aspec, AspecPolicy};

fn module_with_data(bytes: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{bytes}")
            (func (export "run") i32.const 0 i32.const 1 call $emit)
        )"#
    ))
    .expect("wat")
}

fn module_with_complexity_ifs(count: usize) -> Vec<u8> {
    let mut body = String::new();
    for _ in 0..count {
        body.push_str(" i32.const 0 if nop end");
    }
    wat::parse_str(format!(
        r#"(module
            (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "\01")
            (func (export "run") {body} i32.const 0 i32.const 1 call $emit)
        )"#
    ))
    .expect("wat")
}

#[test]
fn max_data_segment_bytes_boundary() {
    let policy = AspecPolicy {
        max_data_segment_bytes: 4,
        ..AspecPolicy::default()
    };
    let at_cap = module_with_data("ABCD");
    let over_cap = module_with_data("ABCDE");
    assert!(verify_aspec(&at_cap, &policy).ok);
    assert!(!verify_aspec(&over_cap, &policy).ok);
}

#[test]
fn max_entropy_ratio_boundary() {
    let strict = AspecPolicy {
        max_entropy_ratio: 0.25,
        ..AspecPolicy::default()
    };

    let low_entropy = module_with_data("AAAAAAAA");
    let high_entropy = module_with_data("ABCDEFGH");

    assert!(verify_aspec(&low_entropy, &strict).ok);
    assert!(!verify_aspec(&high_entropy, &strict).ok);
}

#[test]
fn max_cyclomatic_complexity_boundary() {
    let at_cap_wasm = module_with_complexity_ifs(3);
    let over_cap_wasm = module_with_complexity_ifs(4);

    let at_cap = AspecPolicy {
        max_cyclomatic_complexity: verify_aspec(&at_cap_wasm, &AspecPolicy::default())
            .max_cyclomatic_complexity,
        ..AspecPolicy::default()
    };

    let over_cap = at_cap.clone();

    assert!(verify_aspec(&at_cap_wasm, &at_cap).ok);
    assert!(!verify_aspec(&over_cap_wasm, &over_cap).ok);
}

#[test]
fn kolmogorov_proxy_cap_heavy_lane_flag_boundary() {
    let wasm = module_with_data("ABCDEFGHIJ");
    let report = verify_aspec(&wasm, &AspecPolicy::default());

    let at_cap = AspecPolicy {
        kolmogorov_proxy_cap: report.kolmogorov_proxy_bits.ceil() as u64,
        ..AspecPolicy::default()
    };
    let below_cap = AspecPolicy {
        kolmogorov_proxy_cap: at_cap.kolmogorov_proxy_cap.saturating_sub(1),
        ..AspecPolicy::default()
    };

    let at_report = verify_aspec(&wasm, &at_cap);
    let below_report = verify_aspec(&wasm, &below_cap);
    assert!(!at_report.heavy_lane_flag);
    assert!(below_report.heavy_lane_flag);
}
