use evidenceos_core::aspec::{verify_aspec, AspecLane, AspecPolicy, FloatPolicy};

fn base_module(body: &str) -> Vec<u8> {
    wat::parse_str(format!("(module (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32))) (func (export \"run\") {body}))")).expect("wat")
}

fn insert_meta_before_code_section(wasm: &[u8], payload: &str) -> Vec<u8> {
    fn enc(mut v: u32, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }
    fn dec(bytes: &[u8], at: &mut usize) -> Option<u32> {
        let (mut v, mut s) = (0u32, 0);
        while *at < bytes.len() {
            let b = bytes[*at];
            *at += 1;
            v |= u32::from(b & 0x7f) << s;
            if b & 0x80 == 0 {
                return Some(v);
            }
            s += 7;
            if s > 28 {
                break;
            }
        }
        None
    }
    let mut out = wasm[..8].to_vec();
    let mut i = 8;
    let mut inserted = false;
    while i < wasm.len() {
        let id = wasm[i];
        i += 1;
        let mut j = i;
        let Some(sz) = dec(wasm, &mut j) else {
            return wasm.to_vec();
        };
        let hdr = &wasm[i..j];
        i = j;
        let end = i + sz as usize;
        if !inserted && id == 10 {
            let mut cp = Vec::new();
            enc(4, &mut cp);
            cp.extend_from_slice(b"meta");
            cp.extend_from_slice(payload.as_bytes());
            out.push(0);
            let mut sh = Vec::new();
            enc(cp.len() as u32, &mut sh);
            out.extend_from_slice(&sh);
            out.extend_from_slice(&cp);
            inserted = true;
        }
        out.push(id);
        out.extend_from_slice(hdr);
        out.extend_from_slice(&wasm[i..end]);
        i = end;
    }
    out
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
    let float_loop = base_module("f32.const 1.0 drop (loop nop)");
    assert!(!verify_aspec(&float_loop, &AspecPolicy::default()).ok);
    let marked = insert_meta_before_code_section(&float_loop, "loop_bound:1");
    assert!(verify_aspec(&marked, &low).ok);
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
    let one = insert_meta_before_code_section(&base_module("(loop nop)"), "loop_bound:1");
    let over = insert_meta_before_code_section(&base_module("(loop nop)"), "loop_bound:2");
    assert!(verify_aspec(&one, &p).ok);
    assert!(!verify_aspec(&over, &p).ok);
}
