#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use evidenceos_core::oracle::{OracleResolution, TieBreaker};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    num_symbols: u32,
    delta_sigma: f64,
    ttl_epochs: Option<u64>,
    tie_breaker: u8,
    buckets: Vec<u32>,
    query_values: Vec<f64>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let num_symbols = input.num_symbols.min(5000);
    let mut resolution = match OracleResolution::new(num_symbols, input.delta_sigma) {
        Ok(v) => v,
        Err(_) => return,
    };

    resolution.ttl_epochs = input.ttl_epochs;
    resolution.tie_breaker = match input.tie_breaker % 3 {
        0 => TieBreaker::Lower,
        1 => TieBreaker::Upper,
        _ => TieBreaker::NearestEven,
    };

    for b in input.buckets {
        if b >= resolution.num_symbols {
            continue;
        }
        let encoded = resolution.encode_bucket(b).unwrap_or_default();
        if encoded.is_empty() {
            continue;
        }
        let decoded = resolution.decode_bucket(&encoded);
        assert!(matches!(decoded, Ok(v) if v == b));
        let validated = resolution.validate_canonical_bytes(&encoded);
        assert!(matches!(validated, Ok(v) if v == b));
    }

    for v in input.query_values {
        let _ = resolution.quantize_unit_interval(v);
    }
});
