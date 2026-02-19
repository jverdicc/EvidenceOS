#![no_main]

use evidenceos_core::structured_claims;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = structured_claims::validate_and_canonicalize("cbrn/v1", data);
    if let Ok(valid) = result {
        let bits = structured_claims::kout_bits_upper_bound(&valid.canonical_bytes);
        assert!(bits <= u64::from(u32::MAX) * 8);
    }
});
