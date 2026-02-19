#![no_main]

use evidenceos_core::structured_claims;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = structured_claims::validate_and_canonicalize(structured_claims::LEGACY_SCHEMA_ID, data);
    if let Ok(valid) = structured_claims::validate_and_canonicalize(structured_claims::SCHEMA_ID, data)
    {
        let _ = structured_claims::validate_and_canonicalize(
            structured_claims::SCHEMA_ID,
            &valid.canonical_bytes,
        );
        let bits = structured_claims::kout_bits_upper_bound(&valid.canonical_bytes);
        assert!(bits <= u64::from(u32::MAX) * 8);
    }
});
