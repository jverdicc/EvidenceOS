#![no_main]

use evidenceos_core::structured_claims;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = structured_claims::validate_and_canonicalize(structured_claims::SCHEMA_ID, data);
});
