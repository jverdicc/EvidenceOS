#![no_main]

use evidenceos_core::aspec::{verify_aspec, AspecPolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = verify_aspec(data, &AspecPolicy::default());
    assert_eq!(report.ok, report.reasons.is_empty());
});
