#![no_main]

use evidenceos_core::physhir::parse_quantity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_quantity(&format!("1 {s}"));
    }
});
