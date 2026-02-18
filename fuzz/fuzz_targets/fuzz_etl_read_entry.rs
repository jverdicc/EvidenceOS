#![no_main]

use evidenceos_core::etl::Etl;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("etl.log");
    std::fs::write(&path, data).expect("write fuzz input");

    if let Ok(etl) = Etl::open_or_create(&path) {
        let _ = etl.read_entry(0);
    }
});
