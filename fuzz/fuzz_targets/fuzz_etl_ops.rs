#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use evidenceos_core::etl::Etl;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Op {
    Append(Vec<u8>),
    Revoke(Vec<u8>),
    Read(u64),
    RootAt(u64),
    Inclusion(u64),
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(ops) = Vec::<Op>::arbitrary(&mut u) else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("etl-fuzz.log");
    let mut etl = Etl::open_or_create(&path).expect("etl");

    for op in ops {
        match op {
            Op::Append(bytes) => {
                let _ = etl.append(&bytes);
            }
            Op::Revoke(id) => {
                if let Ok(id_str) = std::str::from_utf8(&id) {
                    let _ = etl.revoke(id_str, "fuzz");
                    let _ = etl.taint_descendants(id_str);
                }
            }
            Op::Read(i) => {
                let _ = etl.read_entry(i);
            }
            Op::RootAt(s) => {
                let _ = etl.root_at_size(s);
            }
            Op::Inclusion(i) => {
                let _ = etl.inclusion_proof(i);
            }
        }
    }
});
