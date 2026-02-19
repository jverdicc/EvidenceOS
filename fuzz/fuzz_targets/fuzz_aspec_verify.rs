#![no_main]

use evidenceos_core::aspec::{verify_aspec, AspecPolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = verify_aspec(data, &AspecPolicy::default());
    if report.ok {
        assert!(report.reasons.is_empty());
    } else {
        assert!(!report.reasons.is_empty());
    }

    assert!(report.kolmogorov_proxy_bits.is_finite());
    assert!(report.kolmogorov_proxy_bits >= 0.0);
    assert!(report.data_entropy_ratio.is_finite());
    assert!(report.data_entropy_ratio >= 0.0);
});
