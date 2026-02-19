// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#![no_main]

use evidenceos_core::aspec::{verify_aspec, AspecPolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = verify_aspec(data, &AspecPolicy::default());
    assert_eq!(report.ok, report.reasons.is_empty());

    assert!(report.kolmogorov_proxy_bits.is_finite());
    assert!(report.kolmogorov_proxy_bits >= 0.0);
    assert!(report.data_entropy_ratio.is_finite());
    assert!(report.data_entropy_ratio >= 0.0);
});
