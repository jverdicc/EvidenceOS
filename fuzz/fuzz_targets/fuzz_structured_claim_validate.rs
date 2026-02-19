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

use evidenceos_core::structured_claims;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = structured_claims::validate_and_canonicalize("cbrn/v1", data);
    if let Ok(valid) = result {
        let bits = structured_claims::kout_bits_upper_bound(&valid.canonical_bytes);
        assert!(bits <= u64::from(u32::MAX) * 8);
    }
});
