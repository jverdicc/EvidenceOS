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
use sha2::{Digest, Sha256};

#[test]
fn canonical_proto_checksum_matches_snapshot() {
    let proto = include_bytes!("../proto/evidenceos.proto");
    let digest = Sha256::digest(proto);
    let actual = hex::encode(digest);
    let expected = "e1e9afa6298d0ffc571e48c38f45feefbc942b23d0355ff8d72ce8b06e7249c0";
    assert_eq!(
        actual, expected,
        "canonical proto changed; update snapshot intentionally"
    );
}
