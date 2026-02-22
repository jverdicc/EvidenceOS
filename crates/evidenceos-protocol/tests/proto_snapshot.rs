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
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

#[test]
fn canonical_proto_checksum_matches_snapshot() {
    let proto = include_bytes!("../proto/evidenceos.proto");
    let digest = Sha256::digest(proto);
    let actual = hex::encode(digest);
    let expected = "9d53726935aa537ab68849be060bc20cef2fe675b57a1ec8fc974aab928a4099";
    assert_eq!(
        actual, expected,
        "canonical proto changed; update snapshot intentionally"
    );
}

#[test]
fn descriptor_set_checksum_matches_snapshot() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc path");
    let temp = tempfile::tempdir().expect("temp dir");
    let descriptor = temp.path().join("evidenceos.protoset");
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let status = Command::new(protoc)
        .current_dir(&manifest_dir)
        .arg("--proto_path=proto")
        .arg("--include_imports")
        .arg(format!("--descriptor_set_out={}", descriptor.display()))
        .arg("proto/evidenceos.proto")
        .arg("proto/evidenceos_v1.proto")
        .status()
        .expect("run protoc");
    assert!(status.success(), "protoc descriptor generation failed");

    let bytes = std::fs::read(&descriptor).expect("read descriptor set");
    let actual = hex::encode(Sha256::digest(&bytes));
    let expected = "a251fa8df995d3fc13f0f1295f509e47efa306ec26a0630aca3d0d831fa55765";
    assert_eq!(
        actual, expected,
        "descriptor set changed; update snapshot intentionally"
    );
}
