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
    let expected = "6cde13b72b42e46d149364e18ad2f96b3874526f4e0c6a98d744dc11be183851";
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
    let expected = "e96d1dc6933a44f8723df6b9059079aa3104f359cd8c320554ffdbdad183cba8";
    assert_eq!(
        actual, expected,
        "descriptor set changed; update snapshot intentionally"
    );
}
