// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to find protoc");
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/evidenceos.proto"], &["proto"])
        .expect("failed to compile canonical proto");
}
