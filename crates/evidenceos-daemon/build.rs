// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a vendored protoc so contributors/CI don't need a system installation.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/evidenceos.proto"], &["../../proto"])?;

    println!("cargo:rerun-if-changed=../../proto/evidenceos.proto");
    Ok(())
}
