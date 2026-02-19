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
// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;

#[derive(Debug, Parser)]
#[command(name = "evidenceos-daemon")]
#[command(about = "EvidenceOS Rust verification-kernel daemon")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,

    #[arg(long, default_value = "./data")]
    data_dir: String,

    /// Deprecated: path to ETL log file. Use --data-dir instead.
    #[arg(long, hide = true)]
    etl_path: Option<String>,

    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::parse();

    if let Some(etl_path) = args.etl_path.take() {
        let etl_path = std::path::PathBuf::from(etl_path);
        let data_dir = etl_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        args.data_dir = data_dir.to_string_lossy().into_owned();
        tracing::warn!("--etl-path is deprecated; use --data-dir (derived from etl path parent)");
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(args.log))
        .init();

    std::fs::create_dir_all(&args.data_dir)?;

    let addr: SocketAddr = args.listen.parse()?;
    let svc = EvidenceOsService::build(&args.data_dir)?;

    tracing::info!(%addr, data_dir=%args.data_dir, "starting EvidenceOS gRPC server");

    tonic::transport::Server::builder()
        .add_service(EvidenceOsServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
