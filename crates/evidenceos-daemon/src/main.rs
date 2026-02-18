// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

mod server;

use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

use server::pb::evidence_os_server::EvidenceOsServer;
use server::EvidenceOsService;

#[derive(Debug, Parser)]
#[command(name = "evidenceos-daemon")]
#[command(about = "EvidenceOS Rust verification-kernel daemon")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,

    #[arg(long, default_value = "./data")]
    data_dir: String,

    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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
