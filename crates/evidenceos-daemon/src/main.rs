mod server;

use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

use server::pb::evidence_os_server::EvidenceOsServer;
use server::EvidenceOsService;

#[derive(Debug, Parser)]
#[command(name = "evidenceos-daemon")]
#[command(about = "EvidenceOS Rust verification-kernel daemon (reference implementation)")]
struct Args {
    /// Listen address, e.g. 127.0.0.1:50051
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,

    /// Path to the Evidence Transparency Log (ETL) file.
    #[arg(long, default_value = "./data/etl.log")]
    etl_path: String,

    /// Log filter (tracing-subscriber EnvFilter syntax).
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(args.log))
        .init();

    // Ensure parent dir exists.
    if let Some(parent) = std::path::Path::new(&args.etl_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let addr: SocketAddr = args.listen.parse()?;
    let (_state, svc) = EvidenceOsService::build(&args.etl_path)?;

    tracing::info!(%addr, etl_path=%args.etl_path, "starting EvidenceOS gRPC server");

    tonic::transport::Server::builder()
        .add_service(EvidenceOsServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
