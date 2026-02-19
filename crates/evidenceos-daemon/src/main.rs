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
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

use evidenceos_daemon::auth::{AuthConfig, RequestGuard};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_daemon::telemetry::Telemetry;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer as EvidenceOsV2Server;
use evidenceos_protocol::pb::v1::evidence_os_server::EvidenceOsServer as EvidenceOsV1Server;

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

    #[arg(long, default_value_t = false)]
    durable_etl: bool,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    #[arg(long)]
    mtls_client_ca: Option<String>,

    #[arg(long, default_value_t = false)]
    require_client_cert: bool,

    #[arg(long)]
    auth_token: Option<String>,

    #[arg(long)]
    auth_hmac_key: Option<String>,

    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    max_request_bytes: usize,

    #[arg(long, default_value = "127.0.0.1:9464")]
    metrics_listen: String,

    #[arg(long)]
    rpc_timeout_ms: Option<u64>,
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
    let metrics_addr: SocketAddr = args.metrics_listen.parse()?;
    let telemetry = Arc::new(Telemetry::new()?);
    let _metrics_handle = telemetry.clone().spawn_metrics_server(metrics_addr).await?;
    let svc = EvidenceOsService::build_with_options(&args.data_dir, args.durable_etl, telemetry)?;

    if args.auth_token.is_some() && args.auth_hmac_key.is_some() {
        return Err("--auth-token and --auth-hmac-key are mutually exclusive".into());
    }
    if args.require_client_cert && args.mtls_client_ca.is_none() {
        return Err("--require-client-cert requires --mtls-client-ca".into());
    }
    if args.tls_cert.is_some() ^ args.tls_key.is_some() {
        return Err("--tls-cert and --tls-key must be provided together".into());
    }

    let auth = match (args.auth_token.clone(), args.auth_hmac_key.clone()) {
        (Some(token), None) => Some(AuthConfig::BearerToken(token)),
        (None, Some(hmac)) => Some(AuthConfig::HmacKey(hmac.into_bytes())),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("validated above"),
    };
    let timeout = args.rpc_timeout_ms.map(Duration::from_millis);
    let interceptor = RequestGuard::new(auth, timeout);

    tracing::info!(
        %addr,
        data_dir=%args.data_dir,
        tls_enabled=%args.tls_cert.is_some(),
        mtls_required=%args.require_client_cert,
        max_request_bytes=%args.max_request_bytes,
        auth_enabled=%(args.auth_token.is_some() || args.auth_hmac_key.is_some()),
        metrics_addr=%metrics_addr,
        "starting EvidenceOS gRPC server"
    );

    let mut builder = tonic::transport::Server::builder();
    if let (Some(cert_path), Some(key_path)) = (args.tls_cert.as_ref(), args.tls_key.as_ref()) {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
        let mut tls = tonic::transport::ServerTlsConfig::new().identity(identity);
        if args.require_client_cert {
            let ca_path = args
                .mtls_client_ca
                .as_ref()
                .ok_or("--require-client-cert requires --mtls-client-ca")?;
            let ca_pem = std::fs::read(ca_path)?;
            let ca = tonic::transport::Certificate::from_pem(ca_pem);
            tls = tls.client_ca_root(ca);
        }
        builder = builder.tls_config(tls)?;
    }

    builder
        .add_service(EvidenceOsV2Server::with_interceptor(
            svc.clone(),
            interceptor.clone(),
        ))
        .add_service(EvidenceOsV1Server::with_interceptor(svc, interceptor))
        .serve(addr)
        .await?;

    Ok(())
}
