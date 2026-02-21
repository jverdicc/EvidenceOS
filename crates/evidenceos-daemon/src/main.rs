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
use ed25519_dalek::VerifyingKey;
use evidenceos_attest::{load_policy, verify_attestation_blob};
use evidenceos_core::aspec::AspecPolicy;
use evidenceos_core::oracle_registry::OracleRegistry;
use evidenceos_core::oracle_wasm::WasmOracleSandboxPolicy;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

use evidenceos_daemon::auth::{AuthConfig, RequestGuard};
use evidenceos_daemon::config::{DaemonConfig, DaemonOracleConfig};
use evidenceos_daemon::http_preflight;
use evidenceos_daemon::pln_profile::load_pln_profile;
use evidenceos_daemon::server::{EvidenceOsService, NullSpecRegistryConfig};
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
    #[arg(long, default_value = "./oracles")]
    oracle_dir: String,
    #[arg(long)]
    trusted_oracle_keys: Option<String>,
    #[arg(long, default_value_t = false)]
    require_attestation: bool,
    #[arg(long)]
    attestation_policy: Option<String>,
    #[arg(long)]
    nullspec_registry_dir: Option<String>,
    #[arg(long)]
    nullspec_authority_keys_dir: Option<String>,
    #[arg(long)]
    rpc_timeout_ms: Option<u64>,
    #[arg(long, default_value_t = false)]
    offline_settlement_ingest: bool,
    #[arg(long, default_value_t = false)]
    insecure_synthetic_holdout: bool,
    #[arg(long, default_value_t = false)]
    allow_plaintext_holdouts: bool,
    #[arg(long)]
    import_signed_settlements_dir: Option<String>,
    #[arg(long)]
    offline_settlement_verify_key_hex: Option<String>,

    #[arg(long)]
    preflight_http_listen: Option<String>,
    #[arg(long, default_value_t = 16_384)]
    preflight_max_body_bytes: usize,
    #[arg(long)]
    preflight_require_bearer_token: Option<String>,
    #[arg(long, default_value_t = true)]
    preflight_fail_open_for_low_risk: bool,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "exec,shell.exec,fs.write,fs.delete_tree,email.send,payment.charge"
    )]
    preflight_high_risk_tools: Vec<String>,
    #[arg(long, default_value_t = 120)]
    preflight_timeout_ms: u64,
    #[arg(long, default_value_t = 50)]
    preflight_rate_limit_rps: u32,
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
        .with_env_filter(EnvFilter::new(args.log.clone()))
        .init();

    std::fs::create_dir_all(&args.data_dir)?;
    if args.offline_settlement_ingest {
        std::env::set_var("EVIDENCEOS_OFFLINE_SETTLEMENT_INGEST", "1");
    }
    if args.allow_plaintext_holdouts {
        std::env::set_var("EVIDENCEOS_ALLOW_PLAINTEXT_HOLDOUTS", "1");
        tracing::warn!(
            "plaintext holdout mode enabled; development-only and unsafe for production"
        );
    }
    if args.insecure_synthetic_holdout {
        std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
        tracing::warn!(
            "insecure synthetic holdout mode enabled; do not use in production environments"
        );
    }
    if let Some(profile) = load_pln_profile(std::path::Path::new(&args.data_dir))? {
        tracing::info!(cpu_model=%profile.cpu_model, syscall_p99=%profile.syscall_fuel.p99_fuel, wasm_p99=%profile.wasm_instruction_fuel.p99_fuel, "loaded PLN profile");
    }
    if let Some(src) = args.trusted_oracle_keys.as_deref() {
        let dst = std::path::Path::new(&args.data_dir).join("trusted_oracle_keys.json");
        std::fs::copy(src, dst)?;
    }

    let addr: SocketAddr = args.listen.parse()?;
    let metrics_addr: SocketAddr = args.metrics_listen.parse()?;
    let telemetry = Arc::new(Telemetry::new()?);
    let _metrics_handle = telemetry.clone().spawn_metrics_server(metrics_addr).await?;
    let oracle_cfg = DaemonOracleConfig::load(
        &args.oracle_dir,
        args.trusted_oracle_keys.as_deref(),
        std::path::Path::new(&args.data_dir),
        args.nullspec_registry_dir.as_deref(),
        args.nullspec_authority_keys_dir.as_deref(),
    )?;
    let oracle_aspec_policy = AspecPolicy::oracle_v1();
    let registry = OracleRegistry::load_from_dir(
        &oracle_cfg.oracle_dir,
        &oracle_cfg.trusted_authorities,
        &oracle_aspec_policy,
        WasmOracleSandboxPolicy::default(),
    )?;
    tracing::info!(count=%registry.oracle_ids().len(), "loaded oracle bundles");

    let svc = EvidenceOsService::build_with_options_and_nullspec(
        &args.data_dir,
        args.durable_etl,
        telemetry.clone(),
        NullSpecRegistryConfig {
            registry_dir: oracle_cfg.nullspec_registry_dir.clone(),
            authority_keys_dir: oracle_cfg.trusted_nullspec_keys_dir.clone(),
            reload_interval: Duration::from_secs(30),
        },
    )?;

    if args.require_attestation {
        let policy_path = args
            .attestation_policy
            .as_ref()
            .ok_or("--require-attestation requires --attestation-policy")?;
        let policy_bytes = std::fs::read(policy_path)?;
        let policy = load_policy(&policy_bytes)?;
        let startup_measurement = std::env::var("EVIDENCEOS_STARTUP_TEE_MEASUREMENT_HEX")?;
        let startup_blob = std::env::var("EVIDENCEOS_STARTUP_TEE_ATTESTATION_BLOB_B64")?;
        let startup_backend = std::env::var("EVIDENCEOS_STARTUP_TEE_BACKEND")
            .unwrap_or_else(|_| "amd-sev-snp".to_string());
        verify_attestation_blob(
            &startup_backend,
            &startup_measurement,
            &startup_blob,
            &policy,
        )?;
        tracing::info!("startup attestation verification succeeded");
    }

    if let Some(import_dir) = args.import_signed_settlements_dir.as_ref() {
        let key_hex = args.offline_settlement_verify_key_hex.as_ref().ok_or(
            "--import-signed-settlements-dir requires --offline-settlement-verify-key-hex",
        )?;
        let key_bytes = hex::decode(key_hex)?;
        let verify_key = VerifyingKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "offline settlement verify key must be 32 bytes")?,
        )?;
        let applied =
            svc.apply_signed_settlements(std::path::Path::new(import_dir), &verify_key)?;
        tracing::info!(count=%applied, "applied signed settlements");
    }

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
        (Some(_), Some(_)) => return Err("mutually exclusive auth already validated".into()),
    };

    let timeout = args.rpc_timeout_ms.map(Duration::from_millis);
    let interceptor = RequestGuard::new(auth, timeout);

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

    let daemon_cfg = DaemonConfig {
        preflight_http_listen: args.preflight_http_listen.clone(),
        preflight_max_body_bytes: args.preflight_max_body_bytes,
        preflight_require_bearer_token: args.preflight_require_bearer_token.clone(),
        preflight_fail_open_for_low_risk: args.preflight_fail_open_for_low_risk,
        preflight_high_risk_tools: args.preflight_high_risk_tools.clone(),
        preflight_timeout_ms: args.preflight_timeout_ms,
        preflight_rate_limit_rps: args.preflight_rate_limit_rps,
    };

    let (shutdown_tx, _) = broadcast::channel::<()>(2);
    let mut grpc_shutdown_rx = shutdown_tx.subscribe();
    let grpc = builder
        .add_service(EvidenceOsV2Server::with_interceptor(
            svc.clone(),
            interceptor.clone(),
        ))
        .add_service(EvidenceOsV1Server::with_interceptor(
            svc.clone(),
            interceptor,
        ))
        .serve_with_shutdown(addr, async move {
            let _ = grpc_shutdown_rx.recv().await;
        });

    let mut tasks = vec![tokio::spawn(async move {
        grpc.await.map_err(|e| e.to_string())
    })];

    if let Some(http_listen) = daemon_cfg.preflight_http_listen.clone() {
        let listener = http_preflight::bind_listener(&http_listen).await?;
        let mut http_shutdown_rx = shutdown_tx.subscribe();
        let preflight_state = http_preflight::build_state(
            daemon_cfg,
            telemetry,
            svc.probe_detector(),
            svc.policy_oracles(),
        );
        tasks.push(tokio::spawn(async move {
            http_preflight::serve(listener, preflight_state, async move {
                let _ = http_shutdown_rx.recv().await;
            })
            .await
            .map_err(|e| e.to_string())
        }));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            let _ = shutdown_tx.send(());
        }
        r = async {
            for task in tasks {
                let joined = task.await.map_err(|e| e.to_string())?;
                joined?;
            }
            Ok::<(), String>(())
        } => {
            if let Err(err) = r {
                return Err(err.into());
            }
        }
    }

    Ok(())
}
