// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use evidenceos_core::etl::Etl;
use evidenceos_core::ledger::ConservationLedger;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::{EvidenceOs, EvidenceOsServer};
use serde_json::json;
use tempfile::tempdir;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tonic::transport::{Channel, Server};

fn sample_claim(seed: u64, payload_size: usize) -> Vec<u8> {
    let payload = vec![b'x'; payload_size];
    json!({
        "claim_id": seed,
        "kind": "benchmark",
        "payload": payload,
    })
    .to_string()
    .into_bytes()
}

fn bench_etl_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("etl_overhead");
    for payload_size in [256usize, 1024, 4096] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("claim_{payload_size}b")),
            &payload_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let dir = tempdir().expect("tempdir");
                        let etl_path = dir.path().join("latency.etl");
                        let etl = Etl::open_or_create(&etl_path).expect("etl");
                        let claim = sample_claim(7, size);
                        (dir, etl, claim)
                    },
                    |(_dir, mut etl, claim)| {
                        let _ = etl.append(&claim).expect("append claim");
                        criterion::black_box(etl.root_hash());
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_ledger_update_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("ledger_update_latency");
    for &(k_bits, e_value) in &[
        (0.25_f64, 1.01_f64),
        (1.0_f64, 1.05_f64),
        (4.0_f64, 1.1_f64),
    ] {
        group.bench_with_input(
            BenchmarkId::new("w_k_cycle", format!("k{k_bits}_e{e_value}")),
            &(k_bits, e_value),
            |b, &(k_bits, e_value)| {
                b.iter_batched(
                    || ConservationLedger::new(0.05).expect("ledger"),
                    |mut ledger| {
                        ledger
                            .charge(
                                k_bits,
                                "benchmark_charge",
                                json!({"k_bits": k_bits, "mode": "w/k"}),
                            )
                            .expect("charge");
                        ledger
                            .settle_e_value(
                                e_value,
                                "benchmark_settle",
                                json!({"e_value": e_value, "mode": "w/k"}),
                            )
                            .expect("settle");
                        criterion::black_box((
                            ledger.k_bits_total(),
                            ledger.wealth(),
                            ledger.w_max(),
                        ));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

async fn spawn_health_client() -> Result<(EvidenceOsClient<Channel>, oneshot::Sender<()>), String> {
    let data_dir = tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let service = EvidenceOsService::build(data_dir.path().to_str().ok_or("invalid tempdir path")?)
        .map_err(|status| format!("service build failed: {status}"))?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let _ = Server::builder()
            .add_service(EvidenceOsServer::new(service))
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await;
    });

    let client = EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok((client, tx))
}

fn bench_grpc_roundtrip(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("grpc_roundtrip");

    group.bench_function("local_health_function", |b| {
        let data_dir = tempdir().expect("tempdir");
        let service = Arc::new(
            EvidenceOsService::build(data_dir.path().to_str().expect("tempdir path utf-8"))
                .expect("service"),
        );

        b.to_async(&rt).iter(|| {
            let service = Arc::clone(&service);
            async move {
                let response = service
                    .health(tonic::Request::new(pb::HealthRequest {}))
                    .await
                    .expect("local health");
                criterion::black_box(response.into_inner().status);
            }
        });
    });

    let setup = rt.block_on(spawn_health_client());
    let (client, shutdown) = match setup {
        Ok(ok) => ok,
        Err(e) => {
            group.finish();
            panic!("failed to stand up benchmark grpc server: {e}");
        }
    };

    group.bench_function("grpc_health_roundtrip", |b| {
        let client = Arc::new(tokio::sync::Mutex::new(client.clone()));
        b.to_async(&rt).iter(|| {
            let client = Arc::clone(&client);
            async move {
                let mut client = client.lock().await;
                let response = client
                    .health(pb::HealthRequest {})
                    .await
                    .expect("grpc health")
                    .into_inner();
                criterion::black_box(response.status);
            }
        });
    });

    let _ = rt.block_on(async { shutdown.send(()) });
    group.finish();
}

criterion_group!(
    verification_latency,
    bench_etl_overhead,
    bench_ledger_update_latency,
    bench_grpc_roundtrip
);
criterion_main!(verification_latency);
