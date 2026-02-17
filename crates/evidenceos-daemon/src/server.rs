// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use evidenceos_core::capsule::ClaimCapsule;
use evidenceos_core::dlc::{DeterministicLogicalClock, DlcConfig};
use evidenceos_core::etl::Etl;
use evidenceos_core::ledger::ConservationLedger;
use evidenceos_core::oracle::{HoldoutBoundary, HoldoutLabels, HysteresisState, OracleResolution};

pub mod pb {
    tonic::include_proto!("evidenceos.v1");
}

use pb::evidence_os_server::EvidenceOs;

#[derive(Debug, Clone)]
struct SessionConfig {
    oracle_buckets: u32,
    hysteresis_delta: f64,
    binom_p1: f64,
}

#[derive(Debug)]
enum Holdout {
    Labels {
        labels: HoldoutLabels,
        hysteresis: HysteresisState<Vec<u8>>,
        resolution: OracleResolution,
    },
    ScalarBoundary {
        boundary: HoldoutBoundary,
        hysteresis_acc: HysteresisState<f64>,
        resolution_acc: OracleResolution,
    },
}

#[derive(Debug)]
struct SessionState {
    cfg: SessionConfig,
    ledger: ConservationLedger,
    dlc: DeterministicLogicalClock,
    holdouts: HashMap<String, Holdout>,
}

#[derive(Debug)]
pub(crate) struct KernelState {
    sessions: Mutex<HashMap<String, SessionState>>,
    etl: Mutex<Etl>,
}

impl KernelState {
    #[allow(clippy::result_large_err)]
    fn new(etl_path: &str) -> Result<Self, Status> {
        let etl = Etl::open_or_create(etl_path)
            .map_err(|e| Status::internal(format!("etl init: {e}")))?;
        Ok(Self {
            sessions: Mutex::new(HashMap::new()),
            etl: Mutex::new(etl),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceOsService {
    state: Arc<KernelState>,
}

impl EvidenceOsService {
    pub(crate) fn new(state: Arc<KernelState>) -> Self {
        Self { state }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn build(etl_path: &str) -> Result<(Arc<KernelState>, Self), Status> {
        let state = Arc::new(KernelState::new(etl_path)?);
        let svc = Self::new(state.clone());
        Ok((state, svc))
    }
}

fn status_from_err(e: evidenceos_core::EvidenceOSError) -> Status {
    use evidenceos_core::EvidenceOSError as E;
    match e {
        E::InvalidArgument(s) => Status::invalid_argument(s),
        E::NotFound(s) => Status::not_found(s),
        E::Frozen => Status::failed_precondition("session frozen"),
        E::AspecRejected(s) => Status::failed_precondition(s),
        E::Internal(s) => Status::internal(s),
    }
}

#[tonic::async_trait]
impl EvidenceOs for EvidenceOsService {
    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        Ok(Response::new(pb::HealthResponse {
            status: "SERVING".to_string(),
        }))
    }

    async fn create_session(
        &self,
        request: Request<pb::CreateSessionRequest>,
    ) -> Result<Response<pb::CreateSessionResponse>, Status> {
        let req = request.into_inner();

        let alpha = if req.alpha == 0.0 { 0.05 } else { req.alpha };
        let epoch_size = if req.epoch_size == 0 {
            10_000
        } else {
            req.epoch_size
        };
        let hysteresis_delta = if req.hysteresis_delta < 0.0 {
            return Err(Status::invalid_argument("hysteresis_delta must be >= 0"));
        } else {
            req.hysteresis_delta
        };
        let oracle_buckets = if req.oracle_buckets == 0 {
            256
        } else {
            req.oracle_buckets
        };

        let joint_bits_budget = if req.joint_bits_budget == 0 {
            None
        } else {
            Some(req.joint_bits_budget as f64)
        };

        let binom_p1 = if req.binom_p1 == 0.0 {
            0.60
        } else {
            req.binom_p1
        };
        if !(binom_p1 > 0.5 && binom_p1 < 1.0) {
            return Err(Status::invalid_argument("binom_p1 must be in (0.5,1)"));
        }

        let cfg = SessionConfig {
            oracle_buckets,
            hysteresis_delta,
            binom_p1,
        };

        let mut ledger = ConservationLedger::new(alpha).map_err(status_from_err)?;
        ledger = ledger.with_budget(joint_bits_budget);

        let dlc_cfg = DlcConfig::new(epoch_size).map_err(status_from_err)?;
        let dlc = DeterministicLogicalClock::new(dlc_cfg);

        let session_id = Uuid::new_v4().to_string();

        let session = SessionState {
            cfg,
            ledger,
            dlc,
            holdouts: HashMap::new(),
        };

        self.state
            .sessions
            .lock()
            .insert(session_id.clone(), session);

        info!(session_id = %session_id, "session created");

        Ok(Response::new(pb::CreateSessionResponse { session_id }))
    }

    async fn init_holdout(
        &self,
        request: Request<pb::InitHoldoutRequest>,
    ) -> Result<Response<pb::InitHoldoutResponse>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let mut sessions = self.state.sessions.lock();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| Status::not_found("session not found"))?;

        let mut rng = ChaCha20Rng::seed_from_u64(req.seed);

        let holdout_id = Uuid::new_v4().to_string();

        match pb::HoldoutKind::try_from(req.kind).unwrap_or(pb::HoldoutKind::Unspecified) {
            pb::HoldoutKind::Labels => {
                let n = if req.size == 0 {
                    256
                } else {
                    req.size as usize
                };
                let mut labels = Vec::with_capacity(n);
                for _ in 0..n {
                    labels.push(if rng.gen::<bool>() { 1u8 } else { 0u8 });
                }
                let labels = HoldoutLabels::new(labels).map_err(status_from_err)?;
                let resolution =
                    OracleResolution::new(session.cfg.oracle_buckets, session.cfg.hysteresis_delta)
                        .map_err(status_from_err)?;

                session.holdouts.insert(
                    holdout_id.clone(),
                    Holdout::Labels {
                        labels,
                        hysteresis: HysteresisState::default(),
                        resolution,
                    },
                );
            }
            pb::HoldoutKind::ScalarBoundary => {
                let b = rng.gen::<f64>();
                let boundary = HoldoutBoundary::new(b).map_err(status_from_err)?;
                let resolution_acc =
                    OracleResolution::new(session.cfg.oracle_buckets, session.cfg.hysteresis_delta)
                        .map_err(status_from_err)?;

                session.holdouts.insert(
                    holdout_id.clone(),
                    Holdout::ScalarBoundary {
                        boundary,
                        hysteresis_acc: HysteresisState::default(),
                        resolution_acc,
                    },
                );
            }
            pb::HoldoutKind::Unspecified => {
                return Err(Status::invalid_argument("holdout kind unspecified"));
            }
        }

        // Charge a small fixed cost to the logical clock for dataset initialization.
        let _epoch = session.dlc.tick(1_000);

        info!(session_id=%session_id, holdout_id=%holdout_id, "holdout initialized");

        Ok(Response::new(pb::InitHoldoutResponse { holdout_id }))
    }

    async fn oracle_accuracy(
        &self,
        request: Request<pb::OracleAccuracyRequest>,
    ) -> Result<Response<pb::OracleReply>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let holdout_id = req.holdout_id;
        let preds = req.predictions;

        let mut sessions = self.state.sessions.lock();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| Status::not_found("session not found"))?;

        let holdout = session
            .holdouts
            .get_mut(&holdout_id)
            .ok_or_else(|| Status::not_found("holdout not found"))?;

        match holdout {
            Holdout::Labels {
                labels,
                hysteresis,
                resolution,
            } => {
                let k_bits = resolution.bits_per_call();
                if let Err(_e) = session.ledger.charge(
                    k_bits,
                    "oracle_accuracy",
                    serde_json::json!({"holdout_id": holdout_id}),
                ) {
                    return Ok(Response::new(pb::OracleReply {
                        bucket: 0,
                        num_buckets: resolution.num_buckets,
                        logical_epoch: session.dlc.current_epoch(),
                        k_bits_total: session.ledger.k_bits_total,
                        barrier: session.ledger.barrier(),
                        frozen: true,
                    }));
                }

                let raw = labels.accuracy(&preds).map_err(status_from_err)?;
                let bucket = resolution.quantize_unit_interval(raw);

                let local = if let Some(ref last) = hysteresis.last_input {
                    HoldoutLabels::hamming_distance(last, &preds).map_err(status_from_err)? <= 1
                } else {
                    false
                };

                let out_bucket =
                    hysteresis.apply(local, resolution.delta_sigma, raw, bucket, preds.clone());

                let epoch = session.dlc.tick(10_000);

                Ok(Response::new(pb::OracleReply {
                    bucket: out_bucket,
                    num_buckets: resolution.num_buckets,
                    logical_epoch: epoch,
                    k_bits_total: session.ledger.k_bits_total,
                    barrier: session.ledger.barrier(),
                    frozen: session.ledger.frozen,
                }))
            }
            _ => Err(Status::failed_precondition(
                "oracle_accuracy is only defined for LABELS holdouts",
            )),
        }
    }

    async fn oracle_boundary_safety(
        &self,
        request: Request<pb::OracleBoundarySafetyRequest>,
    ) -> Result<Response<pb::OracleReply>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let holdout_id = req.holdout_id;
        let x = req.x;

        let mut sessions = self.state.sessions.lock();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| Status::not_found("session not found"))?;

        let holdout = session
            .holdouts
            .get_mut(&holdout_id)
            .ok_or_else(|| Status::not_found("holdout not found"))?;

        match holdout {
            Holdout::ScalarBoundary { boundary, .. } => {
                let k_bits = 1.0;
                if let Err(_e) = session.ledger.charge(
                    k_bits,
                    "oracle_boundary_safety",
                    serde_json::json!({"holdout_id": holdout_id}),
                ) {
                    return Ok(Response::new(pb::OracleReply {
                        bucket: 0,
                        num_buckets: 2,
                        logical_epoch: session.dlc.current_epoch(),
                        k_bits_total: session.ledger.k_bits_total,
                        barrier: session.ledger.barrier(),
                        frozen: true,
                    }));
                }

                let safe = boundary.safety_det(x);
                let bucket = if safe { 1 } else { 0 };

                let epoch = session.dlc.tick(10_000);

                Ok(Response::new(pb::OracleReply {
                    bucket,
                    num_buckets: 2,
                    logical_epoch: epoch,
                    k_bits_total: session.ledger.k_bits_total,
                    barrier: session.ledger.barrier(),
                    frozen: session.ledger.frozen,
                }))
            }
            _ => Err(Status::failed_precondition(
                "oracle_boundary_safety is only defined for SCALAR_BOUNDARY holdouts",
            )),
        }
    }

    async fn oracle_boundary_accuracy(
        &self,
        request: Request<pb::OracleBoundaryAccuracyRequest>,
    ) -> Result<Response<pb::OracleReply>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let holdout_id = req.holdout_id;
        let x = req.x;

        let mut sessions = self.state.sessions.lock();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| Status::not_found("session not found"))?;

        let holdout = session
            .holdouts
            .get_mut(&holdout_id)
            .ok_or_else(|| Status::not_found("holdout not found"))?;

        match holdout {
            Holdout::ScalarBoundary {
                boundary,
                hysteresis_acc,
                resolution_acc,
            } => {
                let k_bits = resolution_acc.bits_per_call();
                if let Err(_e) = session.ledger.charge(
                    k_bits,
                    "oracle_boundary_accuracy",
                    serde_json::json!({"holdout_id": holdout_id}),
                ) {
                    return Ok(Response::new(pb::OracleReply {
                        bucket: 0,
                        num_buckets: resolution_acc.num_buckets,
                        logical_epoch: session.dlc.current_epoch(),
                        k_bits_total: session.ledger.k_bits_total,
                        barrier: session.ledger.barrier(),
                        frozen: true,
                    }));
                }

                let raw = boundary.accuracy_det(x);
                let bucket = resolution_acc.quantize_unit_interval(raw);

                // Locality for scalar x: within epsilon.
                let local = if let Some(last_x) = hysteresis_acc.last_input {
                    (x - last_x).abs() <= 1e-6
                } else {
                    false
                };

                let out_bucket =
                    hysteresis_acc.apply(local, resolution_acc.delta_sigma, raw, bucket, x);

                let epoch = session.dlc.tick(10_000);

                Ok(Response::new(pb::OracleReply {
                    bucket: out_bucket,
                    num_buckets: resolution_acc.num_buckets,
                    logical_epoch: epoch,
                    k_bits_total: session.ledger.k_bits_total,
                    barrier: session.ledger.barrier(),
                    frozen: session.ledger.frozen,
                }))
            }
            _ => Err(Status::failed_precondition(
                "oracle_boundary_accuracy is only defined for SCALAR_BOUNDARY holdouts",
            )),
        }
    }

    async fn evaluate_and_certify(
        &self,
        request: Request<pb::EvaluateAndCertifyRequest>,
    ) -> Result<Response<pb::EvaluateAndCertifyResponse>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let holdout_id = req.holdout_id;
        let preds = req.predictions;
        let claim_name = req.claim_name;

        let mut sessions = self.state.sessions.lock();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| Status::not_found("session not found"))?;

        let holdout = session
            .holdouts
            .get(&holdout_id)
            .ok_or_else(|| Status::not_found("holdout not found"))?;

        let labels = match holdout {
            Holdout::Labels { labels, .. } => labels,
            _ => {
                return Err(Status::failed_precondition(
                    "evaluate_and_certify only supported for LABELS holdouts",
                ));
            }
        };

        if preds.len() != labels.len() {
            return Err(Status::invalid_argument(format!(
                "predictions length {} != labels length {}",
                preds.len(),
                labels.len()
            )));
        }

        let mut correct: u64 = 0;
        for (p, y) in preds.iter().zip(labels.labels_bytes().iter()) {
            if *p != 0 && *p != 1 {
                return Err(Status::invalid_argument("predictions must be bytes of 0/1"));
            }
            if p == y {
                correct += 1;
            }
        }

        let n = labels.len() as f64;
        let k = correct as f64;
        let raw_acc = k / n;

        // Binomial likelihood ratio e-value.
        let p0 = 0.5;
        let p1 = session.cfg.binom_p1;

        let ln_e = k * (p1 / p0).ln() + (n - k) * ((1.0 - p1) / (1.0 - p0)).ln();
        let e_value = ln_e.exp().min(f64::MAX);

        if let Err(e) = session.ledger.settle_e_value(
            e_value,
            "evaluate",
            serde_json::json!({"holdout_id": holdout_id, "raw_acc": raw_acc}),
        ) {
            warn!("settle_e_value failed: {e}");
            return Err(status_from_err(e));
        }

        let certified = session.ledger.can_certify();

        let mut capsule_hash = String::new();
        let mut etl_index = 0u64;

        if certified {
            let capsule = ClaimCapsule::new(
                session_id.clone(),
                holdout_id.clone(),
                claim_name,
                &preds,
                labels.labels_bytes(),
                &session.ledger,
                e_value,
                true,
            );
            capsule_hash = capsule.capsule_hash_hex();

            let capsule_bytes = capsule.to_json_bytes();
            let mut etl = self.state.etl.lock();
            let (idx, _leaf) = etl.append(&capsule_bytes).map_err(status_from_err)?;
            etl_index = idx;
            info!(session_id=%session_id, holdout_id=%holdout_id, etl_index=etl_index, "CERTIFIED");
        } else {
            info!(session_id=%session_id, holdout_id=%holdout_id, "not certified");
        }

        let _epoch = session.dlc.tick(50_000);

        Ok(Response::new(pb::EvaluateAndCertifyResponse {
            certified,
            e_value,
            wealth: session.ledger.wealth,
            barrier: session.ledger.barrier(),
            k_bits_total: session.ledger.k_bits_total,
            capsule_hash,
            etl_index,
        }))
    }

    async fn get_ledger(
        &self,
        request: Request<pb::GetLedgerRequest>,
    ) -> Result<Response<pb::LedgerSnapshot>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let sessions = self.state.sessions.lock();
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| Status::not_found("session not found"))?;

        let events = session
            .ledger
            .events
            .iter()
            .map(|e| pb::LedgerEvent {
                kind: e.kind.clone(),
                bits: e.bits,
                json_meta: serde_json::to_string(&e.meta).unwrap_or_else(|_| "null".to_string()),
            })
            .collect();

        Ok(Response::new(pb::LedgerSnapshot {
            alpha: session.ledger.alpha,
            alpha_prime: session.ledger.alpha_prime(),
            k_bits_total: session.ledger.k_bits_total,
            barrier: session.ledger.barrier(),
            wealth: session.ledger.wealth,
            events,
        }))
    }

    async fn get_etl_root(
        &self,
        _request: Request<pb::GetEtlRootRequest>,
    ) -> Result<Response<pb::GetEtlRootResponse>, Status> {
        let etl = self.state.etl.lock();
        Ok(Response::new(pb::GetEtlRootResponse {
            root_hash_hex: etl.root_hex(),
            tree_size: etl.tree_size(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::oneshot;

    #[tokio::test]
    async fn grpc_smoke_create_session_and_holdout() {
        let dir = tempfile::tempdir().unwrap();
        let etl_path = dir.path().join("etl.log");
        let (_state, svc) = EvidenceOsService::build(etl_path.to_str().unwrap()).unwrap();

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(pb::evidence_os_server::EvidenceOsServer::new(svc))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = rx.await;
                    },
                )
                .await
                .unwrap();
        });

        let endpoint = format!("http://{}", local_addr);
        let mut client = pb::evidence_os_client::EvidenceOsClient::connect(endpoint)
            .await
            .unwrap();

        let health = client
            .health(pb::HealthRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(health.status, "SERVING");

        let sess = client
            .create_session(pb::CreateSessionRequest {
                alpha: 0.05,
                epoch_size: 10_000,
                hysteresis_delta: 0.0,
                oracle_buckets: 256,
                joint_bits_budget: 0,
                binom_p1: 0.6,
            })
            .await
            .unwrap()
            .into_inner();

        let hold = client
            .init_holdout(pb::InitHoldoutRequest {
                session_id: sess.session_id.clone(),
                kind: pb::HoldoutKind::Labels as i32,
                seed: 123,
                size: 32,
            })
            .await
            .unwrap()
            .into_inner();

        // Query once.
        let preds = vec![0u8; 32];
        let reply = client
            .oracle_accuracy(pb::OracleAccuracyRequest {
                session_id: sess.session_id.clone(),
                holdout_id: hold.holdout_id.clone(),
                predictions: preds,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.num_buckets, 256);

        // Shutdown.
        let _ = tx.send(());
    }
}
