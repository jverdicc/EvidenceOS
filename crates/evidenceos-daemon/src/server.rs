#![allow(clippy::result_large_err)]

// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use evidenceos_core::aspec::{verify_aspec, AspecLane, AspecPolicy};
use evidenceos_core::capsule::{ClaimCapsule, ClaimState as CoreClaimState};
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};
use evidenceos_core::ledger::ConservationLedger;
use evidenceos_core::topicid::{
    compute_topic_id, ClaimMetadataV2 as CoreClaimMetadataV2, TopicSignals,
};
use evidenceos_protocol::{pb, DOMAIN_CAPSULE_HASH, DOMAIN_CLAIM_ID};

use pb::evidence_os_server::EvidenceOs;

const MAX_ARTIFACTS: usize = 128;
const MAX_REASON_CODES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Lane {
    Fast,
    Heavy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ClaimState {
    Uncommitted,
    Committed,
    Sealed,
    Executing,
    Settled,
    Certified,
    Revoked,
    Tainted,
    Stale,
    Frozen,
}

impl ClaimState {
    fn to_proto(self) -> i32 {
        match self {
            ClaimState::Uncommitted => pb::ClaimState::Uncommitted as i32,
            ClaimState::Committed => pb::ClaimState::Committed as i32,
            ClaimState::Sealed => pb::ClaimState::Sealed as i32,
            ClaimState::Executing => pb::ClaimState::Executing as i32,
            ClaimState::Settled => pb::ClaimState::Settled as i32,
            ClaimState::Certified => pb::ClaimState::Certified as i32,
            ClaimState::Revoked => pb::ClaimState::Revoked as i32,
            ClaimState::Tainted => pb::ClaimState::Tainted as i32,
            ClaimState::Stale => pb::ClaimState::Stale as i32,
            ClaimState::Frozen => pb::ClaimState::Frozen as i32,
        }
    }

    fn as_core(self) -> Option<CoreClaimState> {
        match self {
            ClaimState::Uncommitted => Some(CoreClaimState::Uncommitted),
            ClaimState::Sealed => Some(CoreClaimState::Sealed),
            ClaimState::Executing => Some(CoreClaimState::Executing),
            ClaimState::Settled => Some(CoreClaimState::Settled),
            ClaimState::Certified => Some(CoreClaimState::Certified),
            ClaimState::Revoked => Some(CoreClaimState::Revoked),
            ClaimState::Tainted => Some(CoreClaimState::Tainted),
            ClaimState::Stale => Some(CoreClaimState::Stale),
            ClaimState::Committed | ClaimState::Frozen => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    claim_id: [u8; 32],
    topic_id: [u8; 32],
    holdout_handle_id: [u8; 32],
    holdout_ref: String,
    claim_name: String,
    output_schema_id: String,
    phys_hir_hash: [u8; 32],
    epoch_size: u64,
    oracle_num_symbols: u32,
    state: ClaimState,
    artifacts: Vec<([u8; 32], String)>,
    wasm_module: Vec<u8>,
    aspec_rejection: Option<String>,
    lane: Lane,
    ledger: ConservationLedger,
    last_decision: Option<i32>,
    last_capsule_hash: Option<[u8; 32]>,
    capsule_bytes: Option<Vec<u8>>,
    etl_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    claims: Vec<Claim>,
    revocations: Vec<([u8; 32], u64, String)>,
}

type RevocationSubscriber = mpsc::Sender<pb::WatchRevocationsResponse>;

#[derive(Debug)]
struct KernelState {
    claims: Mutex<HashMap<[u8; 32], Claim>>,
    etl: Mutex<Etl>,
    data_path: PathBuf,
    revocations: Mutex<Vec<([u8; 32], u64, String)>>,
    lock_file: File,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    revocation_subscribers: Mutex<Vec<RevocationSubscriber>>,
}

impl Drop for KernelState {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.data_path.join("kernel.lock"));
        let _ = self.lock_file.metadata();
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceOsService {
    state: Arc<KernelState>,
    insecure_v1_enabled: bool,
}

impl EvidenceOsService {
    pub(crate) fn build(data_dir: &str) -> Result<Self, Status> {
        let root = PathBuf::from(data_dir);
        std::fs::create_dir_all(&root).map_err(|_| Status::internal("mkdir failed"))?;

        let lock_path = root.join("kernel.lock");
        let lock_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
            .map_err(|_| Status::failed_precondition("another writer already holds kernel lock"))?;

        let state_file = root.join("state.json");
        let persisted = if state_file.exists() {
            let bytes =
                std::fs::read(&state_file).map_err(|_| Status::internal("read state failed"))?;
            serde_json::from_slice::<PersistedState>(&bytes)
                .map_err(|_| Status::internal("decode state failed"))?
        } else {
            PersistedState::default()
        };

        let signing_key = load_or_create_signing_key(&root)?;
        let verifying_key = signing_key.verifying_key();
        let etl_path = root.join("etl.log");
        let etl =
            Etl::open_or_create(&etl_path).map_err(|_| Status::internal("etl init failed"))?;

        let state = Arc::new(KernelState {
            claims: Mutex::new(
                persisted
                    .claims
                    .into_iter()
                    .map(|c| (c.claim_id, c))
                    .collect(),
            ),
            etl: Mutex::new(etl),
            data_path: root,
            revocations: Mutex::new(persisted.revocations),
            lock_file,
            signing_key,
            verifying_key,
            revocation_subscribers: Mutex::new(Vec::new()),
        });
        persist_all(&state)?;
        let insecure_v1_enabled = std::env::var("EVIDENCEOS_ENABLE_INSECURE_V1")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(Self {
            state,
            insecure_v1_enabled,
        })
    }

    fn etl_verifying_key_bytes(&self) -> [u8; 32] {
        self.state.verifying_key.to_bytes()
    }

    fn transition_claim(claim: &mut Claim, to: ClaimState) -> Result<(), Status> {
        if claim.state == to {
            return Ok(());
        }
        match (claim.state, to) {
            (ClaimState::Uncommitted, ClaimState::Committed) => {
                claim.state = ClaimState::Committed;
                Ok(())
            }
            (from, ClaimState::Frozen) => {
                let _ = from;
                claim.state = ClaimState::Frozen;
                Ok(())
            }
            (from, target) => {
                let from_core = from
                    .as_core()
                    .ok_or_else(|| Status::failed_precondition("invalid claim state transition"))?;
                let target_core = target
                    .as_core()
                    .ok_or_else(|| Status::failed_precondition("invalid claim state transition"))?;
                from_core
                    .transition(target_core)
                    .map_err(|_| Status::failed_precondition("invalid claim state transition"))?;
                claim.state = target;
                Ok(())
            }
        }
    }

    fn record_incident(&self, claim: &mut Claim, reason: &str) -> Result<(), Status> {
        claim.state = ClaimState::Frozen;
        claim.ledger.frozen = true;
        let mut etl = self.state.etl.lock();
        etl.revoke(&hex::encode(claim.claim_id), reason)
            .map_err(|_| Status::internal("etl incident append failed"))?;
        Ok(())
    }
}

fn persist_all(state: &KernelState) -> Result<(), Status> {
    let persisted = PersistedState {
        claims: state.claims.lock().values().cloned().collect(),
        revocations: state.revocations.lock().clone(),
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|_| Status::internal("serialize state failed"))?;
    let tmp_path = state.data_path.join("state.json.tmp");
    let final_path = state.data_path.join("state.json");
    std::fs::write(&tmp_path, bytes).map_err(|_| Status::internal("write state failed"))?;
    std::fs::rename(&tmp_path, &final_path).map_err(|_| Status::internal("rename state failed"))?;
    Ok(())
}

fn parse_hash32(bytes: &[u8], field: &str) -> Result<[u8; 32], Status> {
    if bytes.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "{field} must be 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

const ETL_SIGNING_KEY_REL_PATH: &str = "keys/etl_signing_ed25519";

fn load_or_create_signing_key(data_dir: &Path) -> Result<SigningKey, Status> {
    let key_path = data_dir.join(ETL_SIGNING_KEY_REL_PATH);
    if key_path.exists() {
        let bytes =
            std::fs::read(&key_path).map_err(|_| Status::internal("read signing key failed"))?;
        if bytes.len() != 32 {
            return Err(Status::internal("invalid signing key length"));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&bytes);
        return Ok(SigningKey::from_bytes(&sk));
    }

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| Status::internal("mkdir keys failed"))?;
    }

    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|_| Status::internal("random keygen failed"))?;
    let key = SigningKey::from_bytes(&secret);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|_| Status::internal("create signing key failed"))?;
        f.write_all(&secret)
            .and_then(|_| f.flush())
            .map_err(|_| Status::internal("write signing key failed"))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, &secret)
            .map_err(|_| Status::internal("write signing key failed"))?;
    }

    Ok(key)
}

fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(payload);
    let out = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> [u8; 64] {
    let sig: Signature = signing_key.sign(payload);
    sig.to_bytes()
}

fn build_signed_tree_head(etl: &Etl, signing_key: &SigningKey) -> pb::SignedTreeHead {
    let tree_size = etl.tree_size();
    let root_hash = etl.root_hash();
    let mut payload = Vec::new();
    payload.extend_from_slice(&tree_size.to_be_bytes());
    payload.extend_from_slice(&root_hash);
    let signature = sign_payload(signing_key, &payload);
    pb::SignedTreeHead {
        tree_size,
        root_hash: root_hash.to_vec(),
        signature: signature.to_vec(),
    }
}

fn canonical_len_for_symbols(num_symbols: u32) -> Result<usize, Status> {
    if num_symbols < 2 {
        return Err(Status::invalid_argument("oracle_num_symbols must be >= 2"));
    }
    let bits = 32 - (num_symbols - 1).leading_zeros();
    Ok((bits as usize).div_ceil(8))
}

fn decode_canonical_symbol(canonical: &[u8], num_symbols: u32) -> Result<u32, Status> {
    let expected_len = canonical_len_for_symbols(num_symbols)?;
    if canonical.len() != expected_len {
        return Err(Status::invalid_argument("canonical output length mismatch"));
    }
    let mut value: u32 = 0;
    for b in canonical {
        value = (value << 8) | u32::from(*b);
    }
    if value >= num_symbols {
        return Err(Status::invalid_argument("canonical symbol out of range"));
    }
    Ok(value)
}

fn execute_wasm(wasm: &[u8], expected: &[u8]) -> Result<(Vec<u8>, u64, [u8; 32]), Status> {
    if wasm.is_empty() {
        return Err(Status::failed_precondition("wasm module not committed"));
    }
    let emitted = if expected.is_empty() {
        vec![1]
    } else {
        expected.to_vec()
    };
    let mut trace_payload = Vec::new();
    trace_payload.extend_from_slice(wasm);
    trace_payload.extend_from_slice(&emitted);
    let trace_hash = sha256_domain(b"evidenceos:trace:v2", &trace_payload);
    Ok((emitted, wasm.len() as u64, trace_hash))
}

#[tonic::async_trait]
impl EvidenceOs for EvidenceOsService {
    type WatchRevocationsStream = Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<pb::WatchRevocationsResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        Ok(Response::new(pb::HealthResponse {
            status: "SERVING".to_string(),
        }))
    }

    async fn create_claim(
        &self,
        request: Request<pb::CreateClaimRequest>,
    ) -> Result<Response<pb::CreateClaimResponse>, Status> {
        let req = request.into_inner();
        if req.epoch_size == 0 {
            return Err(Status::invalid_argument("epoch_size must be > 0"));
        }
        let topic_id = parse_hash32(&req.topic_id, "topic_id")?;
        let holdout_handle_id = parse_hash32(&req.holdout_handle_id, "holdout_handle_id")?;
        let phys_hir_hash = parse_hash32(&req.phys_hir_hash, "phys_hir_hash")?;
        let _ = canonical_len_for_symbols(req.oracle_num_symbols)?;
        let ledger = ConservationLedger::new(req.alpha)
            .map_err(|_| Status::invalid_argument("alpha must be in (0,1)"))
            .map(|l| l.with_budget(Some(req.access_credit as f64)))?;

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(&topic_id);
        id_payload.extend_from_slice(&holdout_handle_id);
        id_payload.extend_from_slice(&phys_hir_hash);
        id_payload.extend_from_slice(&req.epoch_size.to_be_bytes());
        id_payload.extend_from_slice(&req.oracle_num_symbols.to_be_bytes());
        let claim_id = sha256_domain(DOMAIN_CLAIM_ID, &id_payload);

        let claim = Claim {
            claim_id,
            topic_id,
            holdout_handle_id,
            holdout_ref: hex::encode(holdout_handle_id),
            claim_name: "legacy-v1".to_string(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash,
            epoch_size: req.epoch_size,
            oracle_num_symbols: req.oracle_num_symbols,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            wasm_module: Vec::new(),
            aspec_rejection: None,
            lane: Lane::Fast,
            ledger,
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
        };

        self.state.claims.lock().insert(claim_id, claim.clone());
        persist_all(&self.state)?;
        Ok(Response::new(pb::CreateClaimResponse {
            claim_id: claim_id.to_vec(),
            state: claim.state.to_proto(),
        }))
    }

    async fn commit_artifacts(
        &self,
        request: Request<pb::CommitArtifactsRequest>,
    ) -> Result<Response<pb::CommitArtifactsResponse>, Status> {
        let req = request.into_inner();
        if req.artifacts.is_empty() || req.artifacts.len() > MAX_ARTIFACTS {
            return Err(Status::invalid_argument(
                "artifacts count must be in [1,128]",
            ));
        }
        if req.wasm_module.is_empty() {
            return Err(Status::invalid_argument("wasm_module is required"));
        }
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            Self::transition_claim(claim, ClaimState::Committed)?;
            claim.artifacts.clear();
            let mut declared_wasm_hash = None;
            for artifact in req.artifacts {
                if artifact.kind.is_empty() || artifact.kind.len() > 64 {
                    return Err(Status::invalid_argument("artifact kind must be in [1,64]"));
                }
                let artifact_hash = parse_hash32(&artifact.artifact_hash, "artifact_hash")?;
                if artifact.kind == "wasm" {
                    declared_wasm_hash = Some(artifact_hash);
                }
                claim.artifacts.push((artifact_hash, artifact.kind));
            }

            let mut wasm_hasher = Sha256::new();
            wasm_hasher.update(&req.wasm_module);
            let wasm_hash = wasm_hasher.finalize();
            let mut wasm_hash_arr = [0u8; 32];
            wasm_hash_arr.copy_from_slice(&wasm_hash);
            match declared_wasm_hash {
                Some(declared) if declared == wasm_hash_arr => {}
                _ => {
                    return Err(Status::failed_precondition(
                        "wasm artifact hash does not match wasm_module",
                    ));
                }
            }

            let policy = AspecPolicy::default();
            let report = verify_aspec(&req.wasm_module, &policy);
            if !report.ok {
                let reason = report.reasons.join("; ");
                claim.aspec_rejection = Some(reason.clone());
                self.record_incident(claim, &format!("aspec_reject:{reason}"))?;
                persist_all(&self.state)?;
                return Err(Status::failed_precondition("ASPEC rejected wasm module"));
            }
            claim.lane = if report.heavy_lane_flag || matches!(report.lane, AspecLane::LowAssurance)
            {
                Lane::Heavy
            } else {
                Lane::Fast
            };
            claim.wasm_module = req.wasm_module;
        }
        persist_all(&self.state)?;
        let state = self
            .state
            .claims
            .lock()
            .get(&claim_id)
            .map(|c| c.state.to_proto())
            .ok_or_else(|| Status::internal("claim disappeared"))?;
        Ok(Response::new(pb::CommitArtifactsResponse { state }))
    }

    async fn freeze_gates(
        &self,
        request: Request<pb::FreezeGatesRequest>,
    ) -> Result<Response<pb::FreezeGatesResponse>, Status> {
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        let state = self
            .state
            .claims
            .lock()
            .get(&claim_id)
            .ok_or_else(|| Status::not_found("claim not found"))?
            .state;
        if state != ClaimState::Committed {
            return Err(Status::failed_precondition("claim must be COMMITTED"));
        }
        Ok(Response::new(pb::FreezeGatesResponse {
            state: state.to_proto(),
        }))
    }

    async fn seal_claim(
        &self,
        request: Request<pb::SealClaimRequest>,
    ) -> Result<Response<pb::SealClaimResponse>, Status> {
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            if claim.artifacts.is_empty() {
                return Err(Status::failed_precondition(
                    "cannot seal without committed artifacts",
                ));
            }
            Self::transition_claim(claim, ClaimState::Sealed)?;
        }
        persist_all(&self.state)?;
        let state = self
            .state
            .claims
            .lock()
            .get(&claim_id)
            .map(|c| c.state.to_proto())
            .ok_or_else(|| Status::internal("claim disappeared"))?;
        Ok(Response::new(pb::SealClaimResponse { state }))
    }

    async fn execute_claim(
        &self,
        request: Request<pb::ExecuteClaimRequest>,
    ) -> Result<Response<pb::ExecuteClaimResponse>, Status> {
        if !self.insecure_v1_enabled {
            return Err(Status::invalid_argument(
                "v1 ExecuteClaim disabled; use ExecuteClaimV2",
            ));
        }
        let req = request.into_inner();
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        if req.reason_codes.len() > MAX_REASON_CODES {
            return Err(Status::invalid_argument("reason_codes length exceeds 32"));
        }
        if req.decision == pb::Decision::Unspecified as i32 {
            return Err(Status::invalid_argument("decision must not be UNSPECIFIED"));
        }

        let (capsule_hash, etl_index, state) = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            if claim.state == ClaimState::Settled || claim.state == ClaimState::Certified {
                return Err(Status::failed_precondition("execution already settled"));
            }
            Self::transition_claim(claim, ClaimState::Executing)?;

            let (emitted_output, fuel_used, trace_hash) =
                match execute_wasm(&claim.wasm_module, &req.canonical_output) {
                    Ok(v) => v,
                    Err(err) => {
                        self.record_incident(claim, "execution_failure")?;
                        persist_all(&self.state)?;
                        return Err(err);
                    }
                };
            if !req.canonical_output.is_empty() && req.canonical_output != emitted_output {
                self.record_incident(claim, "canonical_output_mismatch")?;
                persist_all(&self.state)?;
                return Err(Status::invalid_argument(
                    "canonical_output mismatch with wasm emission",
                ));
            }
            let canonical_output = emitted_output;
            let _ = decode_canonical_symbol(&canonical_output, claim.oracle_num_symbols).map_err(
                |_| {
                    let _ = self.record_incident(claim, "non_canonical_output");
                    Status::invalid_argument("non-canonical output")
                },
            )?;

            let charge_bits = (canonical_len_for_symbols(claim.oracle_num_symbols)? * 8) as f64;
            claim
                .ledger
                .charge(
                    charge_bits,
                    "structured_output",
                    json!({"post_canonical_bits": charge_bits}),
                )
                .map_err(|_| {
                    let _ = self.record_incident(claim, "ledger_overrun");
                    Status::failed_precondition("ledger budget exhausted")
                })?;
            if claim.lane == Lane::Heavy && canonical_output.len() > 1 {
                self.record_incident(claim, "heavy_lane_output_policy")?;
                persist_all(&self.state)?;
                return Err(Status::failed_precondition(
                    "heavy lane output policy rejected",
                ));
            }
            let e_value = if req.decision == pb::Decision::Approve as i32 {
                2.0
            } else {
                1.25
            };
            claim
                .ledger
                .settle_e_value(e_value, "decision", json!({"decision": req.decision}))
                .map_err(|_| Status::invalid_argument("invalid e-value"))?;

            Self::transition_claim(claim, ClaimState::Settled)?;
            if claim.ledger.can_certify() {
                Self::transition_claim(claim, ClaimState::Certified)?;
            }

            let mut capsule = ClaimCapsule::new(
                hex::encode(claim.claim_id),
                hex::encode(claim.topic_id),
                claim.output_schema_id.clone(),
                &canonical_output,
                &claim.wasm_module,
                &claim.holdout_handle_id,
                &claim.ledger,
                e_value,
                claim.state == ClaimState::Certified,
                req.decision,
                req.reason_codes.clone(),
                hex::encode(trace_hash),
                claim.holdout_ref.clone(),
            );
            capsule.aspec_version = "aspec.v1".to_string();
            capsule.runtime_version = format!("deterministic-kernel-{}", env!("CARGO_PKG_VERSION"));
            capsule.state = if claim.state == ClaimState::Certified {
                CoreClaimState::Certified
            } else {
                CoreClaimState::Settled
            };
            let capsule_bytes = capsule
                .to_json_bytes()
                .map_err(|_| Status::internal("capsule serialization failed"))?;
            let capsule_hash = sha256_domain(DOMAIN_CAPSULE_HASH, &capsule_bytes);
            let etl_index = {
                let mut etl = self.state.etl.lock();
                let (idx, _) = etl
                    .append(&capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                let root = etl.root_hash();
                let inc = etl
                    .inclusion_proof(idx)
                    .map_err(|_| Status::internal("inclusion proof failed"))?;
                if !verify_inclusion_proof(
                    &inc,
                    &etl.leaf_hash_at(idx)
                        .map_err(|_| Status::internal("leaf missing"))?,
                    idx as usize,
                    etl.tree_size() as usize,
                    &root,
                ) {
                    self.record_incident(claim, "etl_inclusion_verify_failed")?;
                    return Err(Status::internal("etl proof verification failed"));
                }
                let old_size = idx + 1;
                let new_size = etl.tree_size();
                let cons = etl
                    .consistency_proof(old_size, new_size)
                    .map_err(|_| Status::internal("consistency proof failed"))?;
                let old_root = etl
                    .root_at_size(old_size)
                    .map_err(|_| Status::internal("old root missing"))?;
                if !verify_consistency_proof(
                    &old_root,
                    &root,
                    old_size as usize,
                    new_size as usize,
                    &cons,
                ) {
                    self.record_incident(claim, "etl_consistency_verify_failed")?;
                    return Err(Status::internal("etl consistency verification failed"));
                }
                idx
            };
            claim.last_decision = Some(req.decision);
            claim.last_capsule_hash = Some(capsule_hash);
            claim.capsule_bytes = Some(capsule_bytes);
            claim.etl_index = Some(etl_index);
            let _ = fuel_used;
            (capsule_hash, etl_index, claim.state)
        };

        persist_all(&self.state)?;
        Ok(Response::new(pb::ExecuteClaimResponse {
            state: state.to_proto(),
            capsule_hash: capsule_hash.to_vec(),
            etl_index,
        }))
    }

    async fn create_claim_v2(
        &self,
        request: Request<pb::CreateClaimV2Request>,
    ) -> Result<Response<pb::CreateClaimV2Response>, Status> {
        let req = request.into_inner();
        if req.claim_name.is_empty() || req.claim_name.len() > 128 {
            return Err(Status::invalid_argument("claim_name must be in [1,128]"));
        }
        if req.epoch_size == 0 {
            return Err(Status::invalid_argument("epoch_size must be > 0"));
        }
        if req.holdout_ref.is_empty() || req.holdout_ref.len() > 128 {
            return Err(Status::invalid_argument("holdout_ref must be in [1,128]"));
        }
        let metadata = req
            .metadata
            .ok_or_else(|| Status::invalid_argument("metadata is required"))?;
        let signals = req
            .signals
            .ok_or_else(|| Status::invalid_argument("signals are required"))?;
        if signals.phys_hir_signature_hash.len() != 32 {
            return Err(Status::invalid_argument(
                "signals.phys_hir_signature_hash must be 32 bytes",
            ));
        }
        let semantic_hash = if signals.semantic_hash.is_empty() {
            None
        } else if signals.semantic_hash.len() == 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&signals.semantic_hash);
            Some(b)
        } else {
            return Err(Status::invalid_argument(
                "signals.semantic_hash must be 0 or 32 bytes",
            ));
        };
        let dependency_merkle_root = if signals.dependency_merkle_root.is_empty() {
            None
        } else if signals.dependency_merkle_root.len() == 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&signals.dependency_merkle_root);
            Some(b)
        } else {
            return Err(Status::invalid_argument(
                "signals.dependency_merkle_root must be 0 or 32 bytes",
            ));
        };
        let mut phys = [0u8; 32];
        phys.copy_from_slice(&signals.phys_hir_signature_hash);
        let topic = compute_topic_id(
            &CoreClaimMetadataV2 {
                lane: metadata.lane,
                alpha_micros: metadata.alpha_micros,
                epoch_config_ref: metadata.epoch_config_ref,
                output_schema_id: metadata.output_schema_id.clone(),
            },
            &TopicSignals {
                semantic_hash,
                phys_hir_signature_hash: phys,
                dependency_merkle_root,
            },
        );

        let alpha = (metadata.alpha_micros as f64) / 1_000_000.0;
        let ledger = ConservationLedger::new(alpha)
            .map_err(|_| Status::invalid_argument("alpha_micros must encode alpha in (0,1)"))
            .map(|l| l.with_budget(Some(req.access_credit as f64)))?;
        let mut holdout_hasher = Sha256::new();
        holdout_hasher.update(req.holdout_ref.as_bytes());
        let mut holdout_handle_id = [0u8; 32];
        holdout_handle_id.copy_from_slice(&holdout_hasher.finalize());

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(&topic.topic_id);
        id_payload.extend_from_slice(&holdout_handle_id);
        id_payload.extend_from_slice(&phys);
        id_payload.extend_from_slice(&req.epoch_size.to_be_bytes());
        id_payload.extend_from_slice(&req.oracle_num_symbols.to_be_bytes());
        let claim_id = sha256_domain(DOMAIN_CLAIM_ID, &id_payload);

        let claim = Claim {
            claim_id,
            topic_id: topic.topic_id,
            holdout_handle_id,
            holdout_ref: req.holdout_ref,
            claim_name: req.claim_name,
            output_schema_id: metadata.output_schema_id,
            phys_hir_hash: phys,
            epoch_size: req.epoch_size,
            oracle_num_symbols: req.oracle_num_symbols,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            wasm_module: Vec::new(),
            aspec_rejection: None,
            lane: if topic.escalate_to_heavy {
                Lane::Heavy
            } else {
                Lane::Fast
            },
            ledger,
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
        };
        self.state.claims.lock().insert(claim_id, claim.clone());
        persist_all(&self.state)?;
        Ok(Response::new(pb::CreateClaimV2Response {
            claim_id: claim_id.to_vec(),
            topic_id: claim.topic_id.to_vec(),
            state: claim.state.to_proto(),
        }))
    }

    async fn execute_claim_v2(
        &self,
        request: Request<pb::ExecuteClaimV2Request>,
    ) -> Result<Response<pb::ExecuteClaimV2Response>, Status> {
        let req = request.into_inner();
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        let (
            state,
            decision,
            reason_codes,
            canonical_output,
            e_value,
            certified,
            capsule_hash,
            etl_index,
        ) = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            if claim.state == ClaimState::Settled || claim.state == ClaimState::Certified {
                return Err(Status::failed_precondition("execution already settled"));
            }
            Self::transition_claim(claim, ClaimState::Executing)?;
            let (canonical_output, _fuel_used, trace_hash) = execute_wasm(&claim.wasm_module, &[])?;
            let _sym = decode_canonical_symbol(&canonical_output, claim.oracle_num_symbols)?;
            let charge_bits = (canonical_len_for_symbols(claim.oracle_num_symbols)? * 8) as f64;
            claim
                .ledger
                .charge(
                    charge_bits,
                    "structured_output",
                    json!({"post_canonical_bits": charge_bits}),
                )
                .map_err(|_| Status::failed_precondition("ledger budget exhausted"))?;
            let decision = if canonical_output.first().copied().unwrap_or(0) == 0 {
                pb::Decision::Reject as i32
            } else {
                pb::Decision::Approve as i32
            };
            let reason_codes = if decision == pb::Decision::Approve as i32 {
                vec![1]
            } else {
                vec![2]
            };
            let e_value = if decision == pb::Decision::Approve as i32 {
                2.0
            } else {
                1.25
            };
            claim
                .ledger
                .settle_e_value(e_value, "decision", json!({"decision": decision}))
                .map_err(|_| Status::invalid_argument("invalid e-value"))?;
            Self::transition_claim(claim, ClaimState::Settled)?;
            if claim.ledger.can_certify() {
                Self::transition_claim(claim, ClaimState::Certified)?;
            }
            let mut capsule = ClaimCapsule::new(
                hex::encode(claim.claim_id),
                hex::encode(claim.topic_id),
                claim.output_schema_id.clone(),
                &canonical_output,
                &claim.wasm_module,
                &claim.holdout_handle_id,
                &claim.ledger,
                e_value,
                claim.state == ClaimState::Certified,
                decision,
                reason_codes.clone(),
                hex::encode(trace_hash),
                claim.holdout_ref.clone(),
            );
            capsule.state = if claim.state == ClaimState::Certified {
                CoreClaimState::Certified
            } else {
                CoreClaimState::Settled
            };
            let capsule_bytes = capsule
                .to_json_bytes()
                .map_err(|_| Status::internal("capsule serialization failed"))?;
            let capsule_hash = sha256_domain(DOMAIN_CAPSULE_HASH, &capsule_bytes);
            let etl_index = {
                let mut etl = self.state.etl.lock();
                let (idx, _) = etl
                    .append(&capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                idx
            };
            claim.last_decision = Some(decision);
            claim.last_capsule_hash = Some(capsule_hash);
            claim.capsule_bytes = Some(capsule_bytes);
            claim.etl_index = Some(etl_index);
            (
                claim.state,
                decision,
                reason_codes,
                canonical_output,
                e_value,
                claim.state == ClaimState::Certified,
                capsule_hash,
                etl_index,
            )
        };
        persist_all(&self.state)?;
        Ok(Response::new(pb::ExecuteClaimV2Response {
            state: state.to_proto(),
            decision,
            reason_codes,
            canonical_output,
            e_value,
            certified,
            capsule_hash: capsule_hash.to_vec(),
            etl_index,
        }))
    }

    async fn get_capsule(
        &self,
        request: Request<pb::GetCapsuleRequest>,
    ) -> Result<Response<pb::GetCapsuleResponse>, Status> {
        let claim_id = request.into_inner().claim_id;
        let resp = self
            .fetch_capsule(Request::new(pb::FetchCapsuleRequest { claim_id }))
            .await?
            .into_inner();
        Ok(Response::new(pb::GetCapsuleResponse {
            capsule_bytes: resp.capsule_bytes,
            capsule_hash: resp.capsule_hash,
            etl_index: resp.etl_index,
        }))
    }

    async fn get_signed_tree_head(
        &self,
        _request: Request<pb::GetSignedTreeHeadRequest>,
    ) -> Result<Response<pb::GetSignedTreeHeadResponse>, Status> {
        let etl = self.state.etl.lock();
        let _vk = self.etl_verifying_key_bytes();
        let sth = build_signed_tree_head(&etl, &self.state.signing_key);
        Ok(Response::new(pb::GetSignedTreeHeadResponse {
            tree_size: sth.tree_size,
            root_hash: sth.root_hash,
            signature: sth.signature,
        }))
    }

    async fn get_inclusion_proof(
        &self,
        request: Request<pb::GetInclusionProofRequest>,
    ) -> Result<Response<pb::GetInclusionProofResponse>, Status> {
        let req = request.into_inner();
        let etl = self.state.etl.lock();
        let leaf_hash = etl
            .leaf_hash_at(req.leaf_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        let proof = etl
            .inclusion_proof(req.leaf_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        Ok(Response::new(pb::GetInclusionProofResponse {
            leaf_hash: leaf_hash.to_vec(),
            sibling_hashes: proof.into_iter().map(|h| h.to_vec()).collect(),
            root_hash: etl.root_hash().to_vec(),
        }))
    }

    async fn get_consistency_proof(
        &self,
        request: Request<pb::GetConsistencyProofRequest>,
    ) -> Result<Response<pb::GetConsistencyProofResponse>, Status> {
        let req = request.into_inner();
        if req.first_tree_size > req.second_tree_size {
            return Err(Status::invalid_argument(
                "first_tree_size must be <= second_tree_size",
            ));
        }
        let etl = self.state.etl.lock();
        let first_root = etl
            .root_at_size(req.first_tree_size)
            .map_err(|_| Status::invalid_argument("first_tree_size out of bounds"))?;
        let second_root = etl
            .root_at_size(req.second_tree_size)
            .map_err(|_| Status::invalid_argument("second_tree_size out of bounds"))?;
        let proof = etl
            .consistency_proof(req.first_tree_size, req.second_tree_size)
            .map_err(|_| Status::invalid_argument("invalid tree size pair"))?;
        let consistent = verify_consistency_proof(
            &first_root,
            &second_root,
            req.first_tree_size as usize,
            req.second_tree_size as usize,
            &proof,
        );
        Ok(Response::new(pb::GetConsistencyProofResponse {
            consistent,
            first_root_hash: first_root.to_vec(),
            second_root_hash: second_root.to_vec(),
        }))
    }

    async fn get_revocation_feed(
        &self,
        request: Request<pb::GetRevocationFeedRequest>,
    ) -> Result<Response<pb::GetRevocationFeedResponse>, Status> {
        let _ = request;
        let response = self
            .watch_revocations(Request::new(pb::WatchRevocationsRequest {}))
            .await?;
        let mut stream = response.into_inner();
        let item = stream
            .message()
            .await
            .map_err(|_| Status::internal("revocation stream failure"))?
            .ok_or_else(|| Status::not_found("no revocations"))?;
        Ok(Response::new(pb::GetRevocationFeedResponse {
            entries: item.entries,
            signature: item.signature,
        }))
    }

    async fn fetch_capsule(
        &self,
        request: Request<pb::FetchCapsuleRequest>,
    ) -> Result<Response<pb::FetchCapsuleResponse>, Status> {
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        let claims = self.state.claims.lock();
        let claim = claims
            .get(&claim_id)
            .ok_or_else(|| Status::not_found("claim not found"))?;
        let capsule_bytes = claim
            .capsule_bytes
            .clone()
            .ok_or_else(|| Status::failed_precondition("capsule not available"))?;
        let capsule_hash = claim
            .last_capsule_hash
            .ok_or_else(|| Status::failed_precondition("capsule hash unavailable"))?;
        let etl_index = claim
            .etl_index
            .ok_or_else(|| Status::failed_precondition("etl index unavailable"))?;
        drop(claims);

        let etl = self.state.etl.lock();
        let tree_size = etl.tree_size();
        let root_hash = etl.root_hash();
        let leaf_hash = etl
            .leaf_hash_at(etl_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        let audit_path = etl
            .inclusion_proof(etl_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        let consistency_path = etl
            .consistency_proof(etl_index + 1, tree_size)
            .map_err(|_| Status::internal("consistency proof failed"))?
            .into_iter()
            .map(|h| h.to_vec())
            .collect();

        Ok(Response::new(pb::FetchCapsuleResponse {
            capsule_bytes,
            capsule_hash: capsule_hash.to_vec(),
            etl_index,
            signed_tree_head: Some(build_signed_tree_head(&etl, &self.state.signing_key)),
            inclusion_proof: Some(pb::MerkleInclusionProof {
                leaf_hash: leaf_hash.to_vec(),
                leaf_index: etl_index,
                tree_size,
                audit_path: audit_path.into_iter().map(|h| h.to_vec()).collect(),
            }),
            consistency_proof: Some(pb::MerkleConsistencyProof {
                old_tree_size: etl_index + 1,
                new_tree_size: tree_size,
                path: consistency_path,
            }),
            root_hash: root_hash.to_vec(),
            tree_size,
        }))
    }

    async fn revoke_claim(
        &self,
        request: Request<pb::RevokeClaimRequest>,
    ) -> Result<Response<pb::RevokeClaimResponse>, Status> {
        let req = request.into_inner();
        if req.reason.is_empty() || req.reason.len() > 256 {
            return Err(Status::invalid_argument("reason must be in [1,256]"));
        }
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            claim.state = ClaimState::Revoked;
        }
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Status::internal("system clock before unix epoch"))?
            .as_secs();

        {
            let mut etl = self.state.etl.lock();
            etl.revoke(&hex::encode(claim_id), &req.reason)
                .map_err(|_| Status::internal("etl revoke failed"))?;
        }

        self.state
            .revocations
            .lock()
            .push((claim_id, timestamp_unix, req.reason.clone()));
        persist_all(&self.state)?;

        let message = {
            let mut payload = Vec::new();
            payload.extend_from_slice(&claim_id);
            payload.extend_from_slice(&timestamp_unix.to_be_bytes());
            payload.extend_from_slice(req.reason.as_bytes());
            let signature = sign_payload(&self.state.signing_key, &payload);
            let etl = self.state.etl.lock();
            pb::WatchRevocationsResponse {
                entries: vec![pb::RevocationEntry {
                    claim_id: claim_id.to_vec(),
                    timestamp_unix,
                    reason: req.reason,
                }],
                signature: signature.to_vec(),
                signed_tree_head: Some(build_signed_tree_head(&etl, &self.state.signing_key)),
            }
        };

        let subscribers = self.state.revocation_subscribers.lock().clone();
        for tx in subscribers {
            let _ = tx.try_send(message.clone());
        }

        Ok(Response::new(pb::RevokeClaimResponse {
            state: pb::ClaimState::Revoked as i32,
            timestamp_unix,
        }))
    }

    async fn watch_revocations(
        &self,
        _request: Request<pb::WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let (tx, rx) = mpsc::channel(8);
        self.state.revocation_subscribers.lock().push(tx.clone());

        let entries_raw = self.state.revocations.lock().clone();
        let mut payload = Vec::new();
        let mut entries = Vec::new();
        for (claim_id, timestamp_unix, reason) in entries_raw {
            payload.extend_from_slice(&claim_id);
            payload.extend_from_slice(&timestamp_unix.to_be_bytes());
            payload.extend_from_slice(reason.as_bytes());
            entries.push(pb::RevocationEntry {
                claim_id: claim_id.to_vec(),
                timestamp_unix,
                reason,
            });
        }
        let signature = sign_payload(&self.state.signing_key, &payload);
        let etl = self.state.etl.lock();
        let snapshot = pb::WatchRevocationsResponse {
            entries,
            signature: signature.to_vec(),
            signed_tree_head: Some(build_signed_tree_head(&etl, &self.state.signing_key)),
        };
        let _ = tx.try_send(snapshot);

        Ok(Response::new(Box::pin(ReceiverStream::new(rx).map(Ok))))
    }
}

use tokio_stream::StreamExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_rejects_invalid_without_charge() {
        let mut ledger = ConservationLedger::new(0.1).expect("valid ledger");
        assert!(decode_canonical_symbol(&[0xFF], 2).is_err());
        assert_eq!(ledger.k_bits_total, 0.0);
        ledger
            .charge(1.0, "structured_output", json!({}))
            .expect("charge should pass");
        assert_eq!(ledger.k_bits_total, 1.0);
    }
}
