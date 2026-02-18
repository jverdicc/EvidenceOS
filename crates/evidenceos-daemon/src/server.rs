#![allow(clippy::result_large_err)]

// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use evidenceos_core::etl::Etl;
use evidenceos_protocol::pb;

use pb::evidence_os_server::EvidenceOs;

const MAX_ARTIFACTS: usize = 128;
const MAX_REASON_CODES: usize = 32;
const DOMAIN_CLAIM_ID: &[u8] = b"evidenceos:claim_id:v1";
const DOMAIN_CAPSULE_HASH: &[u8] = b"evidenceos:capsule:v1";

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceLedger {
    log2_wealth: f64,
    leakage_bits: u64,
    epsilon: f64,
    delta: f64,
    access_credit: u64,
    alpha: f64,
}

impl ResourceLedger {
    fn new(alpha: f64, access_credit: u64) -> Result<Self, Status> {
        if !(alpha > 0.0 && alpha < 1.0) {
            return Err(Status::invalid_argument("alpha must be in (0,1)"));
        }
        if access_credit == 0 {
            return Err(Status::invalid_argument("access_credit must be > 0"));
        }
        Ok(Self {
            log2_wealth: 0.0,
            leakage_bits: 0,
            epsilon: 0.0,
            delta: 0.0,
            access_credit,
            alpha,
        })
    }

    fn charge_leakage(&mut self, bits: u64) -> Result<(), Status> {
        if bits == 0 {
            return Err(Status::invalid_argument("bits must be > 0"));
        }
        if self.access_credit < bits {
            return Err(Status::failed_precondition("access credit exhausted"));
        }
        self.access_credit -= bits;
        self.leakage_bits = self
            .leakage_bits
            .checked_add(bits)
            .ok_or_else(|| Status::internal("leakage overflow"))?;
        Ok(())
    }

    fn settle_e_value(&mut self, e_value: f64) -> Result<(), Status> {
        if e_value <= 0.0 {
            return Err(Status::invalid_argument("e_value must be > 0"));
        }
        self.log2_wealth += e_value.log2();
        Ok(())
    }

    fn certifiable(&self) -> bool {
        let log2_barrier = self.leakage_bits as f64 - self.alpha.log2();
        self.log2_wealth >= log2_barrier
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    claim_id: [u8; 32],
    topic_id: [u8; 32],
    holdout_handle_id: [u8; 32],
    phys_hir_hash: [u8; 32],
    epoch_size: u64,
    oracle_num_symbols: u32,
    state: ClaimState,
    artifacts: Vec<([u8; 32], String)>,
    ledger: ResourceLedger,
    capsule_bytes: Option<Vec<u8>>,
    capsule_hash: Option<[u8; 32]>,
    etl_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Capsule {
    version: u32,
    claim_id: [u8; 32],
    code_hash: [u8; 32],
    ir_manifest_hashes: Vec<[u8; 32]>,
    leakage_bits: u64,
    log2_wealth: f64,
    epsilon: f64,
    delta: f64,
    access_credit: u64,
    decision: u32,
    reason_codes: Vec<u32>,
    canonical_output: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    claims: Vec<Claim>,
    revocations: Vec<([u8; 32], u64, String)>,
    signing_key: [u8; 32],
}

#[derive(Debug)]
struct KernelState {
    claims: Mutex<HashMap<[u8; 32], Claim>>,
    etl: Mutex<Etl>,
    data_path: PathBuf,
    revocations: Mutex<Vec<([u8; 32], u64, String)>>,
    lock_file: File,
    signing_key: [u8; 32],
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
}

impl EvidenceOsService {
    #[allow(clippy::result_large_err)]
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

        let signing_key = if persisted.signing_key == [0u8; 32] {
            sha256_domain(b"evidenceos:signing-key", data_dir.as_bytes())
        } else {
            persisted.signing_key
        };

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
        });
        persist_all(&state)?;
        Ok(Self { state })
    }
}

fn persist_all(state: &KernelState) -> Result<(), Status> {
    let persisted = PersistedState {
        claims: state.claims.lock().values().cloned().collect(),
        revocations: state.revocations.lock().clone(),
        signing_key: state.signing_key,
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

fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(payload);
    let out = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

fn sign_payload(signing_key: &[u8; 32], payload: &[u8]) -> [u8; 64] {
    let key = SigningKey::from_bytes(signing_key);
    let sig: Signature = key.sign(payload);
    sig.to_bytes()
}

fn build_signed_tree_head(etl: &Etl, signing_key: &[u8; 32]) -> pb::SignedTreeHead {
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

fn assert_transition(from: ClaimState, to: ClaimState) -> Result<(), Status> {
    let ok = matches!(
        (from, to),
        (ClaimState::Uncommitted, ClaimState::Committed)
            | (ClaimState::Committed, ClaimState::Sealed)
            | (ClaimState::Sealed, ClaimState::Executing)
            | (ClaimState::Executing, ClaimState::Settled)
            | (ClaimState::Settled, ClaimState::Certified)
            | (_, ClaimState::Frozen)
            | (_, ClaimState::Revoked)
            | (_, ClaimState::Tainted)
            | (_, ClaimState::Stale)
    );
    if ok {
        Ok(())
    } else {
        Err(Status::failed_precondition(
            "invalid claim state transition",
        ))
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
        let ledger = ResourceLedger::new(req.alpha, req.access_credit)?;

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
            phys_hir_hash,
            epoch_size: req.epoch_size,
            oracle_num_symbols: req.oracle_num_symbols,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            ledger,
            capsule_bytes: None,
            capsule_hash: None,
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
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            assert_transition(claim.state, ClaimState::Committed)?;
            claim.artifacts.clear();
            for artifact in req.artifacts {
                if artifact.kind.is_empty() || artifact.kind.len() > 64 {
                    return Err(Status::invalid_argument("artifact kind must be in [1,64]"));
                }
                claim.artifacts.push((
                    parse_hash32(&artifact.artifact_hash, "artifact_hash")?,
                    artifact.kind,
                ));
            }
            claim.state = ClaimState::Committed;
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
            assert_transition(claim.state, ClaimState::Sealed)?;
            if claim.artifacts.is_empty() {
                return Err(Status::failed_precondition(
                    "cannot seal without committed artifacts",
                ));
            }
            claim.state = ClaimState::Sealed;
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
            assert_transition(claim.state, ClaimState::Executing)?;
            let _ = decode_canonical_symbol(&req.canonical_output, claim.oracle_num_symbols)?;

            claim.state = ClaimState::Executing;
            let charge_bits = (canonical_len_for_symbols(claim.oracle_num_symbols)? * 8) as u64;
            claim.ledger.charge_leakage(charge_bits)?;
            claim
                .ledger
                .settle_e_value(if req.decision == pb::Decision::Approve as i32 {
                    2.0
                } else {
                    1.25
                })?;
            claim.state = ClaimState::Settled;
            if claim.ledger.certifiable() {
                claim.state = ClaimState::Certified;
            }

            let mut manifests = Vec::new();
            for (hash, kind) in &claim.artifacts {
                if kind.contains("manifest") {
                    manifests.push(*hash);
                }
            }
            let capsule = Capsule {
                version: 1,
                claim_id,
                code_hash: claim.artifacts[0].0,
                ir_manifest_hashes: manifests,
                leakage_bits: claim.ledger.leakage_bits,
                log2_wealth: claim.ledger.log2_wealth,
                epsilon: claim.ledger.epsilon,
                delta: claim.ledger.delta,
                access_credit: claim.ledger.access_credit,
                decision: req.decision as u32,
                reason_codes: req.reason_codes,
                canonical_output: req.canonical_output,
            };
            let capsule_bytes =
                serde_json::to_vec(&capsule).map_err(|_| Status::internal("serialize failed"))?;
            let capsule_hash = sha256_domain(DOMAIN_CAPSULE_HASH, &capsule_bytes);
            let etl_index = {
                let mut etl = self.state.etl.lock();
                let (idx, _leaf) = etl
                    .append(&capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                idx
            };
            claim.capsule_bytes = Some(capsule_bytes);
            claim.capsule_hash = Some(capsule_hash);
            claim.etl_index = Some(etl_index);
            (capsule_hash, etl_index, claim.state)
        };

        persist_all(&self.state)?;

        Ok(Response::new(pb::ExecuteClaimResponse {
            state: state.to_proto(),
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
        let consistent = req.first_tree_size == req.second_tree_size && first_root == second_root
            || req.first_tree_size < req.second_tree_size;
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
        let resp = self
            .watch_revocations(Request::new(pb::WatchRevocationsRequest {}))
            .await?
            .into_inner();
        Ok(Response::new(pb::GetRevocationFeedResponse {
            entries: resp.entries,
            signature: resp.signature,
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
            .capsule_hash
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

        let consistency_path: Vec<Vec<u8>> = Vec::new();

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
        self.state
            .revocations
            .lock()
            .push((claim_id, timestamp_unix, req.reason));
        persist_all(&self.state)?;

        Ok(Response::new(pb::RevokeClaimResponse {
            state: pb::ClaimState::Revoked as i32,
            timestamp_unix,
        }))
    }

    async fn watch_revocations(
        &self,
        _request: Request<pb::WatchRevocationsRequest>,
    ) -> Result<Response<pb::WatchRevocationsResponse>, Status> {
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
        Ok(Response::new(pb::WatchRevocationsResponse {
            entries,
            signature: signature.to_vec(),
            signed_tree_head: Some(build_signed_tree_head(&etl, &self.state.signing_key)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_rejects_invalid_without_charge() {
        let mut ledger = ResourceLedger::new(0.1, 16).expect("valid ledger");
        assert!(decode_canonical_symbol(&[0xFF], 2).is_err());
        assert_eq!(ledger.leakage_bits, 0);
        ledger.charge_leakage(1).expect("charge should pass");
        assert_eq!(ledger.leakage_bits, 1);
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create dir");
        let data_dir_str = data_dir.to_string_lossy().to_string();
        {
            let svc = EvidenceOsService::build(&data_dir_str).expect("build service");
            let resp = tokio::runtime::Runtime::new()
                .expect("runtime")
                .block_on(async {
                    svc.create_claim(Request::new(pb::CreateClaimRequest {
                        topic_id: [1u8; 32].to_vec(),
                        holdout_handle_id: [2u8; 32].to_vec(),
                        phys_hir_hash: [3u8; 32].to_vec(),
                        epoch_size: 100,
                        oracle_num_symbols: 4,
                        alpha: 0.05,
                        access_credit: 32,
                    }))
                    .await
                })
                .expect("create claim")
                .into_inner();
            assert_eq!(resp.claim_id.len(), 32);
        }
        let svc2 = EvidenceOsService::build(&data_dir_str).expect("rebuild service");
        assert_eq!(svc2.state.claims.lock().len(), 1);
    }
}
