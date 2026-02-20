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
#![allow(clippy::result_large_err)]

// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::OracleTtlPolicy;
use crate::policy_oracle::{PolicyOracleDecision, PolicyOracleEngine, PolicyOracleReceipt};
use crate::probe::{ProbeConfig, ProbeDetector, ProbeObservation, ProbeVerdict};
use crate::settlement::{import_signed_settlements, write_unsigned_proposal};
use crate::telemetry::{derive_operation_id, LifecycleEvent, Telemetry};
use crate::vault::{VaultConfig, VaultEngine, VaultError, VaultExecutionContext};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use evidenceos_core::aspec::{verify_aspec, AspecLane, AspecPolicy, FloatPolicy};
use evidenceos_core::canary::{CanaryConfig, CanaryState};
use evidenceos_core::capsule::{ClaimCapsule, ClaimState as CoreClaimState, ManifestEntry};
use evidenceos_core::eprocess::DirichletMixtureEProcess;
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};
use evidenceos_core::ledger::{ConservationLedger, TopicBudgetPool};
use evidenceos_core::nullspec::{EProcessKind, NullSpecKind};
use evidenceos_core::nullspec_contract::NullSpecContractV1 as RegistryNullSpecContractV1;
use evidenceos_core::nullspec_registry::{NullSpecAuthorityKeyring, NullSpecRegistry};
use evidenceos_core::nullspec_store::NullSpecStore;
use evidenceos_core::oracle::OracleResolution;
use evidenceos_core::settlement::UnsignedSettlementProposal;
use evidenceos_core::structured_claims;
use evidenceos_core::topicid::{
    compute_topic_id, hash_signal, ClaimMetadataV2 as CoreClaimMetadataV2, TopicSignals,
};
use evidenceos_protocol::{
    pb, sha256_domain, DOMAIN_CLAIM_ID, DOMAIN_REVOCATIONS_SNAPSHOT_V1, DOMAIN_STH_SIGNATURE_V1,
};

use pb::evidence_os_server::EvidenceOs as EvidenceOsV2;
use pb::v1;
use pb::v1::evidence_os_server::EvidenceOs as EvidenceOsV1;
use pb::v2;

const MAX_ARTIFACTS: usize = 128;
const MAX_REASON_CODES: usize = 32;
const MAX_DEPENDENCY_ITEMS: usize = 256;
const MAX_METADATA_FIELD_LEN: usize = 128;

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
            ClaimState::Frozen => Some(CoreClaimState::Frozen),
            ClaimState::Committed => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OraclePins {
    codec_hash: [u8; 32],
    bit_width: u32,
    ttl_epochs: u64,
    pinned_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FreezePreimage {
    artifacts_hash: [u8; 32],
    wasm_hash: [u8; 32],
    dependency_merkle_root: [u8; 32],
    holdout_ref_hash: [u8; 32],
    oracle_hash: [u8; 32],
    sealed_preimage_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    claim_id: [u8; 32],
    topic_id: [u8; 32],
    holdout_handle_id: [u8; 32],
    holdout_ref: String,
    #[serde(default)]
    metadata_locked: bool,
    claim_name: String,
    output_schema_id: String,
    phys_hir_hash: [u8; 32],
    #[serde(default)]
    semantic_hash: [u8; 32],
    #[serde(default)]
    output_schema_id_hash: [u8; 32],
    #[serde(default)]
    holdout_handle_hash: [u8; 32],
    #[serde(default)]
    lineage_root_hash: [u8; 32],
    #[serde(default)]
    disagreement_score: u32,
    #[serde(default)]
    semantic_physhir_distance_bits: u32,
    #[serde(default)]
    escalate_to_heavy: bool,
    epoch_size: u64,
    #[serde(default)]
    epoch_counter: u64,
    oracle_num_symbols: u32,
    oracle_resolution: OracleResolution,
    state: ClaimState,
    artifacts: Vec<([u8; 32], String)>,
    #[serde(default)]
    dependency_capsule_hashes: Vec<String>,
    dependency_items: Vec<[u8; 32]>,
    #[serde(default)]
    dependency_merkle_root: Option<[u8; 32]>,
    wasm_module: Vec<u8>,
    aspec_rejection: Option<String>,
    #[serde(default)]
    aspec_report_summary: Option<String>,
    lane: Lane,
    #[serde(default)]
    heavy_lane_diversion_recorded: bool,
    ledger: ConservationLedger,
    last_decision: Option<i32>,
    last_capsule_hash: Option<[u8; 32]>,
    capsule_bytes: Option<Vec<u8>>,
    etl_index: Option<u64>,
    #[serde(default)]
    oracle_pins: Option<OraclePins>,
    #[serde(default)]
    freeze_preimage: Option<FreezePreimage>,
    #[serde(default)]
    operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HoldoutBudgetPool {
    holdout_handle_id: [u8; 32],
    k_bits_budget: f64,
    access_credit_budget: f64,
    k_bits_spent: f64,
    access_credit_spent: f64,
    frozen: bool,
}

#[derive(Debug, Clone)]
struct LaneConfig {
    aspec_policy: AspecPolicy,
    oracle_resolution: OracleResolution,
    k_bits_budget: f64,
    access_credit_budget: f64,
    dp_epsilon_budget: f64,
    dp_delta_budget: f64,
}

impl LaneConfig {
    fn for_lane(lane: Lane, num_symbols: u32, access_credit: f64) -> Result<Self, Status> {
        let mut policy = AspecPolicy::default();
        let (oracle_delta_sigma, k_bits_budget, dp_epsilon_budget, dp_delta_budget) = match lane {
            Lane::Fast => (0.0, access_credit, 0.0, 0.0),
            Lane::Heavy => {
                policy.lane = AspecLane::LowAssurance;
                policy.float_policy = FloatPolicy::Allow;
                policy.max_loop_bound = 10_000;
                policy.max_output_bytes = structured_claims::max_bytes_upper_bound();
                (0.25, access_credit, 0.1, 1e-9)
            }
        };
        Ok(Self {
            aspec_policy: policy,
            oracle_resolution: OracleResolution::new(num_symbols, oracle_delta_sigma)
                .map_err(|_| Status::invalid_argument("oracle_num_symbols must be >= 2"))?,
            k_bits_budget,
            access_credit_budget: access_credit,
            dp_epsilon_budget,
            dp_delta_budget,
        })
    }
}

impl HoldoutBudgetPool {
    fn new(
        holdout_handle_id: [u8; 32],
        k_bits_budget: f64,
        access_credit_budget: f64,
    ) -> Result<Self, Status> {
        if !k_bits_budget.is_finite()
            || !access_credit_budget.is_finite()
            || k_bits_budget < 0.0
            || access_credit_budget < 0.0
        {
            return Err(Status::invalid_argument("invalid holdout pool budget"));
        }
        Ok(Self {
            holdout_handle_id,
            k_bits_budget,
            access_credit_budget,
            k_bits_spent: 0.0,
            access_credit_spent: 0.0,
            frozen: false,
        })
    }

    fn charge(&mut self, k_bits: f64, access_credit: f64) -> Result<(), Status> {
        if self.frozen {
            return Err(Status::failed_precondition("holdout pool exhausted"));
        }
        if !k_bits.is_finite() || !access_credit.is_finite() || k_bits < 0.0 || access_credit < 0.0
        {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        let next_k = self.k_bits_spent + k_bits;
        let next_access = self.access_credit_spent + access_credit;
        if !next_k.is_finite() || !next_access.is_finite() {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        if next_k > self.k_bits_budget + f64::EPSILON
            || next_access > self.access_credit_budget + f64::EPSILON
        {
            self.frozen = true;
            return Err(Status::failed_precondition("holdout pool exhausted"));
        }
        self.k_bits_spent = next_k;
        self.access_credit_spent = next_access;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorRecord {
    ttl_epochs: u64,
    calibration_hash: Option<String>,
    calibration_epoch: Option<u64>,
    updated_at_epoch: u64,
    key_id: String,
    signature_ed25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorConfigFile {
    oracles: HashMap<String, OracleOperatorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EpochControlFile {
    forced_epoch: Option<u64>,
    updated_at_epoch: Option<u64>,
    key_id: Option<String>,
    signature_ed25519: Option<String>,
    event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TrustedKeysFile {
    keys: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct OperatorRuntimeConfig {
    trusted_keys: HashMap<String, Vec<u8>>,
    oracle_ttl_epochs: HashMap<String, u64>,
    oracle_calibration_hash: HashMap<String, String>,
    forced_epoch: Option<u64>,
    active_nullspec_mappings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct PersistedState {
    claims: Vec<Claim>,
    revocations: Vec<([u8; 32], u64, String)>,
    topic_pools: Vec<([u8; 32], TopicBudgetPool)>,
    holdout_pools: Vec<([u8; 32], HoldoutBudgetPool)>,
    canary_states: Vec<(String, CanaryState)>,
}

type RevocationSubscriber = mpsc::Sender<pb::WatchRevocationsResponse>;

const ORACLE_EXPIRED_REASON_CODE: u32 = 9202;
const ORACLE_TTL_ESCALATED_REASON_CODE: u32 = 9203;

#[derive(Debug)]
struct KernelState {
    claims: Mutex<HashMap<[u8; 32], Claim>>,
    topic_pools: Mutex<HashMap<[u8; 32], TopicBudgetPool>>,
    holdout_pools: Mutex<HashMap<[u8; 32], HoldoutBudgetPool>>,
    canary_states: Mutex<HashMap<String, CanaryState>>,
    etl: Mutex<Etl>,
    data_path: PathBuf,
    revocations: Mutex<Vec<([u8; 32], u64, String)>>,
    lock_file: File,
    active_key_id: [u8; 32],
    keyring: HashMap<[u8; 32], SigningKey>,
    revocation_subscribers: Mutex<Vec<RevocationSubscriber>>,
    operator_config: Mutex<OperatorRuntimeConfig>,
}

impl Drop for KernelState {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.data_path.join("kernel.lock"));
        let _ = self.lock_file.metadata();
    }
}

#[derive(Clone)]
pub struct EvidenceOsService {
    state: Arc<KernelState>,
    insecure_v1_enabled: bool,
    dependence_tax_multiplier: f64,
    oracle_ttl_policy: OracleTtlPolicy,
    oracle_ttl_escalation_tax_multiplier: f64,
    telemetry: Arc<Telemetry>,
    probe_detector: Arc<Mutex<ProbeDetector>>,
    policy_oracles: Arc<Vec<PolicyOracleEngine>>,
    canary_config: CanaryConfig,
    offline_settlement_ingest: bool,
}

impl EvidenceOsService {
    pub fn build(data_dir: &str) -> Result<Self, Status> {
        let telemetry =
            Arc::new(Telemetry::new().map_err(|_| Status::internal("telemetry init failed"))?);
        Self::build_with_options(data_dir, false, telemetry)
    }

    pub fn build_with_options(
        data_dir: &str,
        durable_etl: bool,
        telemetry: Arc<Telemetry>,
    ) -> Result<Self, Status> {
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

        let (active_key_id, keyring) = load_or_create_keyring(&root)?;
        let etl_path = root.join("etl.log");
        let etl = Etl::open_or_create_with_options(&etl_path, durable_etl)
            .map_err(|_| Status::internal("etl init failed"))?;
        if etl.recovered_from_partial_write() {
            tracing::warn!(path=%etl_path.display(), "etl recovered from partial trailing write");
        }

        let policy_oracles = load_policy_oracles(&root)?;
        let canary_config = CanaryConfig {
            alpha_drift_micros: std::env::var("EVIDENCEOS_CANARY_ALPHA_DRIFT_MICROS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(50_000),
            check_every_epochs: std::env::var("EVIDENCEOS_CANARY_CHECK_EVERY_EPOCHS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1),
            max_staleness_epochs: std::env::var("EVIDENCEOS_CANARY_MAX_STALENESS_EPOCHS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(100),
        };
        let _ = canary_config
            .barrier()
            .map_err(|_| Status::invalid_argument("invalid canary configuration"))?;

        let operator_config = load_operator_runtime_config(&root)?;

        let state = Arc::new(KernelState {
            claims: Mutex::new(
                persisted
                    .claims
                    .into_iter()
                    .map(|c| (c.claim_id, c))
                    .collect(),
            ),
            topic_pools: Mutex::new(persisted.topic_pools.into_iter().collect()),
            holdout_pools: Mutex::new(persisted.holdout_pools.into_iter().collect()),
            canary_states: Mutex::new(persisted.canary_states.into_iter().collect()),
            etl: Mutex::new(etl),
            data_path: root,
            revocations: Mutex::new(persisted.revocations),
            lock_file,
            active_key_id,
            keyring,
            revocation_subscribers: Mutex::new(Vec::new()),
            operator_config: Mutex::new(operator_config),
        });
        persist_all(&state)?;
        let insecure_v1_enabled = std::env::var("EVIDENCEOS_ENABLE_INSECURE_V1")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let dependence_tax_multiplier = std::env::var("EVIDENCEOS_DEPENDENCE_TAX_MULTIPLIER")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(2.0);
        if !dependence_tax_multiplier.is_finite() || dependence_tax_multiplier < 2.0 {
            return Err(Status::invalid_argument(
                "dependence_tax_multiplier must be finite and >= 2.0",
            ));
        }
        let oracle_ttl_policy = OracleTtlPolicy::from_env();
        let oracle_ttl_escalation_tax_multiplier =
            std::env::var("EVIDENCEOS_ORACLE_TTL_ESCALATION_TAX_MULTIPLIER")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(1.5);
        if !oracle_ttl_escalation_tax_multiplier.is_finite()
            || oracle_ttl_escalation_tax_multiplier < 1.0
        {
            return Err(Status::invalid_argument(
                "oracle_ttl_escalation_tax_multiplier must be finite and >= 1.0",
            ));
        }

        Ok(Self {
            state,
            insecure_v1_enabled,
            dependence_tax_multiplier,
            oracle_ttl_policy,
            oracle_ttl_escalation_tax_multiplier,
            telemetry,
            probe_detector: Arc::new(Mutex::new(ProbeDetector::new(ProbeConfig::from_env()))),
            policy_oracles: Arc::new(policy_oracles),
            canary_config,
            offline_settlement_ingest: std::env::var("EVIDENCEOS_OFFLINE_SETTLEMENT_INGEST")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        })
    }

    pub fn apply_signed_settlements(
        &self,
        import_dir: &Path,
        verify_key: &VerifyingKey,
    ) -> Result<usize, Status> {
        let records = import_signed_settlements(import_dir, verify_key)
            .map_err(|_| Status::failed_precondition("invalid signed settlement file"))?;
        let mut applied = 0usize;
        for record in records {
            let etl_index = {
                let mut etl = self.state.etl.lock();
                let (idx, _) = etl
                    .append(&record.proposal.capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                idx
            };
            if let Ok(claim_id) = decode_hex_hash32(&record.proposal.claim_id_hex, "claim_id") {
                if let Some(claim) = self.state.claims.lock().get_mut(&claim_id) {
                    claim.etl_index = Some(etl_index);
                    if let Ok(capsule_hash) =
                        decode_hex_hash32(&record.proposal.capsule_hash_hex, "capsule_hash")
                    {
                        claim.last_capsule_hash = Some(capsule_hash);
                    }
                }
            }
            applied += 1;
        }
        if applied > 0 {
            persist_all(&self.state)?;
        }
        Ok(applied)
    }

    pub fn reload_operator_runtime_config(&self) -> Result<(), Status> {
        let next = load_operator_runtime_config(&self.state.data_path)?;
        let mut guard = self.state.operator_config.lock();
        let previous = guard.clone();
        *guard = next.clone();
        tracing::info!(
            event="config_reload",
            trusted_keys_before=%previous.trusted_keys.len(),
            trusted_keys_after=%next.trusted_keys.len(),
            oracle_ttls_before=%previous.oracle_ttl_epochs.len(),
            oracle_ttls_after=%next.oracle_ttl_epochs.len(),
            calibrations_before=%previous.oracle_calibration_hash.len(),
            calibrations_after=%next.oracle_calibration_hash.len(),
            nullspec_mappings=%next.active_nullspec_mappings,
            forced_epoch=?next.forced_epoch,
            "reloaded operator runtime config"
        );
        Ok(())
    }
    pub fn probe_detector(&self) -> Arc<Mutex<ProbeDetector>> {
        self.probe_detector.clone()
    }

    pub fn policy_oracles(&self) -> Arc<Vec<PolicyOracleEngine>> {
        self.policy_oracles.clone()
    }

    fn active_signing_key(&self) -> Result<&SigningKey, Status> {
        self.state
            .keyring
            .get(&self.state.active_key_id)
            .ok_or_else(|| Status::internal("active signing key missing"))
    }

    fn lane_name(lane: Lane) -> &'static str {
        match lane {
            Lane::Fast => "fast",
            Lane::Heavy => "heavy",
        }
    }

    fn state_name(state: ClaimState) -> &'static str {
        match state {
            ClaimState::Uncommitted => "UNCOMMITTED",
            ClaimState::Committed => "COMMITTED",
            ClaimState::Sealed => "SEALED",
            ClaimState::Executing => "EXECUTING",
            ClaimState::Settled => "SETTLED",
            ClaimState::Certified => "CERTIFIED",
            ClaimState::Revoked => "REVOKED",
            ClaimState::Tainted => "TAINTED",
            ClaimState::Stale => "STALE",
            ClaimState::Frozen => "FROZEN",
        }
    }

    fn oracle_ttl_for_claim(&self, claim: &Claim) -> u64 {
        self.state
            .operator_config
            .lock()
            .oracle_ttl_epochs
            .get(&claim.claim_name)
            .copied()
            .unwrap_or(1)
            .max(1)
    }

    fn current_epoch_for_claim(&self, claim: &Claim) -> Result<u64, Status> {
        let forced = self.state.operator_config.lock().forced_epoch;
        if let Some(epoch) = forced {
            return Ok(epoch);
        }
        current_logical_epoch(claim.epoch_size)
    }

    fn transition_claim_internal(claim: &mut Claim, to: ClaimState) -> Result<(), Status> {
        if claim.state == to {
            return Ok(());
        }
        if claim.state == ClaimState::Uncommitted && to == ClaimState::Committed {
            claim.state = ClaimState::Committed;
            return Ok(());
        }
        if claim.state == ClaimState::Settled && to == ClaimState::Frozen {
            claim.state = ClaimState::Frozen;
            return Ok(());
        }
        if to == ClaimState::Committed {
            return Err(Status::failed_precondition(
                "invalid claim state transition",
            ));
        }
        let from_core = if claim.state == ClaimState::Committed {
            CoreClaimState::Uncommitted
        } else {
            claim
                .state
                .as_core()
                .ok_or_else(|| Status::failed_precondition("invalid claim state transition"))?
        };
        let target_core = to
            .as_core()
            .ok_or_else(|| Status::failed_precondition("invalid claim state transition"))?;
        from_core
            .transition(target_core)
            .map_err(|_| Status::failed_precondition("invalid claim state transition"))?;
        claim.state = to;
        Ok(())
    }

    fn transition_claim(
        &self,
        claim: &mut Claim,
        to: ClaimState,
        delta_k_bits: f64,
        delta_w: f64,
        decision: Option<i32>,
    ) -> Result<(), Status> {
        let from = claim.state;
        Self::transition_claim_internal(claim, to)?;
        let claim_id = hex::encode(claim.claim_id);
        let topic_id = hex::encode(claim.topic_id);
        let event = LifecycleEvent {
            claim_id: &claim_id,
            topic_id: &topic_id,
            operation_id: &claim.operation_id,
            lane: Self::lane_name(claim.lane),
            delta_k_bits,
            delta_w,
            decision,
            epoch: claim.epoch_counter,
            from: Self::state_name(from),
            to: Self::state_name(to),
        };
        self.telemetry.lifecycle_event(&event);
        let remaining = claim
            .ledger
            .k_bits_budget
            .map_or(0.0, |budget| (budget - claim.ledger.k_bits_total).max(0.0));
        self.telemetry.update_operation_gauges(
            &claim.operation_id,
            remaining,
            claim.ledger.wealth,
            claim.ledger.frozen || claim.state == ClaimState::Frozen,
        );
        Ok(())
    }

    fn freeze_claim_gates(&self, claim: &mut Claim) -> Result<(), Status> {
        if claim.freeze_preimage.is_some() && claim.state == ClaimState::Sealed {
            return Ok(());
        }
        if claim.state != ClaimState::Committed && claim.state != ClaimState::Stale {
            return Err(Status::failed_precondition(
                "claim must be COMMITTED or STALE to freeze gates",
            ));
        }
        if claim.artifacts.is_empty() {
            return Err(Status::failed_precondition(
                "artifacts must be committed before freeze",
            ));
        }
        if claim.wasm_module.is_empty() {
            return Err(Status::failed_precondition(
                "wasm bytes must be committed before freeze",
            ));
        }
        if claim.aspec_rejection.is_some() {
            return Err(Status::failed_precondition("ASPEC report must be accepted"));
        }
        if claim.lane == Lane::Heavy && !claim.heavy_lane_diversion_recorded {
            return Err(Status::failed_precondition(
                "heavy lane diversion must be recorded before freeze",
            ));
        }

        claim
            .artifacts
            .sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        if claim.dependency_items.len() > MAX_DEPENDENCY_ITEMS {
            return Err(Status::failed_precondition(
                "dependency list exceeds allowed size",
            ));
        }
        claim.dependency_items.sort();

        let dependency_merkle_root = dependency_merkle_root(&claim.dependency_items);
        claim.dependency_merkle_root = Some(dependency_merkle_root);

        let wasm_hash = sha256_bytes(&claim.wasm_module);
        let artifacts_hash = artifacts_commitment(&claim.artifacts);
        let holdout_ref_hash = sha256_bytes(claim.holdout_ref.as_bytes());

        let bit_width = canonical_len_for_symbols(claim.oracle_num_symbols)? as u32 * 8;
        let oracle_pins = OraclePins {
            codec_hash: sha256_bytes(b"evidenceos.oracle.codec.v1"),
            bit_width,
            ttl_epochs: self.oracle_ttl_for_claim(claim),
            pinned_epoch: self.current_epoch_for_claim(claim)?,
        };
        let oracle_hash = oracle_pins_hash(&oracle_pins);

        let mut preimage_payload = Vec::new();
        preimage_payload.extend_from_slice(&artifacts_hash);
        preimage_payload.extend_from_slice(&wasm_hash);
        preimage_payload.extend_from_slice(&dependency_merkle_root);
        preimage_payload.extend_from_slice(&holdout_ref_hash);
        preimage_payload.extend_from_slice(&oracle_hash);
        let sealed_preimage_hash = sha256_bytes(&preimage_payload);

        claim.oracle_pins = Some(oracle_pins);
        claim.freeze_preimage = Some(FreezePreimage {
            artifacts_hash,
            wasm_hash,
            dependency_merkle_root,
            holdout_ref_hash,
            oracle_hash,
            sealed_preimage_hash,
        });
        claim.metadata_locked = true;
        Self::transition_claim_internal(claim, ClaimState::Sealed)
    }

    fn maybe_mark_stale(claim: &mut Claim, current_epoch: u64) -> Result<(), Status> {
        let pins = match claim.oracle_pins.as_ref() {
            Some(p) => p,
            None => return Ok(()),
        };
        if claim.state != ClaimState::Sealed {
            return Ok(());
        }
        if current_epoch.saturating_sub(pins.pinned_epoch) > pins.ttl_epochs {
            Self::transition_claim_internal(claim, ClaimState::Stale)?;
        }
        Ok(())
    }

    fn record_incident(&self, claim: &mut Claim, reason: &str) -> Result<(), Status> {
        claim.state = ClaimState::Frozen;
        claim.ledger.frozen = true;
        if let Some(capsule_hash) = claim.last_capsule_hash {
            let mut etl = self.state.etl.lock();
            etl.revoke(&hex::encode(capsule_hash), reason)
                .map_err(|_| Status::internal("etl incident append failed"))?;
        }
        Ok(())
    }

    fn principal_id_from_metadata(metadata: &tonic::metadata::MetadataMap) -> String {
        if let Some(v) = metadata.get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(token) = v.strip_prefix("Bearer ") {
                return format!("bearer:{}", hex::encode(sha256_bytes(token.as_bytes())));
            }
        }
        if let Some(v) = metadata
            .get("x-evidenceos-signature")
            .and_then(|v| v.to_str().ok())
        {
            return format!("hmac:{}", hex::encode(sha256_bytes(v.as_bytes())));
        }
        if let Some(v) = metadata
            .get("x-client-cert-fp")
            .and_then(|v| v.to_str().ok())
        {
            return format!("mtls:{}", hex::encode(sha256_bytes(v.as_bytes())));
        }
        "anonymous".to_string()
    }

    fn probe_semantic_hash(signals: Option<&pb::TopicSignalsV2>) -> String {
        if let Some(sig) = signals {
            if sig.semantic_hash.len() == 32 {
                return hex::encode(&sig.semantic_hash);
            }
            if sig.phys_hir_signature_hash.len() == 32 {
                return hex::encode(&sig.phys_hir_signature_hash);
            }
        }
        "none".to_string()
    }

    fn observe_probe(
        &self,
        principal_id: String,
        operation_id: String,
        topic_id: String,
        semantic_hash: String,
    ) -> Result<(), Status> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| v.as_millis() as u64)
            .map_err(|_| Status::internal("system clock before unix epoch"))?;
        let (verdict, snapshot) = self.probe_detector.lock().observe(
            &ProbeObservation {
                principal_id: principal_id.clone(),
                operation_id: operation_id.clone(),
                topic_id: topic_id.clone(),
                semantic_hash,
            },
            now_ms,
        );
        self.telemetry
            .set_probe_risk_score(&operation_id, snapshot.total_requests_window as f64);
        match verdict {
            ProbeVerdict::Clean => Ok(()),
            ProbeVerdict::Throttle {
                reason,
                retry_after_ms,
            } => {
                tracing::warn!(target: "evidenceos.probe", reason=%reason, principal_id=%principal_id, operation_id=%operation_id, topic_id=%topic_id, retry_after_ms=retry_after_ms, "probe throttled");
                self.telemetry.record_probe_throttled(reason);
                self.telemetry.record_probe_suspected(reason);
                Err(Status::resource_exhausted(format!(
                    "PROBE_THROTTLED: {reason}; retry_after_ms={retry_after_ms}"
                )))
            }
            ProbeVerdict::Escalate { reason } => {
                tracing::warn!(target: "evidenceos.probe", reason=%reason, principal_id=%principal_id, operation_id=%operation_id, topic_id=%topic_id, "probe escalated");
                self.telemetry.record_probe_escalated(reason);
                self.telemetry.record_probe_suspected(reason);
                self.append_probe_event(
                    &operation_id,
                    &principal_id,
                    &topic_id,
                    reason,
                    "ESCALATE",
                )?;
                Ok(())
            }
            ProbeVerdict::Freeze { reason } => {
                tracing::error!(target: "evidenceos.probe", reason=%reason, principal_id=%principal_id, operation_id=%operation_id, topic_id=%topic_id, "probe frozen");
                self.telemetry.record_probe_frozen(reason);
                self.telemetry.record_probe_suspected(reason);
                self.append_probe_event(&operation_id, &principal_id, &topic_id, reason, "FREEZE")?;
                Err(Status::permission_denied(format!("PROBE_FROZEN: {reason}")))
            }
        }
    }

    fn append_probe_event(
        &self,
        operation_id: &str,
        principal_id: &str,
        topic_id: &str,
        reason: &str,
        action: &str,
    ) -> Result<(), Status> {
        let entry = serde_json::to_vec(&json!({
            "kind": "probe_event",
            "operation_id": operation_id,
            "principal_hash": hex::encode(sha256_bytes(principal_id.as_bytes())),
            "topic_hash": hex::encode(sha256_bytes(topic_id.as_bytes())),
            "reason": reason,
            "action": action,
        }))
        .map_err(|_| Status::internal("probe event encoding failed"))?;
        self.state
            .etl
            .lock()
            .append(&entry)
            .map_err(|_| Status::internal("probe event append failed"))?;
        Ok(())
    }

    fn append_canary_incident(
        &self,
        claim: &Claim,
        reason: &str,
        e_drift: f64,
        barrier: f64,
    ) -> Result<(), Status> {
        let entry = serde_json::to_vec(&json!({
            "kind": "canary_incident",
            "reason": reason,
            "claim_id": hex::encode(claim.claim_id),
            "claim_name": claim.claim_name,
            "holdout_ref": claim.holdout_ref,
            "e_drift": e_drift,
            "barrier": barrier,
            "operation_id": claim.operation_id,
        }))
        .map_err(|_| Status::internal("canary incident encoding failed"))?;
        self.state
            .etl
            .lock()
            .append(&entry)
            .map_err(|_| Status::internal("canary incident append failed"))?;
        Ok(())
    }

    fn validate_budget_value(value: f64, field: &str) -> Result<(), Status> {
        if !value.is_finite() || value < 0.0 {
            return Err(Status::invalid_argument(format!(
                "{field} must be finite and >= 0"
            )));
        }
        Ok(())
    }

    fn canary_key(claim_name: &str, holdout_ref: &str) -> String {
        format!("{claim_name}::{holdout_ref}")
    }
}

fn persist_all(state: &KernelState) -> Result<(), Status> {
    let persisted = PersistedState {
        claims: state.claims.lock().values().cloned().collect(),
        revocations: state.revocations.lock().clone(),
        topic_pools: state
            .topic_pools
            .lock()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
        holdout_pools: state
            .holdout_pools
            .lock()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
        canary_states: state
            .canary_states
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
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

fn decode_hex_hash32(value: &str, field: &str) -> Result<[u8; 32], Status> {
    let bytes =
        hex::decode(value).map_err(|_| Status::internal(format!("{field} is not valid hex")))?;
    parse_hash32(&bytes, field)
}

const ETL_SIGNING_KEY_REL_PATH: &str = "keys/etl_signing_ed25519";
const KEYRING_DIR_REL_PATH: &str = "keys";
const ACTIVE_KEY_ID_FILE: &str = "active_key_id";

fn write_secret_key(key_path: &Path, secret: &[u8; 32]) -> Result<(), Status> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(key_path)
            .map_err(|_| Status::internal("create signing key failed"))?;
        f.write_all(secret)
            .and_then(|_| f.flush())
            .map_err(|_| Status::internal("write signing key failed"))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(key_path, secret)
            .map_err(|_| Status::internal("write signing key failed"))?;
    }

    Ok(())
}

#[allow(clippy::type_complexity)]
fn load_or_create_keyring(
    data_dir: &Path,
) -> Result<([u8; 32], HashMap<[u8; 32], SigningKey>), Status> {
    let keys_dir = data_dir.join(KEYRING_DIR_REL_PATH);
    std::fs::create_dir_all(&keys_dir).map_err(|_| Status::internal("mkdir keys failed"))?;

    let mut keyring = HashMap::new();
    for entry in
        std::fs::read_dir(&keys_dir).map_err(|_| Status::internal("read keyring failed"))?
    {
        let entry = entry.map_err(|_| Status::internal("read keyring failed"))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some(ACTIVE_KEY_ID_FILE) {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|n| n.to_str()) else {
            continue;
        };
        let bytes = match hex::decode(stem) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let key_id = parse_hash32(&bytes, "key_id")?;
        let secret =
            std::fs::read(&path).map_err(|_| Status::internal("read signing key failed"))?;
        if secret.len() != 32 {
            return Err(Status::internal("invalid signing key length"));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&secret);
        let signing_key = SigningKey::from_bytes(&sk);
        let actual_key_id = key_id_from_verifying_key(&signing_key.verifying_key());
        if actual_key_id != key_id {
            return Err(Status::internal("key_id does not match signing key"));
        }
        keyring.insert(key_id, signing_key);
    }

    let legacy_key_path = data_dir.join(ETL_SIGNING_KEY_REL_PATH);
    if legacy_key_path.exists() {
        let bytes = std::fs::read(&legacy_key_path)
            .map_err(|_| Status::internal("read signing key failed"))?;
        if bytes.len() != 32 {
            return Err(Status::internal("invalid signing key length"));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&sk);
        let key_id = key_id_from_verifying_key(&signing_key.verifying_key());
        let key_path = keys_dir.join(format!("{}.key", hex::encode(key_id)));
        if !key_path.exists() {
            write_secret_key(&key_path, &sk)?;
        }
        keyring.insert(key_id, signing_key);
    }

    if keyring.is_empty() {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|_| Status::internal("random keygen failed"))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let key_id = key_id_from_verifying_key(&signing_key.verifying_key());
        let key_path = keys_dir.join(format!("{}.key", hex::encode(key_id)));
        write_secret_key(&key_path, &secret)?;
        keyring.insert(key_id, signing_key);
    }

    let active_path = keys_dir.join(ACTIVE_KEY_ID_FILE);
    let active_key_id = if active_path.exists() {
        let raw = std::fs::read_to_string(&active_path)
            .map_err(|_| Status::internal("read active key id failed"))?;
        let trimmed = raw.trim();
        let bytes = hex::decode(trimmed).map_err(|_| Status::internal("invalid active key id"))?;
        parse_hash32(&bytes, "active key id")?
    } else {
        *keyring
            .keys()
            .next()
            .ok_or_else(|| Status::internal("keyring is empty"))?
    };

    if !keyring.contains_key(&active_key_id) {
        return Err(Status::internal("active key id not found in keyring"));
    }

    std::fs::write(
        &active_path,
        format!(
            "{}
",
            hex::encode(active_key_id)
        ),
    )
    .map_err(|_| Status::internal("write active key id failed"))?;

    Ok((active_key_id, keyring))
}

fn sha256_bytes(payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(payload);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

fn artifacts_commitment(artifacts: &[([u8; 32], String)]) -> [u8; 32] {
    let mut payload = Vec::new();
    for (hash, kind) in artifacts {
        payload.extend_from_slice(hash);
        payload.extend_from_slice(&(kind.len() as u64).to_be_bytes());
        payload.extend_from_slice(kind.as_bytes());
    }
    sha256_bytes(&payload)
}

fn dependency_merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    if items.is_empty() {
        return sha256_bytes(&[]);
    }
    let mut layer: Vec<[u8; 32]> = items.iter().copied().map(|v| sha256_bytes(&v)).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                left
            };
            let mut concat = [0u8; 64];
            concat[..32].copy_from_slice(&left);
            concat[32..].copy_from_slice(&right);
            next.push(sha256_bytes(&concat));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn oracle_pins_hash(pins: &OraclePins) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&pins.codec_hash);
    payload.extend_from_slice(&pins.bit_width.to_be_bytes());
    payload.extend_from_slice(&pins.ttl_epochs.to_be_bytes());
    payload.extend_from_slice(&pins.pinned_epoch.to_be_bytes());
    sha256_bytes(&payload)
}

fn append_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn append_len_prefixed_str(out: &mut Vec<u8>, value: &str) {
    append_len_prefixed_bytes(out, value.as_bytes());
}

fn sth_signature_payload(tree_size: u64, root_hash: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&tree_size.to_be_bytes());
    payload.extend_from_slice(root_hash);
    sha256_domain(DOMAIN_STH_SIGNATURE_V1, &payload)
}

fn revocations_signature_payload(entries: &[pb::RevocationEntry]) -> [u8; 32] {
    let mut payload = Vec::new();
    for entry in entries {
        append_len_prefixed_bytes(&mut payload, &entry.claim_id);
        payload.extend_from_slice(&entry.timestamp_unix.to_be_bytes());
        append_len_prefixed_str(&mut payload, &entry.reason);
    }
    sha256_domain(DOMAIN_REVOCATIONS_SNAPSHOT_V1, &payload)
}

fn key_id_from_verifying_key(verifying_key: &VerifyingKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(verifying_key.to_bytes());
    let out = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> [u8; 64] {
    let sig: Signature = signing_key.sign(payload);
    sig.to_bytes()
}

fn build_signed_tree_head(
    etl: &Etl,
    signing_key: &SigningKey,
    key_id: [u8; 32],
) -> pb::SignedTreeHead {
    let tree_size = etl.tree_size();
    let root_hash = etl.root_hash();
    let payload = sth_signature_payload(tree_size, &root_hash);
    let signature = sign_payload(signing_key, &payload);
    pb::SignedTreeHead {
        tree_size,
        root_hash: root_hash.to_vec(),
        signature: signature.to_vec(),
        key_id: key_id.to_vec(),
    }
}

fn build_revocations_snapshot(
    signing_key: &SigningKey,
    key_id: [u8; 32],
    revocations: Vec<([u8; 32], u64, String)>,
    signed_tree_head: pb::SignedTreeHead,
) -> pb::WatchRevocationsResponse {
    let entries: Vec<pb::RevocationEntry> = revocations
        .into_iter()
        .map(|(claim_id, timestamp_unix, reason)| pb::RevocationEntry {
            claim_id: claim_id.to_vec(),
            timestamp_unix,
            reason,
        })
        .collect();
    let payload = revocations_signature_payload(&entries);
    let signature = sign_payload(signing_key, &payload);
    pb::WatchRevocationsResponse {
        entries,
        signature: signature.to_vec(),
        signed_tree_head: Some(signed_tree_head),
        key_id: key_id.to_vec(),
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

fn vault_config(claim: &Claim) -> Result<VaultConfig, Status> {
    let canonical_len = canonical_len_for_symbols(claim.oracle_num_symbols)?;
    let max_memory_bytes = if claim.lane == Lane::Heavy {
        2 * 65_536
    } else {
        4 * 65_536
    };
    let max_fuel = if claim.lane == Lane::Heavy {
        250_000
    } else {
        1_000_000
    };
    let max_oracle_calls = if claim.lane == Lane::Heavy { 8 } else { 32 };
    let max_output_bytes = if claim.output_schema_id == structured_claims::LEGACY_SCHEMA_ID {
        canonical_len as u32
    } else {
        structured_claims::max_bytes_upper_bound()
    };
    Ok(VaultConfig {
        max_fuel,
        max_memory_bytes: max_memory_bytes as u64,
        max_output_bytes,
        max_oracle_calls,
    })
}

fn kernel_structured_output(
    output_schema_id: &str,
    canonical_output: &[u8],
    decision: i32,
    reason_codes: &[u32],
    e_value: f64,
) -> Result<Vec<u8>, Status> {
    if output_schema_id == structured_claims::LEGACY_SCHEMA_ID {
        return Ok(canonical_output.to_vec());
    }
    let mut value: serde_json::Value = serde_json::from_slice(canonical_output)
        .map_err(|_| Status::internal("structured canonical output is not valid JSON"))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| Status::internal("structured canonical output is not object JSON"))?;
    obj.insert("kernel_decision".to_string(), json!(decision));
    obj.insert("kernel_reason_codes".to_string(), json!(reason_codes));
    obj.insert("kernel_e_value_total".to_string(), json!(e_value));
    serde_json::to_vec(&value).map_err(|_| Status::internal("failed to encode structured output"))
}

fn policy_oracle_input_json(
    claim: &Claim,
    vault_result: &crate::vault::VaultExecutionResult,
    ledger: &ConservationLedger,
    canonical_output: &[u8],
    reason_codes: &[u32],
) -> Result<Vec<u8>, Status> {
    let payload = serde_json::json!({
        "alpha_micros": (ledger.alpha * 1_000_000.0).round() as u32,
        "canonical_output_len": canonical_output.len() as u32,
        "canonical_output_sha256": hex::encode(sha256_bytes(canonical_output)),
        "claim_id": hex::encode(claim.claim_id),
        "epoch": claim.epoch_counter,
        "fuel_used": vault_result.fuel_used,
        "k_bits_total": ledger.k_bits_total,
        "lane": EvidenceOsService::lane_name(claim.lane),
        "oracle_calls": vault_result.oracle_calls,
        "reason_codes": reason_codes,
        "topic_id": hex::encode(claim.topic_id),
        "w": ledger.wealth,
    });
    evidenceos_core::capsule::canonical_json(&payload)
        .map_err(|_| Status::internal("policy oracle input encode failed"))
}

fn load_policy_oracles(root: &Path) -> Result<Vec<PolicyOracleEngine>, Status> {
    let oracle_dir = root.join("policy-oracles");
    if !oracle_dir.exists() {
        return Ok(Vec::new());
    }
    let allow_failure = std::env::var("EVIDENCEOS_ALLOW_ORACLE_LOAD_FAILURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    match PolicyOracleEngine::load_from_dir(&oracle_dir) {
        Ok(oracles) => Ok(oracles),
        Err(err) if allow_failure => {
            tracing::warn!(error=%err, "policy oracle load failed; continuing due to override");
            Ok(Vec::new())
        }
        Err(err) => {
            tracing::error!(error=%err, "policy oracle load failed");
            Err(err)
        }
    }
}

fn derive_holdout_labels(
    holdout_handle_id: [u8; 32],
    holdout_len: usize,
) -> Result<Vec<u8>, Status> {
    if holdout_len == 0 || holdout_len > 4096 {
        return Err(Status::invalid_argument("holdout length out of bounds"));
    }
    let mut labels = Vec::with_capacity(holdout_len);
    for idx in 0..holdout_len {
        let byte = holdout_handle_id[idx % holdout_handle_id.len()];
        labels.push((byte ^ ((idx as u8).wrapping_mul(31))) & 1);
    }
    Ok(labels)
}

fn requested_lane(lane: &str) -> Result<Lane, Status> {
    match lane.to_ascii_lowercase().as_str() {
        "fast" | "highassurance" | "high_assurance" => Ok(Lane::Fast),
        "heavy" | "lowassurance" | "low_assurance" => Ok(Lane::Heavy),
        _ => Err(Status::invalid_argument(
            "metadata.lane must be fast or heavy",
        )),
    }
}

fn validate_required_str_field(value: &str, field: &str, max_len: usize) -> Result<(), Status> {
    if value.is_empty() || value.len() > max_len {
        return Err(Status::invalid_argument(format!(
            "{field} must be in [1,{max_len}]"
        )));
    }
    Ok(())
}

fn load_operator_runtime_config(data_path: &Path) -> Result<OperatorRuntimeConfig, Status> {
    let trusted_path = data_path.join("trusted_oracle_keys.json");
    let trusted_keys = if trusted_path.exists() {
        let bytes = std::fs::read(&trusted_path)
            .map_err(|_| Status::internal("read trusted keys failed"))?;
        let trusted: TrustedKeysFile = serde_json::from_slice(&bytes)
            .map_err(|_| Status::invalid_argument("decode trusted keys failed"))?;
        let mut out = HashMap::new();
        for (kid, key_hex) in trusted.keys {
            out.insert(
                kid,
                hex::decode(key_hex)
                    .map_err(|_| Status::invalid_argument("invalid trusted key hex"))?,
            );
        }
        out
    } else {
        HashMap::new()
    };

    let oracle_path = data_path.join("oracle_operator_config.json");
    let oracle_cfg = if oracle_path.exists() {
        let bytes = std::fs::read(&oracle_path)
            .map_err(|_| Status::internal("read oracle config failed"))?;
        serde_json::from_slice::<OracleOperatorConfigFile>(&bytes)
            .map_err(|_| Status::invalid_argument("decode oracle config failed"))?
    } else {
        OracleOperatorConfigFile::default()
    };

    for (oracle_id, rec) in &oracle_cfg.oracles {
        verify_signed_oracle_record(oracle_id, rec, &trusted_keys)?;
    }

    let epoch_path = data_path.join("epoch_control.json");
    let epoch_cfg = if epoch_path.exists() {
        let bytes = std::fs::read(&epoch_path)
            .map_err(|_| Status::internal("read epoch control failed"))?;
        serde_json::from_slice::<EpochControlFile>(&bytes)
            .map_err(|_| Status::invalid_argument("decode epoch control failed"))?
    } else {
        EpochControlFile::default()
    };

    let nullspec_mappings_len = {
        let map_path = data_path.join("nullspec").join("active_map.json");
        if map_path.exists() {
            let bytes = std::fs::read(map_path)
                .map_err(|_| Status::internal("nullspec mapping read failed"))?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| Status::invalid_argument("decode nullspec mappings failed"))?;
            value
                .get("mappings")
                .and_then(|v| v.as_array())
                .map(|v| v.len())
                .unwrap_or(0)
        } else {
            0
        }
    };

    Ok(OperatorRuntimeConfig {
        trusted_keys,
        oracle_ttl_epochs: oracle_cfg
            .oracles
            .iter()
            .map(|(id, rec)| (id.clone(), rec.ttl_epochs.max(1)))
            .collect(),
        oracle_calibration_hash: oracle_cfg
            .oracles
            .iter()
            .filter_map(|(id, rec)| rec.calibration_hash.clone().map(|v| (id.clone(), v)))
            .collect(),
        forced_epoch: epoch_cfg.forced_epoch,
        active_nullspec_mappings: nullspec_mappings_len,
    })
}

fn verify_signed_oracle_record(
    _oracle_id: &str,
    rec: &OracleOperatorRecord,
    trusted_keys: &HashMap<String, Vec<u8>>,
) -> Result<(), Status> {
    if rec.ttl_epochs == 0 {
        return Err(Status::invalid_argument("oracle ttl must be > 0"));
    }
    let _key = trusted_keys
        .get(&rec.key_id)
        .ok_or_else(|| Status::failed_precondition("unknown signing key for oracle config"))?;
    let sig_bytes = hex::decode(&rec.signature_ed25519)
        .map_err(|_| Status::invalid_argument("invalid oracle config signature hex"))?;
    if sig_bytes.len() != 64 {
        return Err(Status::invalid_argument(
            "invalid oracle config signature length",
        ));
    }
    Ok(())
}

fn current_logical_epoch(epoch_size: u64) -> Result<u64, Status> {
    if epoch_size == 0 {
        return Err(Status::invalid_argument("epoch_size must be > 0"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Status::internal("system clock before unix epoch"))?
        .as_secs();
    Ok(now / epoch_size)
}

fn build_operation_id(
    topic_id: [u8; 32],
    lineage_root: Option<[u8; 32]>,
    claim_hash: [u8; 32],
    action_class: &str,
    phys_signature_hash: Option<[u8; 32]>,
) -> String {
    let lineage = lineage_root.unwrap_or(claim_hash);
    let phys = phys_signature_hash
        .map(hex::encode)
        .unwrap_or_else(|| "none".to_string());
    derive_operation_id(vec![
        ("topic_id", hex::encode(topic_id)),
        ("lineage_root", hex::encode(lineage)),
        ("action_class", action_class.to_string()),
        ("phys_signature_hash", phys),
    ])
}

fn default_registry_nullspec() -> Result<RegistryNullSpecContractV1, Status> {
    let mut null_spec = RegistryNullSpecContractV1 {
        id: String::new(),
        domain: "sealed-vault".to_string(),
        null_accuracy: 0.5,
        e_value: evidenceos_core::nullspec_contract::EValueSpecV1::LikelihoodRatio {
            n_observations: 1,
        },
        created_at_unix: 0,
        version: 1,
    };
    null_spec.id = null_spec
        .compute_id()
        .map_err(|_| Status::internal("nullspec id compute failed"))?;
    Ok(null_spec)
}

fn vault_context(
    claim: &Claim,
    null_spec: RegistryNullSpecContractV1,
) -> Result<VaultExecutionContext, Status> {
    let holdout_len = usize::try_from(claim.epoch_size)
        .map_err(|_| Status::invalid_argument("epoch_size too large"))?;
    let holdout_labels = derive_holdout_labels(claim.holdout_handle_id, holdout_len)?;
    Ok(VaultExecutionContext {
        holdout_labels,
        oracle_num_buckets: claim.oracle_num_symbols,
        oracle_delta_sigma: claim.oracle_resolution.delta_sigma,
        null_spec,
        output_schema_id: claim.output_schema_id.clone(),
    })
}

fn oracle_resolution_hash(resolution: &OracleResolution) -> Result<[u8; 32], Status> {
    let bytes = serde_json::to_vec(resolution)
        .map_err(|_| Status::internal("oracle resolution encode failed"))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&out);
    Ok(hash)
}

fn compute_nullspec_e_value(
    contract: &evidenceos_core::nullspec::NullSpecContractV1,
    oracle_buckets: &[u32],
) -> Result<(f64, String), Status> {
    match (&contract.kind, &contract.eprocess) {
        (
            NullSpecKind::ParametricBernoulli { p },
            EProcessKind::LikelihoodRatioFixedAlt { alt },
        ) => {
            if alt.len() != 2 || *p <= 0.0 || *p >= 1.0 {
                return Err(Status::failed_precondition("invalid parametric nullspec"));
            }
            let mut e = 1.0_f64;
            for &b in oracle_buckets {
                let idx = usize::try_from(b)
                    .map_err(|_| Status::failed_precondition("bucket overflow"))?;
                if idx >= 2 {
                    return Err(Status::failed_precondition(
                        "bucket out of range for bernoulli nullspec",
                    ));
                }
                let p0 = if idx == 1 { *p } else { 1.0 - *p };
                let altp = alt[idx];
                if !p0.is_finite() || p0 <= 0.0 || !altp.is_finite() || altp < 0.0 {
                    return Err(Status::failed_precondition(
                        "invalid bernoulli probabilities",
                    ));
                }
                let inc = altp / p0;
                if !inc.is_finite() || inc < 0.0 {
                    return Err(Status::failed_precondition("invalid e-process increment"));
                }
                e *= inc;
                if !e.is_finite() || e < 0.0 {
                    return Err(Status::failed_precondition("invalid e-process state"));
                }
            }
            Ok((e, "likelihood_ratio_fixed_alt".to_string()))
        }
        (
            NullSpecKind::DiscreteBuckets { p0 },
            EProcessKind::DirichletMultinomialMixture { alpha },
        ) => {
            let mut ep = DirichletMixtureEProcess::new(alpha.clone())
                .map_err(|_| Status::failed_precondition("invalid dirichlet alpha"))?;
            for &b in oracle_buckets {
                let idx = usize::try_from(b)
                    .map_err(|_| Status::failed_precondition("bucket overflow"))?;
                ep.update(idx, p0).map_err(|_| {
                    Status::failed_precondition("invalid non-parametric e-process update")
                })?;
            }
            Ok((ep.e, "dirichlet_multinomial_mixture".to_string()))
        }
        _ => Err(Status::failed_precondition(
            "nullspec kind/eprocess mismatch",
        )),
    }
}

fn map_vault_error(err: VaultError) -> Status {
    match err {
        VaultError::InvalidConfig(_) => Status::invalid_argument("invalid vault configuration"),
        VaultError::InvalidModule(_) => Status::failed_precondition("invalid wasm module"),
        VaultError::Trap(_) => Status::failed_precondition("wasm trap"),
        VaultError::FuelExhausted => Status::resource_exhausted("fuel exhausted"),
        VaultError::MemoryOob => Status::failed_precondition("guest memory out-of-bounds"),
        VaultError::OutputTooLarge => Status::failed_precondition("structured output too large"),
        VaultError::OutputAlreadyEmitted => {
            Status::failed_precondition("too many structured outputs")
        }
        VaultError::OutputMissing => Status::failed_precondition("structured output missing"),
        VaultError::OracleCallLimitExceeded => {
            Status::resource_exhausted("oracle call limit exceeded")
        }
        VaultError::InvalidOracleInput => Status::invalid_argument("invalid oracle input"),
        VaultError::MissingRunExport => Status::failed_precondition("missing run export"),
        VaultError::InvalidStructuredClaim(reason) => {
            Status::failed_precondition(format!("invalid structured claim: {reason}"))
        }
    }
}

#[tonic::async_trait]
impl EvidenceOsV2 for EvidenceOsService {
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
        let access_credit = req.access_credit as f64;
        Self::validate_budget_value(access_credit, "access_credit")?;
        let oracle_resolution = OracleResolution::new(req.oracle_num_symbols, 0.0)
            .map_err(|_| Status::invalid_argument("oracle_num_symbols must be >= 2"))?;
        let ledger = ConservationLedger::new(req.alpha)
            .map_err(|_| Status::invalid_argument("alpha must be in (0,1)"))
            .map(|l| l.with_budgets(Some(access_credit), Some(access_credit)))?;

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(&topic_id);
        id_payload.extend_from_slice(&holdout_handle_id);
        id_payload.extend_from_slice(&phys_hir_hash);
        id_payload.extend_from_slice(&req.epoch_size.to_be_bytes());
        id_payload.extend_from_slice(&oracle_resolution.num_symbols.to_be_bytes());
        let claim_id = sha256_domain(DOMAIN_CLAIM_ID, &id_payload);

        let operation_id = build_operation_id(
            topic_id,
            None,
            claim_id,
            "create_claim_v1",
            Some(phys_hir_hash),
        );
        let claim = Claim {
            claim_id,
            topic_id,
            dependency_merkle_root: None,
            holdout_handle_id,
            holdout_ref: hex::encode(holdout_handle_id),
            metadata_locked: false,
            claim_name: "legacy-v1".to_string(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash,
            semantic_hash: [0u8; 32],
            output_schema_id_hash: hash_signal(b"evidenceos/schema_id", b"legacy/v1"),
            holdout_handle_hash: hash_signal(b"evidenceos/holdout_handle", &holdout_handle_id),
            lineage_root_hash: topic_id,
            disagreement_score: 0,
            semantic_physhir_distance_bits: 0,
            escalate_to_heavy: false,
            epoch_size: req.epoch_size,
            epoch_counter: 0,
            oracle_num_symbols: req.oracle_num_symbols,
            oracle_resolution,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            wasm_module: Vec::new(),
            aspec_rejection: None,
            aspec_report_summary: None,
            lane: Lane::Fast,
            heavy_lane_diversion_recorded: false,
            ledger,
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id,
        };

        self.state.claims.lock().insert(claim_id, claim.clone());
        {
            let mut topic_pools = self.state.topic_pools.lock();
            if let std::collections::hash_map::Entry::Vacant(entry) = topic_pools.entry(topic_id) {
                let pool =
                    TopicBudgetPool::new(hex::encode(topic_id), access_credit, access_credit)
                        .map_err(|_| Status::invalid_argument("invalid topic budget"))?;
                entry.insert(pool);
            }
        }
        self.state
            .holdout_pools
            .lock()
            .entry(holdout_handle_id)
            .or_insert(HoldoutBudgetPool::new(
                holdout_handle_id,
                access_credit,
                access_credit,
            )?);
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
            if claim.metadata_locked
                || matches!(
                    claim.state,
                    ClaimState::Sealed
                        | ClaimState::Executing
                        | ClaimState::Settled
                        | ClaimState::Certified
                        | ClaimState::Frozen
                )
            {
                return Err(Status::failed_precondition(
                    "cannot commit artifacts after freeze",
                ));
            }
            self.transition_claim(claim, ClaimState::Committed, 0.0, 0.0, None)?;
            claim.artifacts.clear();
            claim.dependency_items.clear();
            claim.dependency_merkle_root = None;
            claim.freeze_preimage = None;
            claim.oracle_pins = None;
            claim.epoch_counter = claim.epoch_counter.saturating_add(1);
            let mut declared_wasm_hash = None;
            for artifact in req.artifacts {
                if artifact.kind.is_empty() || artifact.kind.len() > 64 {
                    return Err(Status::invalid_argument("artifact kind must be in [1,64]"));
                }
                let artifact_hash = parse_hash32(&artifact.artifact_hash, "artifact_hash")?;
                if artifact.kind == "wasm" {
                    declared_wasm_hash = Some(artifact_hash);
                }
                if artifact.kind == "dependency" {
                    claim.dependency_items.push(artifact_hash);
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

            let lane_cfg = LaneConfig::for_lane(
                claim.lane,
                claim.oracle_num_symbols,
                claim.ledger.access_credit_budget.unwrap_or(0.0),
            )?;
            let report = verify_aspec(&req.wasm_module, &lane_cfg.aspec_policy);
            let summary = format!(
                "lane={:?};ok={};imports={};loops={};kproxy={:.3}",
                report.lane,
                report.ok,
                report.imported_funcs,
                report.total_loops,
                report.kolmogorov_proxy_bits
            );
            claim.aspec_report_summary = Some(summary);
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
            claim.heavy_lane_diversion_recorded = claim.lane == Lane::Heavy;
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
        let state = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            self.freeze_claim_gates(claim).inspect_err(|_err| {
                let _ = self.record_incident(claim, "freeze_gates_failed");
            })?;
            claim.state
        };
        persist_all(&self.state)?;
        Ok(Response::new(pb::FreezeGatesResponse {
            state: state.to_proto(),
        }))
    }

    async fn seal_claim(
        &self,
        request: Request<pb::SealClaimRequest>,
    ) -> Result<Response<pb::SealClaimResponse>, Status> {
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        let state = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            if claim.state == ClaimState::Sealed && claim.freeze_preimage.is_some() {
                claim.state
            } else {
                self.freeze_claim_gates(claim).inspect_err(|_err| {
                    let _ = self.record_incident(claim, "seal_claim_failed");
                })?;
                claim.state
            }
        };
        persist_all(&self.state)?;
        Ok(Response::new(pb::SealClaimResponse {
            state: state.to_proto(),
        }))
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
            let claim_id_hex = hex::encode(claim.claim_id);
            let span = tracing::info_span!("execute_claim", operation_id=%claim.operation_id, claim_id=%claim_id_hex);
            let _guard = span.enter();
            if claim.state == ClaimState::Settled || claim.state == ClaimState::Certified {
                return Err(Status::failed_precondition("execution already settled"));
            }
            claim.operation_id = build_operation_id(
                claim.topic_id,
                claim.dependency_merkle_root,
                claim.claim_id,
                "execute_claim_v1",
                Some(claim.phys_hir_hash),
            );
            self.transition_claim(claim, ClaimState::Executing, 0.0, 0.0, None)?;

            let vault = VaultEngine::new().map_err(map_vault_error)?;
            let context = vault_context(claim, default_registry_nullspec()?)?;
            let vault_result =
                match vault.execute(&claim.wasm_module, &context, vault_config(claim)?) {
                    Ok(v) => v,
                    Err(err) => {
                        self.record_incident(claim, "execution_failure")?;
                        return Err(map_vault_error(err));
                    }
                };
            let emitted_output = vault_result.canonical_output;
            let fuel_used = vault_result.fuel_used;
            let trace_hash = vault_result.judge_trace_hash;
            if !req.canonical_output.is_empty() && req.canonical_output != emitted_output {
                self.record_incident(claim, "canonical_output_mismatch")?;
                return Err(Status::invalid_argument(
                    "canonical_output mismatch with wasm emission",
                ));
            }
            let canonical_output = emitted_output;
            let _ = claim
                .oracle_resolution
                .validate_canonical_bytes(&canonical_output)
                .map_err(|_| {
                    let _ = self.record_incident(claim, "non_canonical_output");
                    Status::invalid_argument("non-canonical output")
                })?;

            let charge_bits = claim.oracle_resolution.bits_per_call()
                * f64::from(vault_result.oracle_calls.max(1));
            let dependence_multiplier = self.dependence_tax_multiplier;
            let taxed_bits = charge_bits * dependence_multiplier;
            let covariance_charge = taxed_bits - charge_bits;
            claim
                .ledger
                .charge_all(
                    taxed_bits,
                    0.0,
                    0.0,
                    taxed_bits,
                    "structured_output",
                    json!({
                        "post_canonical_bits": charge_bits,
                        "dependence_multiplier": dependence_multiplier,
                        "taxed_k_bits": taxed_bits,
                    }),
                )
                .map_err(|_| {
                    let _ = self.record_incident(claim, "ledger_overrun");
                    Status::failed_precondition("ledger budget exhausted")
                })?;
            {
                let mut topic_pools = self.state.topic_pools.lock();
                let pool = topic_pools
                    .get_mut(&claim.topic_id)
                    .ok_or_else(|| Status::failed_precondition("missing topic budget pool"))?;
                if pool
                    .charge(taxed_bits, taxed_bits, covariance_charge)
                    .is_err()
                {
                    let _ = self.record_incident(claim, "topic_budget_exhausted");
                    return Err(Status::failed_precondition("topic budget exhausted"));
                }
            }
            {
                let mut holdout_pools = self.state.holdout_pools.lock();
                let pool = holdout_pools
                    .get_mut(&claim.holdout_handle_id)
                    .ok_or_else(|| Status::failed_precondition("missing holdout budget pool"))?;
                if pool.charge(taxed_bits, taxed_bits).is_err() {
                    let _ = self.record_incident(claim, "holdout_budget_exhausted");
                    return Err(Status::failed_precondition("holdout budget exhausted"));
                }
            }
            claim
                .ledger
                .charge_kout_bits(vault_result.kout_bits_total)
                .map_err(|_| {
                    let _ = self.record_incident(claim, "ledger_kout_overrun");
                    Status::failed_precondition("ledger kout budget exhausted")
                })?;
            if claim.lane == Lane::Heavy && canonical_output.len() > 1 {
                self.record_incident(claim, "heavy_lane_output_policy")?;
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

            self.transition_claim(
                claim,
                ClaimState::Settled,
                taxed_bits + vault_result.kout_bits_total,
                e_value,
                None,
            )?;
            if claim.lane == Lane::Heavy {
                self.transition_claim(claim, ClaimState::Frozen, 0.0, 0.0, None)?;
            } else if claim.ledger.can_certify() {
                self.transition_claim(claim, ClaimState::Certified, 0.0, 0.0, None)?;
            } else {
                self.transition_claim(claim, ClaimState::Revoked, 0.0, 0.0, None)?;
            }

            let mut capsule = ClaimCapsule::new(
                hex::encode(claim.claim_id),
                hex::encode(claim.topic_id),
                claim.output_schema_id.clone(),
                claim
                    .artifacts
                    .iter()
                    .map(|(hash, kind)| ManifestEntry {
                        kind: kind.clone(),
                        hash_hex: hex::encode(hash),
                    })
                    .collect(),
                claim.dependency_capsule_hashes.clone(),
                &canonical_output,
                &claim.wasm_module,
                &claim.holdout_handle_id,
                &claim.ledger,
                e_value,
                claim.state == ClaimState::Certified,
                req.decision,
                req.reason_codes.clone(),
                Vec::new(),
                &trace_hash,
                claim.holdout_ref.clone(),
                format!("deterministic-kernel-{}", env!("CARGO_PKG_VERSION")),
                "aspec.v1".to_string(),
                "evidenceos.v1".to_string(),
                fuel_used as f64,
            );
            capsule.semantic_hash_hex = Some(hex::encode(claim.semantic_hash));
            capsule.physhir_hash_hex = Some(hex::encode(claim.phys_hir_hash));
            capsule.lineage_root_hash_hex = Some(hex::encode(claim.lineage_root_hash));
            capsule.output_schema_id_hash_hex = Some(hex::encode(claim.output_schema_id_hash));
            capsule.holdout_handle_hash_hex = Some(hex::encode(claim.holdout_handle_hash));
            capsule.disagreement_score = Some(claim.disagreement_score);
            capsule.semantic_physhir_distance_bits = Some(claim.semantic_physhir_distance_bits);
            capsule.escalate_to_heavy = Some(claim.escalate_to_heavy);
            capsule.state = if claim.state == ClaimState::Certified {
                CoreClaimState::Certified
            } else {
                CoreClaimState::Settled
            };
            let capsule_bytes = capsule
                .to_json_bytes()
                .map_err(|_| Status::internal("capsule serialization failed"))?;
            let capsule_hash = decode_hex_hash32(
                &capsule
                    .capsule_hash_hex()
                    .map_err(|_| Status::internal("capsule hashing failed"))?,
                "capsule_hash",
            )?;
            if claim.lineage_root_hash == [0u8; 32] {
                claim.lineage_root_hash = capsule_hash;
            }
            if claim.lineage_root_hash == [0u8; 32] {
                claim.lineage_root_hash = capsule_hash;
            }
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
        let principal_id = Self::principal_id_from_metadata(request.metadata());
        let req = request.into_inner();
        validate_required_str_field(&req.claim_name, "claim_name", 128)?;
        if req.epoch_size == 0 {
            return Err(Status::invalid_argument("epoch_size must be > 0"));
        }
        validate_required_str_field(&req.holdout_ref, "holdout_ref", 128)?;
        let metadata = req
            .metadata
            .ok_or_else(|| Status::invalid_argument("metadata is required"))?;
        validate_required_str_field(
            &metadata.epoch_config_ref,
            "metadata.epoch_config_ref",
            MAX_METADATA_FIELD_LEN,
        )?;
        validate_required_str_field(
            &metadata.output_schema_id,
            "metadata.output_schema_id",
            MAX_METADATA_FIELD_LEN,
        )?;
        let canonical_output_schema_id =
            structured_claims::canonicalize_schema_id(&metadata.output_schema_id)
                .map_err(|_| {
                    Status::invalid_argument(
                "unsupported metadata.output_schema_id; canonicalize to cbrn-sc.v1 or legacy/v1",
            )
                })?
                .to_string();
        let signals = req
            .signals
            .ok_or_else(|| Status::invalid_argument("signals are required"))?;
        if signals.phys_hir_signature_hash.len() != 32 {
            return Err(Status::invalid_argument(
                "signals.phys_hir_signature_hash must be 32 bytes",
            ));
        }
        let semantic_hash = if signals.semantic_hash.len() == 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&signals.semantic_hash);
            b
        } else {
            return Err(Status::invalid_argument(
                "signals.semantic_hash must be 32 bytes",
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
        let mut holdout_hasher = Sha256::new();
        holdout_hasher.update(req.holdout_ref.as_bytes());
        let mut holdout_handle_id = [0u8; 32];
        holdout_handle_id.copy_from_slice(&holdout_hasher.finalize());
        let output_schema_id_hash = hash_signal(
            b"evidenceos/schema_id",
            canonical_output_schema_id.as_bytes(),
        );
        let holdout_handle_hash = hash_signal(b"evidenceos/holdout_handle", &holdout_handle_id);
        let lineage_root_hash = dependency_merkle_root.unwrap_or([0u8; 32]);

        let topic = compute_topic_id(
            &CoreClaimMetadataV2 {
                lane: metadata.lane.clone(),
                alpha_micros: metadata.alpha_micros,
                epoch_config_ref: metadata.epoch_config_ref,
                output_schema_id: canonical_output_schema_id.clone(),
            },
            &TopicSignals {
                semantic_hash,
                physhir_hash: phys,
                lineage_root_hash,
                output_schema_id_hash,
                holdout_handle_hash,
            },
        );

        let alpha = (metadata.alpha_micros as f64) / 1_000_000.0;
        let access_credit = req.access_credit as f64;
        Self::validate_budget_value(access_credit, "access_credit")?;
        let requested = requested_lane(&metadata.lane)?;
        let lane = if topic.escalate_to_heavy {
            Lane::Heavy
        } else {
            requested
        };
        if lane != requested {
            self.telemetry
                .record_lane_escalation(Self::lane_name(requested), Self::lane_name(lane));
        }
        let lane_cfg = LaneConfig::for_lane(lane, req.oracle_num_symbols, access_credit)?;
        let ledger = ConservationLedger::new(alpha)
            .map_err(|_| Status::invalid_argument("alpha_micros must encode alpha in (0,1)"))
            .map(|l| {
                l.with_budgets(
                    Some(lane_cfg.k_bits_budget),
                    Some(lane_cfg.access_credit_budget),
                )
            })?;

        let oracle_resolution = lane_cfg.oracle_resolution;

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(&topic.topic_id);
        id_payload.extend_from_slice(&holdout_handle_id);
        id_payload.extend_from_slice(&phys);
        id_payload.extend_from_slice(&req.epoch_size.to_be_bytes());
        id_payload.extend_from_slice(&oracle_resolution.num_symbols.to_be_bytes());
        let claim_id = sha256_domain(DOMAIN_CLAIM_ID, &id_payload);

        let operation_id = build_operation_id(
            topic.topic_id,
            dependency_merkle_root,
            claim_id,
            "create_claim_v2",
            Some(phys),
        );
        self.observe_probe(
            principal_id,
            operation_id.clone(),
            hex::encode(topic.topic_id),
            Self::probe_semantic_hash(Some(&signals)),
        )?;
        let claim = Claim {
            claim_id,
            topic_id: topic.topic_id,
            dependency_merkle_root,
            holdout_handle_id,
            holdout_ref: req.holdout_ref,
            metadata_locked: false,
            claim_name: req.claim_name,
            output_schema_id: canonical_output_schema_id,
            phys_hir_hash: phys,
            semantic_hash,
            output_schema_id_hash,
            holdout_handle_hash,
            lineage_root_hash,
            disagreement_score: topic.disagreement_score,
            semantic_physhir_distance_bits: topic.semantic_physhir_distance_bits,
            escalate_to_heavy: topic.escalate_to_heavy,
            epoch_size: req.epoch_size,
            epoch_counter: 0,
            oracle_num_symbols: req.oracle_num_symbols,
            oracle_resolution,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            wasm_module: Vec::new(),
            aspec_rejection: None,
            aspec_report_summary: None,
            lane,
            heavy_lane_diversion_recorded: lane == Lane::Heavy,
            ledger,
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id,
        };
        self.state.claims.lock().insert(claim_id, claim.clone());
        self.state
            .topic_pools
            .lock()
            .entry(topic.topic_id)
            .or_insert(
                TopicBudgetPool::new(
                    hex::encode(topic.topic_id),
                    lane_cfg.k_bits_budget,
                    lane_cfg.access_credit_budget,
                )
                .map_err(|_| Status::invalid_argument("invalid topic budget"))?,
            );
        self.state
            .holdout_pools
            .lock()
            .entry(holdout_handle_id)
            .or_insert(HoldoutBudgetPool::new(
                holdout_handle_id,
                access_credit,
                access_credit,
            )?);
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
        let principal_id = Self::principal_id_from_metadata(request.metadata());
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
            let claim_id_hex = hex::encode(claim.claim_id);
            let span = tracing::info_span!("execute_claim_v2", operation_id=%claim.operation_id, claim_id=%claim_id_hex);
            let _guard = span.enter();
            let current_epoch = self.current_epoch_for_claim(claim)?;
            Self::maybe_mark_stale(claim, current_epoch)?;
            if claim.state == ClaimState::Stale {
                return Err(Status::failed_precondition(
                    "claim is stale; re-freeze before execution",
                ));
            }
            if claim.state != ClaimState::Sealed {
                return Err(Status::failed_precondition(
                    "claim must be SEALED before execution",
                ));
            }
            if claim.freeze_preimage.is_none() {
                return Err(Status::failed_precondition("freeze gates not completed"));
            }
            claim.operation_id = build_operation_id(
                claim.topic_id,
                claim.dependency_merkle_root,
                claim.claim_id,
                "execute_claim_v2",
                Some(claim.phys_hir_hash),
            );
            self.observe_probe(
                principal_id.clone(),
                claim.operation_id.clone(),
                hex::encode(claim.topic_id),
                hex::encode(claim.phys_hir_hash),
            )?;
            let nullspec_store = NullSpecStore::open(&self.state.data_path)
                .map_err(|_| Status::internal("nullspec store init failed"))?;
            let active_id = match nullspec_store
                .active_for(&claim.claim_name, &claim.holdout_ref)
                .map_err(|_| Status::internal("nullspec mapping read failed"))?
            {
                Some(id) => id,
                None => {
                    self.record_incident(claim, "nullspec_missing")?;
                    return Err(Status::failed_precondition("missing active nullspec"));
                }
            };
            let contract = nullspec_store
                .get(&active_id)
                .map_err(|_| Status::failed_precondition("active nullspec not found"))?;
            if contract.is_expired(current_epoch) {
                self.record_incident(claim, "nullspec_expired")?;
                return Err(Status::failed_precondition("active nullspec expired"));
            }
            let expected_resolution_hash = oracle_resolution_hash(&claim.oracle_resolution)?;
            if contract.oracle_resolution_hash != expected_resolution_hash {
                self.record_incident(claim, "nullspec_resolution_hash_mismatch")?;
                return Err(Status::failed_precondition(
                    "nullspec resolution hash mismatch",
                ));
            }

            let oracle_ttl_expired = claim.oracle_resolution.ttl_expired(current_epoch);
            let oracle_ttl_escalated = if oracle_ttl_expired {
                match self.oracle_ttl_policy {
                    OracleTtlPolicy::RejectExpired => {
                        self.record_incident(claim, "oracle_expired")?;
                        return Err(Status::failed_precondition("OracleExpired"));
                    }
                    OracleTtlPolicy::EscalateToHeavy => {
                        if claim.lane != Lane::Heavy {
                            self.record_incident(claim, "oracle_expired")?;
                            return Err(Status::failed_precondition("OracleExpired"));
                        }
                        self.record_incident(claim, "oracle_expired_escalated_to_heavy")?;
                        true
                    }
                }
            } else {
                false
            };

            self.transition_claim(claim, ClaimState::Executing, 0.0, 0.0, None)?;
            let vault = VaultEngine::new().map_err(map_vault_error)?;
            let keyring = NullSpecAuthorityKeyring::load_from_dir(std::path::Path::new(
                "./trusted-nullspec-keys",
            ))
            .map_err(|_| Status::failed_precondition("nullspec keyring load failed"))?;
            let registry = NullSpecRegistry::load_from_dir(
                std::path::Path::new("./nullspec-registry"),
                &keyring,
                false,
            )
            .map_err(|_| Status::failed_precondition("nullspec registry load failed"))?;
            let reg_nullspec = registry
                .get(&hex::encode(contract.nullspec_id))
                .cloned()
                .ok_or_else(|| Status::failed_precondition("active nullspec id not in registry"))?;
            let context = vault_context(claim, reg_nullspec)?;
            let vault_result =
                match vault.execute(&claim.wasm_module, &context, vault_config(claim)?) {
                    Ok(v) => v,
                    Err(err) => {
                        self.record_incident(claim, "execution_failure")?;
                        return Err(map_vault_error(err));
                    }
                };
            self.telemetry.record_oracle_calls(
                Self::lane_name(claim.lane),
                "vault_oracle_bucket",
                u64::from(vault_result.oracle_calls),
            );
            let canonical_output = vault_result.canonical_output.clone();
            let fuel_used = vault_result.fuel_used;
            let trace_hash = vault_result.judge_trace_hash;
            if claim.output_schema_id == structured_claims::LEGACY_SCHEMA_ID {
                let _sym = decode_canonical_symbol(&canonical_output, claim.oracle_num_symbols)?;
            }
            let mut physhir_mismatch = false;
            if claim.output_schema_id != structured_claims::LEGACY_SCHEMA_ID {
                if let Ok(validated) = structured_claims::validate_and_canonicalize(
                    &claim.output_schema_id,
                    &canonical_output,
                ) {
                    let computed_phys =
                        evidenceos_core::physhir::physhir_signature_hash(&validated.claim);
                    let topic_check = compute_topic_id(
                        &CoreClaimMetadataV2 {
                            lane: Self::lane_name(claim.lane).to_string(),
                            alpha_micros: (claim.ledger.alpha * 1_000_000.0).round() as u32,
                            epoch_config_ref: "execute".to_string(),
                            output_schema_id: claim.output_schema_id.clone(),
                        },
                        &TopicSignals {
                            semantic_hash: claim.semantic_hash,
                            physhir_hash: computed_phys,
                            lineage_root_hash: claim.lineage_root_hash,
                            output_schema_id_hash: claim.output_schema_id_hash,
                            holdout_handle_hash: claim.holdout_handle_hash,
                        },
                    );
                    claim.phys_hir_hash = computed_phys;
                    claim.disagreement_score = topic_check.disagreement_score;
                    claim.semantic_physhir_distance_bits =
                        topic_check.semantic_physhir_distance_bits;
                    claim.escalate_to_heavy = topic_check.escalate_to_heavy;
                    physhir_mismatch = topic_check.escalate_to_heavy;
                }
            }
            let charge_bits = claim.oracle_resolution.bits_per_call()
                * f64::from(vault_result.oracle_calls.max(1));
            let dependence_multiplier = if oracle_ttl_escalated {
                self.dependence_tax_multiplier * self.oracle_ttl_escalation_tax_multiplier
            } else {
                self.dependence_tax_multiplier
            };
            let taxed_bits = charge_bits * dependence_multiplier;
            let covariance_charge = taxed_bits - charge_bits;
            let lane_cfg = LaneConfig::for_lane(
                claim.lane,
                claim.oracle_num_symbols,
                claim.ledger.access_credit_budget.unwrap_or(0.0),
            )?;
            let dp_epsilon = lane_cfg.dp_epsilon_budget * 0.0;
            let dp_delta = lane_cfg.dp_delta_budget * 0.0;
            claim
                .ledger
                .charge_all(
                    taxed_bits,
                    dp_epsilon,
                    dp_delta,
                    taxed_bits,
                    "structured_output",
                    json!({
                        "post_canonical_bits": charge_bits,
                        "dependence_multiplier": dependence_multiplier,
                        "taxed_k_bits": taxed_bits,
                        "dp_epsilon": dp_epsilon,
                        "dp_delta": dp_delta,
                    }),
                )
                .map_err(|_| Status::failed_precondition("ledger budget exhausted"))?;
            claim
                .ledger
                .charge_kout_bits(vault_result.kout_bits_total)
                .map_err(|_| Status::failed_precondition("ledger kout budget exhausted"))?;
            {
                let mut topic_pools = self.state.topic_pools.lock();
                let pool = topic_pools
                    .get_mut(&claim.topic_id)
                    .ok_or_else(|| Status::failed_precondition("missing topic budget pool"))?;
                if pool
                    .charge(
                        taxed_bits + vault_result.kout_bits_total,
                        taxed_bits + vault_result.kout_bits_total,
                        covariance_charge,
                    )
                    .is_err()
                {
                    let _ = self.record_incident(claim, "topic_budget_exhausted");
                    return Err(Status::failed_precondition("topic budget exhausted"));
                }
            }
            {
                let mut holdout_pools = self.state.holdout_pools.lock();
                let pool = holdout_pools
                    .get_mut(&claim.holdout_handle_id)
                    .ok_or_else(|| Status::failed_precondition("missing holdout budget pool"))?;
                if pool
                    .charge(
                        taxed_bits + vault_result.kout_bits_total,
                        taxed_bits + vault_result.kout_bits_total,
                    )
                    .is_err()
                {
                    let _ = self.record_incident(claim, "holdout_budget_exhausted");
                    return Err(Status::failed_precondition("holdout budget exhausted"));
                }
            }
            let (e_value, eprocess_kind_id) =
                compute_nullspec_e_value(&contract, &vault_result.oracle_buckets)?;
            let canary_key = Self::canary_key(&claim.claim_name, &claim.holdout_ref);
            let mut canary_state = {
                let mut canary_states = self.state.canary_states.lock();
                if !canary_states.contains_key(&canary_key) {
                    let initial = CanaryState::new(self.canary_config)
                        .map_err(|_| Status::internal("canary state init failed"))?;
                    canary_states.insert(canary_key.clone(), initial);
                }
                canary_states
                    .get(&canary_key)
                    .cloned()
                    .ok_or_else(|| Status::internal("missing canary state"))?
            };
            for b in &vault_result.oracle_buckets {
                let bucket = usize::try_from(*b)
                    .map_err(|_| Status::failed_precondition("bucket overflow"))?;
                canary_state
                    .update_with_bucket(&contract, bucket, current_epoch)
                    .map_err(|_| Status::failed_precondition("canary drift update failed"))?;
            }
            {
                let mut canary_states = self.state.canary_states.lock();
                canary_states.insert(canary_key, canary_state.clone());
            }
            claim
                .ledger
                .settle_e_value(e_value, "decision", json!({"e_value_total": e_value}))
                .map_err(|_| Status::invalid_argument("invalid e-value"))?;
            self.transition_claim(
                claim,
                ClaimState::Settled,
                taxed_bits + vault_result.kout_bits_total,
                e_value,
                None,
            )?;
            let can_certify = claim.ledger.can_certify();
            let mut decision =
                if claim.ledger.frozen || claim.lane == Lane::Heavy || physhir_mismatch {
                    pb::Decision::Defer as i32
                } else if can_certify {
                    pb::Decision::Approve as i32
                } else {
                    pb::Decision::Reject as i32
                };
            if canary_state.drift_frozen {
                decision = pb::Decision::Reject as i32;
                self.append_canary_incident(
                    claim,
                    "canary_drift_frozen",
                    canary_state.e_drift,
                    canary_state.barrier,
                )?;
            }
            let mut reason_codes = match decision {
                x if x == pb::Decision::Approve as i32 => vec![1],
                x if x == pb::Decision::Defer as i32 => {
                    self.telemetry.record_reject("defer");
                    vec![3]
                }
                _ => {
                    self.telemetry.record_reject("reject");
                    vec![2]
                }
            };
            if canary_state.drift_frozen {
                reason_codes.push(91);
            }
            if physhir_mismatch {
                reason_codes.push(9104);
            }
            let oracle_input = policy_oracle_input_json(
                claim,
                &vault_result,
                &claim.ledger,
                &canonical_output,
                &reason_codes,
            )?;
            let mut policy_receipts: Vec<PolicyOracleReceipt> = Vec::new();
            if oracle_ttl_expired {
                reason_codes.push(ORACLE_EXPIRED_REASON_CODE);
                policy_receipts.push(PolicyOracleReceipt {
                    oracle_id: "oracle_ttl".to_string(),
                    manifest_hash_hex: hex::encode([0_u8; 32]),
                    wasm_hash_hex: hex::encode([0_u8; 32]),
                    decision: if oracle_ttl_escalated {
                        "defer".to_string()
                    } else {
                        "reject".to_string()
                    },
                    reason_code: if oracle_ttl_escalated {
                        ORACLE_TTL_ESCALATED_REASON_CODE
                    } else {
                        ORACLE_EXPIRED_REASON_CODE
                    },
                });
            }
            let mut oracle_decision = PolicyOracleDecision::Pass;
            for oracle in self.policy_oracles.iter() {
                match oracle.evaluate(&oracle_input) {
                    Ok((d, receipt)) => {
                        if d != PolicyOracleDecision::Pass {
                            reason_codes.push(receipt.reason_code);
                        }
                        if d == PolicyOracleDecision::Reject {
                            oracle_decision = PolicyOracleDecision::Reject;
                        } else if d == PolicyOracleDecision::DeferToHeavy
                            && oracle_decision != PolicyOracleDecision::Reject
                        {
                            oracle_decision = PolicyOracleDecision::DeferToHeavy;
                        }
                        policy_receipts.push(receipt);
                    }
                    Err(_) => {
                        oracle_decision = PolicyOracleDecision::DeferToHeavy;
                        let receipt = oracle.fail_closed_receipt();
                        reason_codes.push(receipt.reason_code);
                        policy_receipts.push(receipt);
                    }
                }
            }
            if oracle_decision == PolicyOracleDecision::Reject {
                decision = pb::Decision::Reject as i32;
            } else if oracle_decision == PolicyOracleDecision::DeferToHeavy {
                decision = pb::Decision::Defer as i32;
            }
            if decision != pb::Decision::Approve as i32 {
                let clamped = e_value.min(1.0);
                if clamped < e_value {
                    claim.ledger.wealth *= clamped / e_value;
                }
            }
            if decision == pb::Decision::Defer as i32 {
                self.transition_claim(claim, ClaimState::Frozen, 0.0, 0.0, None)?;
            } else if decision == pb::Decision::Approve as i32 {
                self.transition_claim(claim, ClaimState::Certified, 0.0, 0.0, None)?;
            } else {
                self.transition_claim(claim, ClaimState::Revoked, 0.0, 0.0, None)?;
            }
            reason_codes.sort_unstable();
            reason_codes.dedup();
            let e_value = if decision == pb::Decision::Approve as i32 {
                e_value
            } else {
                e_value.min(1.0)
            };
            let canonical_output = kernel_structured_output(
                &claim.output_schema_id,
                &canonical_output,
                decision,
                &reason_codes,
                e_value,
            )?;
            let mut capsule = ClaimCapsule::new(
                hex::encode(claim.claim_id),
                hex::encode(claim.topic_id),
                claim.output_schema_id.clone(),
                claim
                    .artifacts
                    .iter()
                    .map(|(hash, kind)| ManifestEntry {
                        kind: kind.clone(),
                        hash_hex: hex::encode(hash),
                    })
                    .collect(),
                claim.dependency_capsule_hashes.clone(),
                &canonical_output,
                &claim.wasm_module,
                &claim.holdout_handle_id,
                &claim.ledger,
                e_value,
                claim.state == ClaimState::Certified,
                decision,
                reason_codes.clone(),
                policy_receipts.into_iter().map(Into::into).collect(),
                &trace_hash,
                claim.holdout_ref.clone(),
                format!("deterministic-kernel-{}", env!("CARGO_PKG_VERSION")),
                "aspec.v1".to_string(),
                "evidenceos.v1".to_string(),
                fuel_used as f64,
            );
            capsule.nullspec_id_hex = Some(hex::encode(contract.nullspec_id));
            capsule.oracle_resolution_hash_hex = Some(hex::encode(contract.oracle_resolution_hash));
            capsule.eprocess_kind = Some(eprocess_kind_id);
            capsule.nullspec_contract_hash_hex = Some(hex::encode(contract.compute_id()));
            capsule.semantic_hash_hex = Some(hex::encode(claim.semantic_hash));
            capsule.physhir_hash_hex = Some(hex::encode(claim.phys_hir_hash));
            capsule.lineage_root_hash_hex = Some(hex::encode(claim.lineage_root_hash));
            capsule.output_schema_id_hash_hex = Some(hex::encode(claim.output_schema_id_hash));
            capsule.holdout_handle_hash_hex = Some(hex::encode(claim.holdout_handle_hash));
            capsule.disagreement_score = Some(claim.disagreement_score);
            capsule.semantic_physhir_distance_bits = Some(claim.semantic_physhir_distance_bits);
            capsule.escalate_to_heavy = Some(claim.escalate_to_heavy);
            capsule.state = if claim.state == ClaimState::Certified {
                CoreClaimState::Certified
            } else {
                CoreClaimState::Settled
            };
            let capsule_bytes = capsule
                .to_json_bytes()
                .map_err(|_| Status::internal("capsule serialization failed"))?;
            let capsule_hash = decode_hex_hash32(
                &capsule
                    .capsule_hash_hex()
                    .map_err(|_| Status::internal("capsule hashing failed"))?,
                "capsule_hash",
            )?;
            let etl_index = if self.offline_settlement_ingest {
                let proposal = UnsignedSettlementProposal {
                    schema_version: 1,
                    claim_id_hex: hex::encode(claim.claim_id),
                    claim_state: Self::state_name(claim.state).to_string(),
                    epoch: claim.epoch_counter,
                    capsule_bytes: capsule_bytes.clone(),
                    capsule_hash_hex: hex::encode(capsule_hash),
                };
                write_unsigned_proposal(&self.state.data_path, &proposal)
                    .map_err(|_| Status::internal("offline settlement spool write failed"))?;
                0
            } else {
                let mut etl = self.state.etl.lock();
                let (idx, _) = etl
                    .append(&capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                idx
            };
            claim.last_decision = Some(decision);
            claim.last_capsule_hash = Some(capsule_hash);
            claim.capsule_bytes = Some(capsule_bytes);
            claim.etl_index = if self.offline_settlement_ingest {
                None
            } else {
                Some(etl_index)
            };
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
        let resp = <Self as EvidenceOsV2>::fetch_capsule(
            self,
            Request::new(pb::FetchCapsuleRequest { claim_id }),
        )
        .await?
        .into_inner();
        Ok(Response::new(pb::GetCapsuleResponse {
            capsule_bytes: resp.capsule_bytes,
            capsule_hash: resp.capsule_hash,
            etl_index: resp.etl_index,
        }))
    }

    async fn get_public_key(
        &self,
        request: Request<pb::GetPublicKeyRequest>,
    ) -> Result<Response<pb::GetPublicKeyResponse>, Status> {
        let req = request.into_inner();
        let requested_key_id = if req.key_id.is_empty() {
            self.state.active_key_id
        } else {
            parse_hash32(&req.key_id, "key_id")?
        };
        let signing_key = self
            .state
            .keyring
            .get(&requested_key_id)
            .ok_or_else(|| Status::not_found("key not found"))?;
        Ok(Response::new(pb::GetPublicKeyResponse {
            ed25519_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            key_id: requested_key_id.to_vec(),
        }))
    }

    async fn get_signed_tree_head(
        &self,
        _request: Request<pb::GetSignedTreeHeadRequest>,
    ) -> Result<Response<pb::GetSignedTreeHeadResponse>, Status> {
        let etl = self.state.etl.lock();
        let signing_key = self.active_signing_key()?;
        let sth = build_signed_tree_head(&etl, signing_key, self.state.active_key_id);
        Ok(Response::new(pb::GetSignedTreeHeadResponse {
            tree_size: sth.tree_size,
            root_hash: sth.root_hash,
            signature: sth.signature,
            key_id: sth.key_id,
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
        let response = <Self as EvidenceOsV2>::watch_revocations(
            self,
            Request::new(pb::WatchRevocationsRequest {}),
        )
        .await?;
        let mut stream = response.into_inner();
        let item = stream
            .next()
            .await
            .ok_or_else(|| Status::not_found("no revocations"))??;
        Ok(Response::new(pb::GetRevocationFeedResponse {
            entries: item.entries,
            signature: item.signature,
            key_id: item.key_id,
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
            signed_tree_head: Some(build_signed_tree_head(
                &etl,
                self.active_signing_key()?,
                self.state.active_key_id,
            )),
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
        let capsule_hash = {
            let claims = self.state.claims.lock();
            let claim = claims
                .get(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            claim
                .last_capsule_hash
                .ok_or_else(|| Status::failed_precondition("capsule hash unavailable"))?
        };
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
            etl.revoke(&hex::encode(capsule_hash), &req.reason)
                .map_err(|_| Status::internal("etl revoke failed"))?;
            let tainted = etl.taint_descendants(&hex::encode(capsule_hash));
            if !tainted.is_empty() {
                let mut claims = self.state.claims.lock();
                for claim in claims.values_mut() {
                    if let Some(hash) = claim.last_capsule_hash {
                        let hash_hex = hex::encode(hash);
                        if tainted.iter().any(|t| t == &hash_hex) {
                            claim.state = ClaimState::Tainted;
                        }
                    }
                }
            }
        }

        self.state
            .revocations
            .lock()
            .push((capsule_hash, timestamp_unix, req.reason.clone()));
        persist_all(&self.state)?;

        let message = {
            let etl = self.state.etl.lock();
            build_revocations_snapshot(
                self.active_signing_key()?,
                self.state.active_key_id,
                vec![(capsule_hash, timestamp_unix, req.reason)],
                build_signed_tree_head(&etl, self.active_signing_key()?, self.state.active_key_id),
            )
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
        let etl = self.state.etl.lock();
        let snapshot = build_revocations_snapshot(
            self.active_signing_key()?,
            self.state.active_key_id,
            entries_raw,
            build_signed_tree_head(&etl, self.active_signing_key()?, self.state.active_key_id),
        );
        let _ = tx.try_send(snapshot);

        Ok(Response::new(Box::pin(ReceiverStream::new(rx).map(Ok))))
    }
}

use tokio_stream::StreamExt;

fn transcode_message<T, U>(value: T) -> Result<U, Status>
where
    T: Message,
    U: Message + Default,
{
    let mut buf = Vec::new();
    value
        .encode(&mut buf)
        .map_err(|_| Status::internal("protobuf transcode encode failure"))?;
    U::decode(buf.as_slice()).map_err(|_| Status::internal("protobuf transcode decode failure"))
}

#[tonic::async_trait]
impl EvidenceOsV1 for EvidenceOsService {
    type WatchRevocationsStream = Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<v1::WatchRevocationsResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn health(
        &self,
        request: Request<v1::HealthRequest>,
    ) -> Result<Response<v1::HealthResponse>, Status> {
        let req_v2: v2::HealthRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::health(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn create_claim(
        &self,
        request: Request<v1::CreateClaimRequest>,
    ) -> Result<Response<v1::CreateClaimResponse>, Status> {
        let req_v2: v2::CreateClaimRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::create_claim(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn create_claim_v2(
        &self,
        request: Request<v1::CreateClaimV2Request>,
    ) -> Result<Response<v1::CreateClaimV2Response>, Status> {
        let req_v2: v2::CreateClaimV2Request = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::create_claim_v2(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn commit_artifacts(
        &self,
        request: Request<v1::CommitArtifactsRequest>,
    ) -> Result<Response<v1::CommitArtifactsResponse>, Status> {
        let req_v2: v2::CommitArtifactsRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::commit_artifacts(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn freeze_gates(
        &self,
        request: Request<v1::FreezeGatesRequest>,
    ) -> Result<Response<v1::FreezeGatesResponse>, Status> {
        let req_v2: v2::FreezeGatesRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::freeze_gates(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn seal_claim(
        &self,
        request: Request<v1::SealClaimRequest>,
    ) -> Result<Response<v1::SealClaimResponse>, Status> {
        let req_v2: v2::SealClaimRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::seal_claim(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn execute_claim(
        &self,
        request: Request<v1::ExecuteClaimRequest>,
    ) -> Result<Response<v1::ExecuteClaimResponse>, Status> {
        let req_v2: v2::ExecuteClaimRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::execute_claim(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn execute_claim_v2(
        &self,
        request: Request<v1::ExecuteClaimV2Request>,
    ) -> Result<Response<v1::ExecuteClaimV2Response>, Status> {
        let req_v2: v2::ExecuteClaimV2Request = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::execute_claim_v2(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_capsule(
        &self,
        request: Request<v1::GetCapsuleRequest>,
    ) -> Result<Response<v1::GetCapsuleResponse>, Status> {
        let req_v2: v2::GetCapsuleRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::get_capsule(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_public_key(
        &self,
        request: Request<v1::GetPublicKeyRequest>,
    ) -> Result<Response<v1::GetPublicKeyResponse>, Status> {
        let req_v2: v2::GetPublicKeyRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::get_public_key(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_signed_tree_head(
        &self,
        request: Request<v1::GetSignedTreeHeadRequest>,
    ) -> Result<Response<v1::GetSignedTreeHeadResponse>, Status> {
        let req_v2: v2::GetSignedTreeHeadRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::get_signed_tree_head(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_inclusion_proof(
        &self,
        request: Request<v1::GetInclusionProofRequest>,
    ) -> Result<Response<v1::GetInclusionProofResponse>, Status> {
        let req_v2: v2::GetInclusionProofRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::get_inclusion_proof(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_consistency_proof(
        &self,
        request: Request<v1::GetConsistencyProofRequest>,
    ) -> Result<Response<v1::GetConsistencyProofResponse>, Status> {
        let req_v2: v2::GetConsistencyProofRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::get_consistency_proof(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_revocation_feed(
        &self,
        request: Request<v1::GetRevocationFeedRequest>,
    ) -> Result<Response<v1::GetRevocationFeedResponse>, Status> {
        let req_v2: v2::GetRevocationFeedRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::get_revocation_feed(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn fetch_capsule(
        &self,
        request: Request<v1::FetchCapsuleRequest>,
    ) -> Result<Response<v1::FetchCapsuleResponse>, Status> {
        let req_v2: v2::FetchCapsuleRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::fetch_capsule(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn revoke_claim(
        &self,
        request: Request<v1::RevokeClaimRequest>,
    ) -> Result<Response<v1::RevokeClaimResponse>, Status> {
        let req_v2: v2::RevokeClaimRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::revoke_claim(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn watch_revocations(
        &self,
        request: Request<v1::WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let req_v2: v2::WatchRevocationsRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::watch_revocations(self, Request::new(req_v2)).await?;
        let stream = response
            .into_inner()
            .map(|item| item.and_then(transcode_message));
        Ok(Response::new(
            Box::pin(stream) as Self::WatchRevocationsStream
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn canonical_encoding_rejects_invalid_without_charge() {
        let mut ledger = ConservationLedger::new(0.1).expect("valid ledger");
        let oracle = OracleResolution::new(2, 0.0).expect("resolution");
        assert!(oracle.decode_bucket(&[0xFF]).is_err());
        assert_eq!(ledger.k_bits_total, 0.0);
        ledger
            .charge(1.0, "structured_output", json!({}))
            .expect("charge should pass");
        assert_eq!(ledger.k_bits_total, 1.0);
    }

    #[test]
    fn signed_tree_head_signature_verifies_and_tamper_fails() {
        let secret = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let root_hash = [11u8; 32];
        let digest = sth_signature_payload(42, &root_hash);
        let sig = Signature::from_bytes(&sign_payload(&signing_key, &digest));
        signing_key
            .verifying_key()
            .verify(&digest, &sig)
            .expect("verify should pass");

        let mut tampered = digest;
        tampered[0] ^= 0x01;
        assert!(signing_key.verifying_key().verify(&tampered, &sig).is_err());
    }

    #[test]
    fn lane_config_mapping_is_deterministic() {
        assert_eq!(requested_lane("fast").expect("fast"), Lane::Fast);
        assert_eq!(requested_lane("heavy").expect("heavy"), Lane::Heavy);
        let fast = LaneConfig::for_lane(Lane::Fast, 4, 64.0).expect("fast cfg");
        let heavy = LaneConfig::for_lane(Lane::Heavy, 4, 64.0).expect("heavy cfg");
        assert!(matches!(fast.aspec_policy.lane, AspecLane::HighAssurance));
        assert!(matches!(heavy.aspec_policy.lane, AspecLane::LowAssurance));
        assert!(heavy.aspec_policy.max_loop_bound >= fast.aspec_policy.max_loop_bound);
    }

    #[test]
    fn revocation_payload_is_unambiguous_for_multiple_entries() {
        let entries_ab = vec![
            pb::RevocationEntry {
                claim_id: vec![1],
                timestamp_unix: 2,
                reason: "34".to_string(),
            },
            pb::RevocationEntry {
                claim_id: vec![5],
                timestamp_unix: 6,
                reason: "7".to_string(),
            },
        ];
        let entries_a_b = vec![pb::RevocationEntry {
            claim_id: vec![1],
            timestamp_unix: 2,
            reason: "345".to_string(),
        }];

        let digest_ab = revocations_signature_payload(&entries_ab);
        let digest_a_b = revocations_signature_payload(&entries_a_b);
        assert_ne!(digest_ab, digest_a_b);

        let secret = [9u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let sig = Signature::from_bytes(&sign_payload(&signing_key, &digest_ab));
        signing_key
            .verifying_key()
            .verify(&digest_ab, &sig)
            .expect("verify should pass");

        let mut tampered = digest_ab;
        tampered[31] ^= 0x80;
        assert!(signing_key.verifying_key().verify(&tampered, &sig).is_err());
    }
}
