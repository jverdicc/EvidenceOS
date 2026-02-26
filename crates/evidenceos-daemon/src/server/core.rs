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

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::getrandom;
use parking_lot::Mutex;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::accounting::{
    AccessCreditPricing, AccountStore, AdmissionProvider, StaticAdmissionProvider,
};
use crate::auth::{derive_caller_identity, CallerIdentity};
use crate::config::OracleTtlPolicy;
use crate::key_management::{load_signing_key_from_kms, SigningKeySource};
use crate::policy_oracle::{PolicyOracleDecision, PolicyOracleEngine, PolicyOracleReceipt};
use crate::probe::{ProbeConfig, ProbeDetector, ProbeObservation, ProbeVerdict};
use crate::public_error::{public_status, PublicErrorCode};
use crate::server::execution::load_idempotency_records;
use crate::settlement::{import_signed_settlements, write_unsigned_proposal};
use crate::telemetry::{derive_operation_id, LifecycleEvent, Telemetry};
use crate::trial::{
    default_trial_arms_config, hash_arm_parameters, interventions_from_trial_config,
    load_trial_arms_config, validate_and_build_delta, AssignmentMode, BaselineCovariates,
    PersistedTrialAllocatorState, StratumKey, TrialAssignment, TrialRouter,
};
use crate::vault::{VaultConfig, VaultEngine, VaultError, VaultExecutionContext};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code, Request, Response, Status};

use evidenceos_core::aspec::{verify_aspec, AspecLane, AspecPolicy, FloatPolicy};
use evidenceos_core::canary::{CanaryConfig, CanaryState};
use evidenceos_core::capsule::{
    ClaimCapsule, ClaimState as CoreClaimState, ManifestEntry, TopicOracleReceiptLike,
    TrialMetadata,
};
use evidenceos_core::crypto_transcripts::{revocations_snapshot_digest, sth_signature_digest};
use evidenceos_core::dlc::{DeterministicLogicalClock, DlcConfig};
use evidenceos_core::eprocess::DirichletMixtureEProcess;
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};
use evidenceos_core::holdout_crypto::{decrypt_holdout_labels, EnvKeyProvider, HoldoutKeyProvider};
use evidenceos_core::ledger::{ConservationLedger, TopicBudgetPool};
use evidenceos_core::nullspec::{
    EProcessKind, NullSpecKind, SignedNullSpecContractV1, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_registry::{NullSpecAuthorityKeyring, NullSpecRegistry};
use evidenceos_core::nullspec_store::NullSpecStore;
use evidenceos_core::oracle::OracleResolution;
use evidenceos_core::settlement::UnsignedSettlementProposal;
use evidenceos_core::structured_claims;
use evidenceos_core::tee::{attestor_from_env, collect_attestation, TeeAttestor};
use evidenceos_core::topicid::{
    compute_topic_id, hash_signal, ClaimMetadataV2 as CoreClaimMetadataV2, TopicSignals,
};
use evidenceos_protocol::{
    pb, sha256_domain, DOMAIN_EPOCH_CONTROL_V1, DOMAIN_ORACLE_OPERATOR_RECORD_V1,
};

use pb::evidence_os_server::EvidenceOs as EvidenceOsV2;
use pb::v1;
use pb::v1::evidence_os_server::EvidenceOs as EvidenceOsV1;
use pb::v2;

const MAX_ARTIFACTS: usize = 128;
const MAX_REASON_CODES: usize = 32;
const MAX_DEPENDENCY_ITEMS: usize = 256;
const MAX_METADATA_FIELD_LEN: usize = 128;
const MAX_PRINCIPAL_ID_LEN: usize = 256;
const MAX_CREDIT_REASON_LEN: usize = 256;
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(300);
const DOMAIN_CLAIM_ID: &[u8] = b"evidenceos:claim_id:v2";
const DOMAIN_TOPIC_MANIFEST_HASH_V1: &[u8] = b"evidenceos:topic_manifest_hash:v1";
const DOMAIN_TOPIC_ORACLE_RECEIPT_V1: &[u8] = b"evidenceos:topic_oracle_receipt:v1";
const TRIAL_NONCE_LEN: usize = 16;
const TRIAL_COMMITMENT_SCHEMA_VERSION_V1: u8 = 1;
const TRIAL_COMMITMENT_SCHEMA_VERSION_V2: u8 = 2;
const TRIAL_COMMITMENT_SCHEMA_VERSION_CURRENT: u8 = TRIAL_COMMITMENT_SCHEMA_VERSION_V2;
const HOLDOUT_MANIFEST_SCHEMA_VERSION: u32 = 1;
const BURN_WASM_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, 0x0a, 0x08, 0x01, 0x06, 0x00,
    0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b,
];
const BUILD_GIT_COMMIT: &str = match option_env!("EVIDENCEOS_BUILD_GIT_COMMIT") {
    Some(v) => v,
    None => "unknown",
};
const BUILD_TIME_UTC: &str = match option_env!("EVIDENCEOS_BUILD_TIME_UTC") {
    Some(v) => v,
    None => "unknown",
};

#[cfg(feature = "crash-test-failpoints")]
fn maybe_abort_failpoint(name: &str) {
    if std::env::var("EVIDENCEOS_CRASH_FAILPOINT").ok().as_deref() == Some(name) {
        std::process::abort();
    }
}

#[cfg(not(feature = "crash-test-failpoints"))]
fn maybe_abort_failpoint(_name: &str) {}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HoldoutDescriptor {
    holdout_ref: String,
    handle: [u8; 32],
    len: usize,
    labels_hash: [u8; 32],
    encryption_key_id: Option<String>,
    holdout_k_bits_budget: Option<f64>,
    holdout_access_credit_budget: Option<f64>,
    holdout_pool_scope: Option<HoldoutPoolScope>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
enum HoldoutPoolScope {
    #[default]
    Global,
    PerPrincipal,
    Both,
}

impl HoldoutPoolScope {
    fn parse(scope: &str) -> Result<Self, Status> {
        match scope {
            "global" => Ok(Self::Global),
            "per_principal" => Ok(Self::PerPrincipal),
            "both" => Ok(Self::Both),
            _ => Err(Status::invalid_argument("invalid holdout_pool_scope")),
        }
    }
}

trait HoldoutProvider: Send + Sync {
    fn resolve(&self, holdout_ref: &str) -> Result<HoldoutDescriptor, Status>;
    fn load_labels(&self, descriptor: &HoldoutDescriptor) -> Result<Vec<u8>, Status>;
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct HoldoutManifestV1 {
    holdout_handle_hex: String,
    len: usize,
    labels_sha256_hex: String,
    created_at_unix: u64,
    schema_version: u32,
    encryption_key_id: Option<String>,
    holdout_k_bits_budget: Option<f64>,
    holdout_access_credit_budget: Option<f64>,
    holdout_pool_scope: Option<String>,
}

impl Default for HoldoutManifestV1 {
    fn default() -> Self {
        Self {
            holdout_handle_hex: String::new(),
            len: 0,
            labels_sha256_hex: String::new(),
            created_at_unix: 0,
            schema_version: HOLDOUT_MANIFEST_SCHEMA_VERSION,
            encryption_key_id: None,
            holdout_k_bits_budget: None,
            holdout_access_credit_budget: None,
            holdout_pool_scope: None,
        }
    }
}

struct RegistryHoldoutProvider {
    root: PathBuf,
    allow_plaintext: bool,
    key_provider: Arc<dyn HoldoutKeyProvider>,
}

impl RegistryHoldoutProvider {
    fn new(
        root: PathBuf,
        allow_plaintext: bool,
        key_provider: Arc<dyn HoldoutKeyProvider>,
    ) -> Self {
        Self {
            root,
            allow_plaintext,
            key_provider,
        }
    }

    fn holdout_dir(&self, holdout_ref: &str) -> PathBuf {
        self.root.join(holdout_ref)
    }
}

impl HoldoutProvider for RegistryHoldoutProvider {
    fn resolve(&self, holdout_ref: &str) -> Result<HoldoutDescriptor, Status> {
        validate_holdout_ref(holdout_ref)?;
        let manifest_path = self.holdout_dir(holdout_ref).join("manifest.json");
        if !manifest_path.exists() {
            return Err(Status::invalid_argument("unknown holdout_ref"));
        }
        let bytes = std::fs::read(&manifest_path)
            .map_err(|_| Status::internal("holdout manifest read failed"))?;
        let manifest: HoldoutManifestV1 = serde_json::from_slice(&bytes)
            .map_err(|_| Status::invalid_argument("invalid holdout manifest"))?;
        if manifest.schema_version != HOLDOUT_MANIFEST_SCHEMA_VERSION {
            return Err(Status::failed_precondition(
                "unsupported holdout manifest schema_version",
            ));
        }
        if manifest.created_at_unix == 0 {
            return Err(Status::invalid_argument(
                "invalid holdout manifest created_at_unix",
            ));
        }
        if let Some(key_id) = manifest.encryption_key_id.as_deref() {
            validate_required_str_field(key_id, "holdout manifest encryption_key_id", 128)?;
        }
        if manifest.len == 0 || manifest.len > 4096 {
            return Err(Status::invalid_argument("invalid holdout manifest len"));
        }
        let handle = decode_hex_hash32(&manifest.holdout_handle_hex, "holdout_handle_hex")?;
        let labels_hash = decode_hex_hash32(&manifest.labels_sha256_hex, "labels_sha256_hex")?;
        if let Some(v) = manifest.holdout_k_bits_budget {
            if !v.is_finite() || v < 0.0 {
                return Err(Status::invalid_argument(
                    "holdout_k_bits_budget must be finite and >= 0",
                ));
            }
        }
        if let Some(v) = manifest.holdout_access_credit_budget {
            if !v.is_finite() || v < 0.0 {
                return Err(Status::invalid_argument(
                    "holdout_access_credit_budget must be finite and >= 0",
                ));
            }
        }
        let holdout_pool_scope = manifest
            .holdout_pool_scope
            .as_deref()
            .map(HoldoutPoolScope::parse)
            .transpose()?;
        Ok(HoldoutDescriptor {
            holdout_ref: holdout_ref.to_string(),
            handle,
            len: manifest.len,
            labels_hash,
            encryption_key_id: manifest.encryption_key_id,
            holdout_k_bits_budget: manifest.holdout_k_bits_budget,
            holdout_access_credit_budget: manifest.holdout_access_credit_budget,
            holdout_pool_scope,
        })
    }

    fn load_labels(&self, descriptor: &HoldoutDescriptor) -> Result<Vec<u8>, Status> {
        let dir = self.holdout_dir(&descriptor.holdout_ref);
        let labels = if let Some(key_id) = descriptor.encryption_key_id.as_deref() {
            let labels_path = dir.join("labels.enc");
            verify_holdout_permissions(&dir, &labels_path)?;
            let payload = std::fs::read(&labels_path)
                .map_err(|_| Status::failed_precondition("holdout labels read failed"))?;
            let key = self
                .key_provider
                .key_for_id(key_id)
                .map_err(|_| Status::failed_precondition("holdout key lookup failed"))?;
            decrypt_holdout_labels(&payload, &key)
                .map_err(|_| Status::failed_precondition("holdout labels decrypt failed"))?
        } else {
            if !self.allow_plaintext {
                return Err(Status::failed_precondition(
                    "plaintext holdouts disabled; set --allow-plaintext-holdouts for development only",
                ));
            }
            let labels_path = dir.join("labels.bin");
            verify_holdout_permissions(&dir, &labels_path)?;
            std::fs::read(&labels_path)
                .map_err(|_| Status::failed_precondition("holdout labels read failed"))?
        };
        if labels.len() != descriptor.len {
            return Err(Status::failed_precondition("holdout label length mismatch"));
        }
        if sha256_bytes(&labels) != descriptor.labels_hash {
            return Err(Status::failed_precondition("holdout label hash mismatch"));
        }
        for &label in &labels {
            if label > 1 {
                return Err(Status::failed_precondition("holdout labels must be binary"));
            }
        }
        Ok(labels)
    }
}

#[derive(Debug)]
struct SyntheticHoldoutProvider;

fn verify_holdout_permissions(dir: &Path, file: &Path) -> Result<(), Status> {
    #[cfg(unix)]
    {
        let dir_meta = std::fs::metadata(dir)
            .map_err(|_| Status::failed_precondition("holdout directory metadata read failed"))?;
        if dir_meta.permissions().mode() & 0o777 != 0o700 {
            return Err(Status::failed_precondition(
                "holdout directory permissions must be 0700",
            ));
        }
        let file_meta = std::fs::metadata(file)
            .map_err(|_| Status::failed_precondition("holdout file metadata read failed"))?;
        if file_meta.permissions().mode() & 0o777 != 0o600 {
            return Err(Status::failed_precondition(
                "holdout label file permissions must be 0600",
            ));
        }
    }
    Ok(())
}

impl HoldoutProvider for SyntheticHoldoutProvider {
    fn resolve(&self, holdout_ref: &str) -> Result<HoldoutDescriptor, Status> {
        validate_holdout_ref(holdout_ref)?;
        let mut holdout_hasher = Sha256::new();
        holdout_hasher.update(holdout_ref.as_bytes());
        let mut holdout_handle_id = [0u8; 32];
        holdout_handle_id.copy_from_slice(&holdout_hasher.finalize());
        let len = 128_usize;
        let labels = derive_holdout_labels(holdout_handle_id, len)?;
        Ok(HoldoutDescriptor {
            holdout_ref: holdout_ref.to_string(),
            handle: holdout_handle_id,
            len,
            labels_hash: sha256_bytes(&labels),
            encryption_key_id: None,
            holdout_k_bits_budget: None,
            holdout_access_credit_budget: None,
            holdout_pool_scope: None,
        })
    }

    fn load_labels(&self, descriptor: &HoldoutDescriptor) -> Result<Vec<u8>, Status> {
        derive_holdout_labels(descriptor.handle, descriptor.len)
    }
}

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
    oracle_resolution_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FreezePreimage {
    artifacts_hash: [u8; 32],
    wasm_hash: [u8; 32],
    dependency_merkle_root: [u8; 32],
    holdout_ref_hash: [u8; 32],
    oracle_hash: [u8; 32],
    trial_commitment_hash: [u8; 32],
    sealed_preimage_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TopicManifestForHash {
    claim_name: String,
    epoch_config_ref: String,
    output_schema_id: String,
    holdout_ref: String,
    holdout_handle_hex: String,
    nullspec_id_hex: Option<String>,
    wasm_code_hash_hex: String,
    oracle_num_symbols: u32,
    epoch_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TopicOracleReceipt {
    claim_manifest_hash: [u8; 32],
    semantic_hash: [u8; 32],
    model_id: String,
    timestamp_unix: u64,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    claim_id: [u8; 32],
    topic_id: [u8; 32],
    holdout_handle_id: [u8; 32],
    holdout_ref: String,
    #[serde(default)]
    epoch_config_ref: String,
    #[serde(default)]
    holdout_len: u64,
    #[serde(default)]
    metadata_locked: bool,
    claim_name: String,
    #[serde(default)]
    oracle_id: String,
    #[serde(default)]
    nullspec_id: String,
    output_schema_id: String,
    phys_hir_hash: [u8; 32],
    #[serde(default)]
    semantic_hash: [u8; 32],
    #[serde(default)]
    topic_oracle_receipt: Option<TopicOracleReceipt>,
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
    #[serde(default)]
    dlc_fuel_accumulated: u64,
    #[serde(default)]
    pln_config: Option<ClaimPlnConfig>,
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
    #[serde(default)]
    owner_principal_id: String,
    #[serde(default)]
    created_at_unix_ms: u64,
    #[serde(default)]
    trial_assignment: Option<TrialAssignment>,
    #[serde(default)]
    trial_commitment_hash: [u8; 32],
    #[serde(default)]
    execution_nonce: u64,
    #[serde(default)]
    holdout_pool_scope: HoldoutPoolScope,
    #[serde(default)]
    reserved_k_bits: f64,
    #[serde(default)]
    reserved_access_credit: f64,
    #[serde(default)]
    reserved_expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpochRuntimeConfigFile {
    epoch_size: u64,
    #[serde(default)]
    pln_constant_cost: Option<u64>,
    #[serde(default)]
    pln_target_fuel: Option<u64>,
    #[serde(default)]
    pln_max_fuel: Option<u64>,
    #[serde(default)]
    pln_fast_enabled: Option<bool>,
    #[serde(default)]
    pln_heavy_enabled: Option<bool>,
    #[serde(default)]
    pln: Option<PlnRuntimeConfigFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PlnRuntimeConfigFile {
    target_fuel: u64,
    max_fuel: u64,
    #[serde(default)]
    lanes: PlnLaneConfigFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlnLaneConfigFile {
    #[serde(default = "bool_true")]
    fast: bool,
    #[serde(default = "bool_true")]
    heavy: bool,
}

impl Default for PlnLaneConfigFile {
    fn default() -> Self {
        Self {
            fast: true,
            heavy: true,
        }
    }
}

#[derive(Debug, Clone)]
struct ClaimPlnConfig {
    target_fuel: u64,
    max_fuel: u64,
}

impl<'de> Deserialize<'de> for ClaimPlnConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            target_fuel: u64,
            max_fuel: u64,
        }
        let raw = Raw::deserialize(deserializer)?;

        Ok(Self {
            target_fuel: raw.target_fuel,
            max_fuel: raw.max_fuel,
        })
    }
}

impl Serialize for ClaimPlnConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Raw {
            target_fuel: u64,
            max_fuel: u64,
        }
        Raw {
            target_fuel: self.target_fuel,
            max_fuel: self.max_fuel,
        }
        .serialize(serializer)
    }
}

fn bool_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct HoldoutPoolKey {
    holdout_id: [u8; 32],
    principal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HoldoutBudgetPool {
    holdout_pool_key: HoldoutPoolKey,
    k_bits_budget: f64,
    access_credit_budget: f64,
    k_bits_spent: f64,
    access_credit_spent: f64,
    #[serde(default)]
    reserved_k_bits: f64,
    #[serde(default)]
    reserved_access_credit: f64,
    frozen: bool,
}

#[derive(Debug, Clone)]
struct LaneConfig {
    aspec_policy: AspecPolicy,
    oracle_resolution: OracleResolution,
    k_bits_budget: f64,
    access_credit_budget: f64,
}

impl PlnLaneConfigFile {
    fn supports_lane(&self, lane: Lane) -> bool {
        match lane {
            Lane::Fast => self.fast,
            Lane::Heavy => self.heavy,
        }
    }
}

impl LaneConfig {
    fn for_lane(lane: Lane, num_symbols: u32, access_credit: f64) -> Result<Self, Status> {
        let mut policy = AspecPolicy::default();
        let (oracle_delta_sigma, k_bits_budget) = match lane {
            Lane::Fast => (0.0, access_credit),
            Lane::Heavy => {
                policy.lane = AspecLane::LowAssurance;
                policy.float_policy = FloatPolicy::Allow;
                policy.max_loop_bound = 10_000;
                policy.max_output_bytes = structured_claims::max_bytes_upper_bound();
                (0.25, access_credit)
            }
        };
        Ok(Self {
            aspec_policy: policy,
            oracle_resolution: OracleResolution::new(num_symbols, oracle_delta_sigma)
                .map_err(|_| Status::invalid_argument("oracle_num_symbols must be >= 2"))?,
            k_bits_budget,
            access_credit_budget: access_credit,
        })
    }
}

impl HoldoutBudgetPool {
    fn new(
        holdout_pool_key: HoldoutPoolKey,
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
            holdout_pool_key,
            k_bits_budget,
            access_credit_budget,
            k_bits_spent: 0.0,
            access_credit_spent: 0.0,
            reserved_k_bits: 0.0,
            reserved_access_credit: 0.0,
            frozen: false,
        })
    }

    fn reserve(&mut self, k_bits: f64, access_credit: f64) -> Result<(), Status> {
        if self.frozen {
            return Err(Status::failed_precondition("holdout pool exhausted"));
        }
        if !k_bits.is_finite() || !access_credit.is_finite() || k_bits < 0.0 || access_credit < 0.0
        {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        let next_reserved_k = self.reserved_k_bits + k_bits;
        let next_reserved_access = self.reserved_access_credit + access_credit;
        if !next_reserved_k.is_finite() || !next_reserved_access.is_finite() {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        let next_k = self.k_bits_spent + next_reserved_k;
        let next_access = self.access_credit_spent + next_reserved_access;
        if !next_k.is_finite() || !next_access.is_finite() {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        if next_k > self.k_bits_budget + f64::EPSILON
            || next_access > self.access_credit_budget + f64::EPSILON
        {
            self.frozen = true;
            return Err(Status::failed_precondition("holdout pool exhausted"));
        }
        self.reserved_k_bits = next_reserved_k;
        self.reserved_access_credit = next_reserved_access;
        Ok(())
    }

    fn settle_reserved(
        &mut self,
        reserved_k_bits: f64,
        reserved_access_credit: f64,
        actual_k_bits: f64,
        actual_access_credit: f64,
    ) -> Result<(), Status> {
        if !reserved_k_bits.is_finite()
            || !reserved_access_credit.is_finite()
            || !actual_k_bits.is_finite()
            || !actual_access_credit.is_finite()
            || reserved_k_bits < 0.0
            || reserved_access_credit < 0.0
            || actual_k_bits < 0.0
            || actual_access_credit < 0.0
            || actual_k_bits > reserved_k_bits + f64::EPSILON
            || actual_access_credit > reserved_access_credit + f64::EPSILON
        {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        if reserved_k_bits > self.reserved_k_bits + f64::EPSILON
            || reserved_access_credit > self.reserved_access_credit + f64::EPSILON
        {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        self.reserved_k_bits -= reserved_k_bits;
        self.reserved_access_credit -= reserved_access_credit;
        self.charge(actual_k_bits, actual_access_credit)
    }

    fn release_reserved(&mut self, k_bits: f64, access_credit: f64) -> Result<(), Status> {
        if !k_bits.is_finite() || !access_credit.is_finite() || k_bits < 0.0 || access_credit < 0.0
        {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        if k_bits > self.reserved_k_bits + f64::EPSILON
            || access_credit > self.reserved_access_credit + f64::EPSILON
        {
            return Err(Status::invalid_argument("invalid holdout pool charge"));
        }
        self.reserved_k_bits -= k_bits;
        self.reserved_access_credit -= access_credit;
        Ok(())
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
        // CREDIT-EXTERNAL: enforcement point.
        // Caller must have been pre-authorized by operator
        // credit service. See docs/CREDIT_AND_ADMISSION.md
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
        // CREDIT-EXTERNAL: enforcement point.
        // Caller must have been pre-authorized by operator
        // credit service. See docs/CREDIT_AND_ADMISSION.md
        self.access_credit_spent = next_access;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorRecord {
    schema_version: u32,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: Option<String>,
    calibration_epoch: Option<u64>,
    disjointness_attestation: Option<DisjointnessAttestation>,
    nonoverlap_proof_uri: Option<String>,
    updated_at_epoch: u64,
    key_id: String,
    signature_ed25519: String,
}

#[derive(Debug, Clone, Serialize)]
struct OracleOperatorRecordSigningPayload<'a> {
    oracle_id: &'a str,
    schema_version: u32,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: &'a str,
    calibration_epoch: Option<u64>,
    disjointness_attestation: Option<&'a DisjointnessAttestation>,
    nonoverlap_proof_uri: Option<&'a str>,
    updated_at_epoch: u64,
    key_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DisjointnessAttestation {
    statement_type: String,
    scope: String,
    proof_sha256_hex: String,
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

#[derive(Debug, Clone, Serialize)]
struct EpochControlSigningPayload<'a> {
    forced_epoch: u64,
    updated_at_epoch: u64,
    key_id: &'a str,
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
    holdout_pools: Vec<(HoldoutPoolKey, HoldoutBudgetPool)>,
    canary_states: Vec<(String, CanaryState)>,
    #[serde(default)]
    trial_allocator_state: Option<PersistedTrialAllocatorState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum PendingMutation {
    Execute {
        claim_id: [u8; 32],
        state: ClaimState,
        decision: i32,
        capsule_hash: [u8; 32],
        capsule_bytes: Vec<u8>,
        etl_index: Option<u64>,
    },
    Revoke {
        claim_id: [u8; 32],
        capsule_hash: [u8; 32],
        reason: String,
        timestamp_unix: u64,
        tainted_claim_ids: Vec<[u8; 32]>,
        etl_applied: bool,
    },
}

impl PendingMutation {
    fn claim_id(&self) -> [u8; 32] {
        match self {
            Self::Execute { claim_id, .. } | Self::Revoke { claim_id, .. } => *claim_id,
        }
    }
}

type RevocationSubscriber = mpsc::Sender<pb::WatchRevocationsResponse>;

const ORACLE_EXPIRED_REASON_CODE: u32 = 9202;
const ORACLE_TTL_ESCALATED_REASON_CODE: u32 = 9203;
const MAGNITUDE_ENVELOPE_REASON_CODE: u32 = 9205;
const LEDGER_NUMERIC_GUARD_REASON_CODE: u32 = 9206;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdempotencyRecord {
    request_hash: [u8; 32],
    status_code: u32,
    status_message: Option<String>,
    response_bytes: Vec<u8>,
    created_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
enum IdempotencyEntry {
    InFlight {
        expires_at: Instant,
    },
    Ready {
        expires_at: Instant,
        record: IdempotencyRecord,
    },
}

#[derive(Debug, Clone)]
struct IdempotencyContext {
    key: (String, String, String),
    request_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreditError {
    InvalidAmount,
    UnknownPrincipal(String),
    Insufficient {
        principal_id: String,
        requested: f64,
        available: f64,
    },
    Io(String),
    Parse(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreditBackend {
    None,
    ConfigFile(PathBuf),
    // Grpc variant: roadmap
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreditBalancesFile {
    principals: HashMap<String, CreditBalanceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreditBalanceEntry {
    balance: f64,
    epoch_id: String,
}

impl CreditBackend {
    pub fn from_env(state_dir: &Path) -> Self {
        match std::env::var("EVIDENCEOS_CREDIT_BACKEND")
            .unwrap_or_else(|_| "none".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "config_file" => Self::ConfigFile(state_dir.join("credit_balances.json")),
            _ => Self::None,
        }
    }

    pub fn check_and_deduct(
        &self,
        principal_id: &str,
        _claim_id: &str,
        amount: f64,
    ) -> Result<f64, CreditError> {
        if !amount.is_finite() || amount < 0.0 {
            return Err(CreditError::InvalidAmount);
        }
        match self {
            Self::None => Ok(f64::MAX),
            Self::ConfigFile(path) => {
                let mut raw = Vec::new();
                File::open(path)
                    .and_then(|mut f| f.read_to_end(&mut raw))
                    .map_err(|e| CreditError::Io(e.to_string()))?;
                let mut balances: CreditBalancesFile =
                    serde_json::from_slice(&raw).map_err(|e| CreditError::Parse(e.to_string()))?;
                let entry = balances
                    .principals
                    .get_mut(principal_id)
                    .ok_or_else(|| CreditError::UnknownPrincipal(principal_id.to_string()))?;
                if !entry.balance.is_finite() || entry.balance < amount {
                    return Err(CreditError::Insufficient {
                        principal_id: principal_id.to_string(),
                        requested: amount,
                        available: entry.balance,
                    });
                }
                entry.balance -= amount;
                let updated_balance = entry.balance;
                let encoded = serde_json::to_vec_pretty(&balances)
                    .map_err(|e| CreditError::Parse(e.to_string()))?;
                let tmp_path = path.with_extension("tmp");
                let mut tmp =
                    File::create(&tmp_path).map_err(|e| CreditError::Io(e.to_string()))?;
                tmp.write_all(&encoded)
                    .and_then(|_| tmp.sync_all())
                    .map_err(|e| CreditError::Io(e.to_string()))?;
                std::fs::rename(&tmp_path, path).map_err(|e| CreditError::Io(e.to_string()))?;
                if let Some(parent) = path.parent() {
                    sync_directory(parent).map_err(|e| CreditError::Io(e.message().to_string()))?;
                }
                Ok(updated_balance)
            }
        }
    }
}

#[derive(Debug)]
struct ServerState {
    claims: Mutex<HashMap<[u8; 32], Claim>>,
    topic_pools: Mutex<HashMap<[u8; 32], TopicBudgetPool>>,
    holdout_pools: Mutex<HashMap<HoldoutPoolKey, HoldoutBudgetPool>>,
    canary_states: Mutex<HashMap<String, CanaryState>>,
    etl: Mutex<Etl>,
    data_path: PathBuf,
    revocations: Mutex<Vec<([u8; 32], u64, String)>>,
    lock_file: File,
    active_key_id: [u8; 32],
    keyring: HashMap<[u8; 32], SigningKey>,
    revocation_subscribers: Mutex<Vec<RevocationSubscriber>>,
    operator_config: Mutex<OperatorRuntimeConfig>,
    account_store: Mutex<AccountStore>,
    nullspec_registry_state: Mutex<NullSpecRegistryState>,
    idempotency: Mutex<HashMap<(String, String, String), IdempotencyEntry>>,
}

#[derive(Debug)]
struct NullSpecRegistryState {
    registry_dir: PathBuf,
    authority_keys_dir: PathBuf,
    keyring: Arc<NullSpecAuthorityKeyring>,
    registry: Arc<NullSpecRegistry>,
    healthy: bool,
    last_reload_attempt: Instant,
    reload_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct NullSpecRegistryConfig {
    pub registry_dir: PathBuf,
    pub authority_keys_dir: PathBuf,
    pub reload_interval: Duration,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.data_path.join("kernel.lock"));
        let _ = self.lock_file.metadata();
    }
}

#[derive(Clone)]
pub struct EvidenceOsService {
    state: Arc<ServerState>,
    insecure_v1_enabled: bool,
    holdout_provider: Arc<dyn HoldoutProvider>,
    dependence_tax_multiplier: f64,
    oracle_ttl_policy: OracleTtlPolicy,
    oracle_ttl_escalation_tax_multiplier: f64,
    telemetry: Arc<Telemetry>,
    probe_detector: Arc<Mutex<ProbeDetector>>,
    policy_oracles: Arc<Vec<PolicyOracleEngine>>,
    canary_config: CanaryConfig,
    offline_settlement_ingest: bool,
    require_disjointness_attestation: bool,
    enforce_operator_provenance: bool,
    tee_attestor: Option<Arc<dyn TeeAttestor>>,
    domain_safety: DomainSafetyConfig,
    trial_router: Arc<TrialRouter>,
    trial_config_hash: Option<[u8; 32]>,
    admission_provider: Arc<dyn AdmissionProvider>,
    credit_backend: CreditBackend,
    access_credit_pricing: AccessCreditPricing,
    operator_principals: Vec<String>,
    default_holdout_k_bits_budget: f64,
    default_holdout_access_credit_budget: f64,
    holdout_pool_scope: HoldoutPoolScope,
    #[allow(dead_code)]
    strict_pln: StrictPlnConfig,
    reservation_ttl_ms: u64,
    reservation_sweep_interval: Duration,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StrictPlnConfig {
    enabled: bool,
    fast_execute_floor_ms: u64,
    heavy_execute_floor_ms: u64,
}

impl StrictPlnConfig {
    fn from_env() -> Self {
        Self {
            enabled: env_flag("EVIDENCEOS_STRICT_PLN", false),
            fast_execute_floor_ms: std::env::var("EVIDENCEOS_STRICT_PLN_FAST_EXECUTE_FLOOR_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            heavy_execute_floor_ms: std::env::var("EVIDENCEOS_STRICT_PLN_HEAVY_EXECUTE_FLOOR_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }
    }

    #[allow(dead_code)]
    fn execute_floor_ms(&self, lane: Lane) -> u64 {
        if !self.enabled {
            return 0;
        }
        match lane {
            Lane::Fast => self.fast_execute_floor_ms,
            Lane::Heavy => self.heavy_execute_floor_ms,
        }
    }
}

#[derive(Debug, Clone)]
struct DomainSafetyConfig {
    require_structured_outputs: bool,
    require_structured_output_domains: HashSet<String>,
    deny_free_text_outputs: bool,
    force_heavy_lane_on_domain: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainSafetyDecision {
    Allow,
    ForceHeavyLane,
    Reject,
}

impl DomainSafetyConfig {
    fn from_env(production_mode: bool) -> Self {
        Self {
            require_structured_outputs: env_flag("EVIDENCEOS_REQUIRE_STRUCTURED_OUTPUTS", true),
            require_structured_output_domains: env_domain_set(
                "EVIDENCEOS_REQUIRE_STRUCTURED_OUTPUTS_DOMAINS",
                "CBRN",
            ),
            deny_free_text_outputs: env_flag("EVIDENCEOS_DENY_FREE_TEXT_OUTPUTS", production_mode),
            force_heavy_lane_on_domain: env_domain_set(
                "EVIDENCEOS_FORCE_HEAVY_LANE_ON_DOMAIN",
                "CBRN",
            ),
        }
    }

    fn decision_for(
        &self,
        domain: &str,
        output_schema_id: &str,
        lane: Lane,
    ) -> DomainSafetyDecision {
        let normalized_domain = domain.trim().to_ascii_uppercase();
        if self.deny_free_text_outputs && output_schema_id == structured_claims::LEGACY_SCHEMA_ID {
            return DomainSafetyDecision::Reject;
        }
        if self.require_structured_outputs
            && self
                .require_structured_output_domains
                .contains(&normalized_domain)
            && output_schema_id != structured_claims::SCHEMA_ID
        {
            return DomainSafetyDecision::Reject;
        }
        if self.force_heavy_lane_on_domain.contains(&normalized_domain) && lane != Lane::Heavy {
            return DomainSafetyDecision::ForceHeavyLane;
        }
        DomainSafetyDecision::Allow
    }
}

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn generate_trial_nonce() -> Result<[u8; TRIAL_NONCE_LEN], Status> {
    let mut nonce = [0_u8; TRIAL_NONCE_LEN];
    getrandom(&mut nonce).map_err(|_| Status::internal("trial nonce generation failed"))?;
    Ok(nonce)
}

fn env_domain_set(name: &str, default: &str) -> HashSet<String> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_ascii_uppercase())
        .collect()
}

#[allow(dead_code)]
fn strict_pln_padding_duration(elapsed: Duration, floor_ms: u64) -> Option<Duration> {
    if floor_ms == 0 {
        return None;
    }
    let floor = Duration::from_millis(floor_ms);
    (elapsed < floor).then_some(floor - elapsed)
}

fn validate_trial_harness_variation(
    enabled: bool,
    arm_count: u16,
    interventions: &HashMap<u16, Arc<dyn crate::trial::EpistemicIntervention>>,
) -> Result<(), Status> {
    if !enabled || arm_count <= 1 {
        return Ok(());
    }

    let unique_hashes = interventions
        .values()
        .map(|intervention| hash_arm_parameters(&intervention.arm_parameters()))
        .collect::<Result<HashSet<[u8; 32]>, Status>>()?;

    if unique_hashes.len() < 2 {
        return Err(Status::failed_precondition(
            "trial harness enabled with multiple arms requires at least 2 distinct arm_parameters_hash values",
        ));
    }

    Ok(())
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
        let nullspec_config = NullSpecRegistryConfig {
            registry_dir: PathBuf::from(data_dir).join("nullspec-registry"),
            authority_keys_dir: PathBuf::from(data_dir).join("trusted-nullspec-keys"),
            reload_interval: Duration::from_secs(30),
        };
        Self::build_with_options_and_nullspec(data_dir, durable_etl, telemetry, nullspec_config)
    }

    pub fn build_with_options_and_nullspec(
        data_dir: &str,
        durable_etl: bool,
        telemetry: Arc<Telemetry>,
        nullspec_config: NullSpecRegistryConfig,
    ) -> Result<Self, Status> {
        let root = PathBuf::from(data_dir);
        std::fs::create_dir_all(&root).map_err(|_| Status::internal("mkdir failed"))?;

        let lock_path = root.join("kernel.lock");
        let lock_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
            .map_err(|_| Status::failed_precondition("another writer already holds kernel lock"))?;

        let state_file = root.join(STATE_FILE_NAME);
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

        let require_disjointness_attestation =
            std::env::var("EVIDENCEOS_REQUIRE_DISJOINTNESS_ATTESTATION")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true);
        let production_mode = std::env::var("EVIDENCEOS_PRODUCTION_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let enforce_operator_provenance = production_mode && require_disjointness_attestation;
        let domain_safety = DomainSafetyConfig::from_env(production_mode);

        let operator_config = load_operator_runtime_config(&root, enforce_operator_provenance)?;

        let (nullspec_keyring, nullspec_registry, nullspec_healthy) =
            match NullSpecAuthorityKeyring::load_from_dir(&nullspec_config.authority_keys_dir) {
                Ok(keyring) => match NullSpecRegistry::load_from_dir(
                    &nullspec_config.registry_dir,
                    &keyring,
                    false,
                ) {
                    Ok(registry) => (keyring, registry, true),
                    Err(_) => {
                        tracing::error!(
                            event = "nullspec_registry_startup_load_failed",
                            registry_dir = %nullspec_config.registry_dir.display(),
                            authority_keys_dir = %nullspec_config.authority_keys_dir.display(),
                            "failed to load nullspec registry at startup; registry marked unhealthy"
                        );
                        (keyring, NullSpecRegistry::default(), false)
                    }
                },
                Err(_) => {
                    tracing::error!(
                        event = "nullspec_registry_startup_keyring_load_failed",
                        authority_keys_dir = %nullspec_config.authority_keys_dir.display(),
                        "failed to load nullspec keyring at startup; registry marked unhealthy"
                    );
                    (
                        NullSpecAuthorityKeyring::default(),
                        NullSpecRegistry::default(),
                        false,
                    )
                }
            };

        let holdouts_root = root.join("holdouts");
        let admission_provider: Arc<dyn AdmissionProvider> =
            // CREDIT-EXTERNAL: enforcement point.
            // Caller must have been pre-authorized by operator
            // credit service. See docs/CREDIT_AND_ADMISSION.md
            Arc::new(StaticAdmissionProvider::from_env());
        let credit_backend = CreditBackend::from_env(&root);
        if production_mode && matches!(credit_backend, CreditBackend::None) {
            tracing::warn!(
                "CREDIT_BACKEND=none in production mode. Credit enforcement is disabled."
            );
        }
        let default_credit_limit = admission_provider.max_credit("anonymous");
        let account_store = AccountStore::open(&root, default_credit_limit)?;

        let state = Arc::new(ServerState {
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
            account_store: Mutex::new(account_store),
            nullspec_registry_state: Mutex::new(NullSpecRegistryState {
                registry_dir: nullspec_config.registry_dir,
                authority_keys_dir: nullspec_config.authority_keys_dir,
                keyring: Arc::new(nullspec_keyring),
                registry: Arc::new(nullspec_registry),
                healthy: nullspec_healthy,
                last_reload_attempt: Instant::now(),
                reload_interval: nullspec_config.reload_interval,
            }),
            idempotency: Mutex::new(HashMap::new()),
        });
        recover_pending_mutations(&state)?;
        load_idempotency_records(&state)?;
        persist_all(&state)?;
        let insecure_v1_enabled = std::env::var("EVIDENCEOS_ENABLE_INSECURE_V1")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let insecure_synthetic_holdout = std::env::var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let holdout_provider: Arc<dyn HoldoutProvider> = if insecure_synthetic_holdout {
            Arc::new(SyntheticHoldoutProvider)
        } else {
            let allow_plaintext_holdouts = std::env::var("EVIDENCEOS_ALLOW_PLAINTEXT_HOLDOUTS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            Arc::new(RegistryHoldoutProvider::new(
                holdouts_root,
                allow_plaintext_holdouts,
                Arc::new(EnvKeyProvider::new()),
            ))
        };
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

        let tee_attestor = attestor_from_env()
            .map_err(|e| {
                tracing::error!(error=?e, "tee backend configuration error");
                public_status(Code::InvalidArgument, PublicErrorCode::InvalidInput)
            })?
            .map(Arc::<dyn TeeAttestor>::from);
        if tee_attestor
            .as_deref()
            .map(|a| a.backend_name() == "noop")
            .unwrap_or(false)
        {
            tracing::warn!(
                event = "tee_noop_enabled",
                "NOOP TEE attestation backend enabled; this is development-only and unsafe for production"
            );
        }

        let operator_principals = std::env::var("EVIDENCEOS_OPERATOR_PRINCIPALS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec!["anonymous".to_string()]);
        let default_holdout_k_bits_budget =
            std::env::var("EVIDENCEOS_DEFAULT_HOLDOUT_K_BITS_BUDGET")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(1024.0);
        Self::validate_budget_value(
            default_holdout_k_bits_budget,
            "default_holdout_k_bits_budget",
        )?;
        let default_holdout_access_credit_budget =
            std::env::var("EVIDENCEOS_DEFAULT_HOLDOUT_ACCESS_CREDIT_BUDGET")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(1024.0);
        Self::validate_budget_value(
            default_holdout_access_credit_budget,
            "default_holdout_access_credit_budget",
        )?;
        let holdout_pool_scope = std::env::var("EVIDENCEOS_HOLDOUT_POOL_SCOPE")
            .ok()
            .as_deref()
            .map(HoldoutPoolScope::parse)
            .transpose()?
            .unwrap_or(HoldoutPoolScope::Global);
        let reservation_ttl_ms = std::env::var("EVIDENCEOS_RESERVATION_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(600_000);
        if reservation_ttl_ms == 0 {
            return Err(Status::invalid_argument("reservation_ttl_ms must be > 0"));
        }
        let reservation_sweep_interval_secs =
            std::env::var("EVIDENCEOS_RESERVATION_SWEEP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);
        if reservation_sweep_interval_secs == 0 {
            return Err(Status::invalid_argument(
                "reservation_sweep_interval_secs must be > 0",
            ));
        }
        let reservation_sweep_interval = Duration::from_secs(reservation_sweep_interval_secs);

        let trial_harness_enabled = std::env::var("EVIDENCEOS_TRIAL_HARNESS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let trial_config_path = std::env::var("EVIDENCEOS_TRIAL_ARMS_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config/trial_arms.json"));
        let loaded_trial_config = if trial_config_path.exists() {
            Some(load_trial_arms_config(&trial_config_path)?)
        } else {
            let fallback = default_trial_arms_config();
            let canonical = evidenceos_core::capsule::canonical_json(&fallback)
                .map_err(|_| Status::internal("trial config canonicalization failed"))?;
            let mut h = Sha256::new();
            h.update(canonical);
            let digest = h.finalize();
            let mut config_hash = [0u8; 32];
            config_hash.copy_from_slice(&digest);
            Some(crate::trial::LoadedTrialConfig {
                config: fallback,
                config_hash,
            })
        };
        let persisted_trial_allocator_state = persisted.trial_allocator_state.clone();

        let (trial_router, trial_config_hash) = if let Some(loaded) = loaded_trial_config {
            let arm_count = loaded.config.arms.len() as u16;
            let blocked = matches!(loaded.config.assignment_mode, AssignmentMode::Blocked);
            let block_size = loaded.config.block_size.unwrap_or(usize::from(arm_count));
            let interventions = interventions_from_trial_config(&loaded.config);
            validate_trial_harness_variation(trial_harness_enabled, arm_count, &interventions)?;
            tracing::info!(
                event = "trial_config_loaded",
                trial_config_path = %trial_config_path.display(),
                trial_config_hash_hex = %hex::encode(loaded.config_hash),
                arm_count,
                assignment_mode = if blocked { "blocked" } else { "hashed" },
                stratify = loaded.config.stratify,
                block_size,
                "loaded epistemic trial config"
            );
            (
                Arc::new(TrialRouter::with_options(
                    arm_count,
                    blocked,
                    loaded.config.stratify,
                    block_size,
                    interventions,
                )?),
                Some(loaded.config_hash),
            )
        } else {
            (Arc::new(TrialRouter::new(1, false, HashMap::new())?), None)
        };

        if let Some(allocator_state) = persisted_trial_allocator_state.as_ref() {
            trial_router.restore_blocked_state(allocator_state)?;
        }

        telemetry.set_trial_harness_state(
            trial_harness_enabled,
            trial_config_hash.map(hex::encode),
            trial_router.arm_count(),
        );

        Ok(Self {
            state,
            insecure_v1_enabled,
            holdout_provider,
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
            require_disjointness_attestation,
            enforce_operator_provenance,
            tee_attestor,
            domain_safety,
            trial_router,
            trial_config_hash,
            admission_provider,
            credit_backend,
            access_credit_pricing: AccessCreditPricing::from_env(),
            operator_principals,
            default_holdout_k_bits_budget,
            default_holdout_access_credit_budget,
            holdout_pool_scope,
            strict_pln: StrictPlnConfig::from_env(),
            reservation_ttl_ms,
            reservation_sweep_interval,
        })
    }

    fn domain_for_policy(
        &self,
        claim_name: &str,
        holdout_ref: &str,
        nullspec_id_hex: &str,
    ) -> Result<String, Status> {
        let nullspec_store = NullSpecStore::open(&self.state.data_path)
            .map_err(|_| Status::internal("nullspec store init failed"))?;
        let active_id = if nullspec_id_hex.is_empty() {
            nullspec_store
                .active_for(claim_name, holdout_ref)
                .map_err(|_| Status::internal("nullspec mapping read failed"))?
        } else {
            let decoded = hex::decode(nullspec_id_hex)
                .map_err(|_| Status::invalid_argument("invalid nullspec_id hex"))?;
            Some(
                decoded
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid nullspec_id length"))?,
            )
        };
        if let Some(active_id) = active_id {
            let contract = nullspec_store
                .get(&active_id)
                .map_err(|_| Status::failed_precondition("active nullspec not found"))?;
            return Ok(contract.oracle_id);
        }
        Ok("UNSPECIFIED".to_string())
    }

    fn synthetic_holdout_enabled(&self) -> bool {
        std::env::var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn protocol_feature_flags(&self) -> pb::FeatureFlags {
        let tls_enabled = std::env::var("EVIDENCEOS_TLS_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mtls_enabled = std::env::var("EVIDENCEOS_MTLS_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let oracle_registry_enabled = !self.policy_oracles.is_empty();
        pb::FeatureFlags {
            tls_enabled,
            mtls_enabled,
            oracle_registry_enabled,
            insecure_v1_enabled: self.insecure_v1_enabled,
            synthetic_holdout_enabled: self.synthetic_holdout_enabled(),
            offline_settlement_ingest_enabled: self.offline_settlement_ingest,
            disjointness_attestation_required: self.require_disjointness_attestation,
        }
    }

    pub fn reload_nullspec_registry(&self) -> Result<(), Status> {
        let mut state = self.state.nullspec_registry_state.lock();
        let keyring = NullSpecAuthorityKeyring::load_from_dir(&state.authority_keys_dir)
            .map_err(|_| Status::failed_precondition("nullspec keyring load failed"))?;
        let registry = NullSpecRegistry::load_from_dir(&state.registry_dir, &keyring, false)
            .map_err(|_| Status::failed_precondition("nullspec registry load failed"))?;
        state.keyring = Arc::new(keyring);
        state.registry = Arc::new(registry);
        state.healthy = true;
        state.last_reload_attempt = Instant::now();
        tracing::info!(
            event = "nullspec_registry_reload",
            registry_dir = %state.registry_dir.display(),
            authority_keys_dir = %state.authority_keys_dir.display(),
            "reloaded nullspec registry and authority keyring"
        );
        Ok(())
    }

    fn ensure_nullspec_registry_fresh(&self) -> Result<Arc<NullSpecRegistry>, Status> {
        let should_attempt_reload = {
            let state = self.state.nullspec_registry_state.lock();
            state.last_reload_attempt.elapsed() >= state.reload_interval
        };

        if should_attempt_reload {
            if let Err(err) = self.reload_nullspec_registry() {
                let mut state = self.state.nullspec_registry_state.lock();
                state.healthy = false;
                state.last_reload_attempt = Instant::now();
                tracing::error!(event = "nullspec_registry_reload_failed", error = %err, "failed to reload nullspec registry; failing closed");
            }
        }

        let state = self.state.nullspec_registry_state.lock();
        if !state.healthy {
            return Err(Status::failed_precondition(
                "nullspec registry reload failed; registry marked unhealthy",
            ));
        }
        tracing::debug!(
            event = "nullspec_registry_cache_hit",
            authority_keys = state.keyring.keys.len(),
            "using cached nullspec registry"
        );
        Ok(state.registry.clone())
    }

    fn populate_tee_attestation(
        &self,
        capsule: &mut ClaimCapsule,
        measurement: &[u8],
    ) -> Result<(), Status> {
        let Some(attestor) = &self.tee_attestor else {
            return Ok(());
        };
        let report = collect_attestation(attestor.as_ref(), measurement)
            .map_err(|_| Status::failed_precondition("tee attestation failed"))?;
        capsule.environment_attestations.tee_backend_name = Some(report.backend_name);
        capsule.environment_attestations.tee_measurement_hex = Some(report.measurement_hex);
        capsule.environment_attestations.tee_attestation_blob_b64 =
            Some(report.attestation_blob_b64);
        Ok(())
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
            let etl_index = record.proposal.etl_index;
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
            persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        }
        Ok(applied)
    }

    pub fn reload_operator_runtime_config(&self) -> Result<(), Status> {
        let next = match load_operator_runtime_config(
            &self.state.data_path,
            self.enforce_operator_provenance,
        ) {
            Ok(cfg) => cfg,
            Err(status) => {
                tracing::error!(
                    event="config_reload_rejected",
                    severity="high",
                    error=%status,
                    "rejected operator runtime config reload; retaining last-known-good config"
                );
                return Err(status);
            }
        };
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

    pub fn reservation_sweep_interval(&self) -> Duration {
        self.reservation_sweep_interval
    }

    pub fn sweep_expired_reservations(&self) -> Result<usize, Status> {
        let now_ms = current_time_unix_ms()?;
        let mut expired_claims: Vec<[u8; 32]> = Vec::new();
        {
            let claims = self.state.claims.lock();
            for (claim_id, claim) in claims.iter() {
                if claim.reserved_k_bits <= 0.0 && claim.reserved_access_credit <= 0.0 {
                    continue;
                }
                if claim.reserved_expires_at_unix_ms == 0
                    || now_ms <= claim.reserved_expires_at_unix_ms
                {
                    continue;
                }
                if claim.state != ClaimState::Uncommitted && claim.state != ClaimState::Frozen {
                    continue;
                }
                expired_claims.push(*claim_id);
            }
        }

        if expired_claims.is_empty() {
            return Ok(0);
        }

        let mut topic_pools = self.state.topic_pools.lock();
        let mut holdout_pools = self.state.holdout_pools.lock();
        let mut claims = self.state.claims.lock();
        let mut expired_count = 0usize;

        for claim_id in expired_claims {
            let Some(claim) = claims.get_mut(&claim_id) else {
                continue;
            };
            if claim.reserved_k_bits <= 0.0 && claim.reserved_access_credit <= 0.0 {
                continue;
            }
            if claim.reserved_expires_at_unix_ms == 0 || now_ms <= claim.reserved_expires_at_unix_ms
            {
                continue;
            }
            if claim.state != ClaimState::Uncommitted && claim.state != ClaimState::Frozen {
                continue;
            }

            let released_k_bits = claim.reserved_k_bits;
            let released_access_credit = claim.reserved_access_credit;

            let topic_pool = topic_pools
                .get_mut(&claim.topic_id)
                .ok_or_else(|| Status::failed_precondition("missing topic budget pool"))?;
            topic_pool
                .release_reserved(released_k_bits, released_access_credit)
                .map_err(|_| Status::internal("failed to release topic reservation"))?;

            let holdout_keys = self.holdout_pool_keys(
                claim.holdout_handle_id,
                &claim.owner_principal_id,
                claim.holdout_pool_scope,
            );
            for holdout_key in holdout_keys {
                let holdout_pool = holdout_pools
                    .get_mut(&holdout_key)
                    .ok_or_else(|| Status::failed_precondition("missing holdout budget pool"))?;
                holdout_pool
                    .release_reserved(released_k_bits, released_access_credit)
                    .map_err(|_| Status::internal("failed to release holdout reservation"))?;
            }

            claim.reserved_k_bits = 0.0;
            claim.reserved_access_credit = 0.0;
            claim.reserved_expires_at_unix_ms = 0;
            self.transition_claim(claim, ClaimState::Stale, 0.0, 0.0, None)?;
            self.append_reservation_expired_incident(
                claim,
                released_k_bits,
                released_access_credit,
            )?;
            expired_count = expired_count.saturating_add(1);
        }

        if expired_count > 0 {
            persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        }
        Ok(expired_count)
    }

    fn active_signing_key(&self) -> Result<&SigningKey, Status> {
        self.state
            .keyring
            .get(&self.state.active_key_id)
            .ok_or_else(|| Status::internal("active signing key missing"))
    }

    fn caller_identity(metadata: &tonic::metadata::MetadataMap) -> CallerIdentity {
        derive_caller_identity(metadata)
    }

    fn principal_id_from_metadata(metadata: &tonic::metadata::MetadataMap) -> String {
        Self::caller_identity(metadata).principal_id
    }

    #[allow(clippy::result_large_err)]
    fn require_auditor_role(caller: &CallerIdentity, rpc_name: &str) -> Result<(), Status> {
        if caller.is_operator() || caller.is_auditor() {
            return Ok(());
        }
        tracing::warn!(
            target: "evidenceos.authz",
            rpc = rpc_name,
            caller_principal_id = %caller.principal_id,
            "AUTHZ_AUDITOR_ROLE_REQUIRED",
        );
        Err(Status::permission_denied("auditor role required"))
    }

    #[allow(clippy::result_large_err)]
    fn enforce_claim_access(
        caller: &CallerIdentity,
        claim: &Claim,
        rpc_name: &str,
    ) -> Result<(), Status> {
        if caller.is_operator() {
            tracing::warn!(
                target: "evidenceos.authz",
                rpc = rpc_name,
                claim_id = %hex::encode(claim.claim_id),
                owner_principal_id = %claim.owner_principal_id,
                caller_principal_id = %caller.principal_id,
                "AUTHZ_OPERATOR_OVERRIDE",
            );
            return Ok(());
        }
        if claim.owner_principal_id == caller.principal_id {
            return Ok(());
        }
        Err(Status::permission_denied(
            "AUTHZ_CLAIM_OWNER_MISMATCH: caller does not own claim",
        ))
    }

    fn request_id_from_metadata(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
        let Some(raw) = metadata.get("x-request-id") else {
            return Err(Status::invalid_argument("missing x-request-id"));
        };
        let req_id = raw
            .to_str()
            .map_err(|_| Status::invalid_argument("invalid x-request-id"))?
            .trim();
        if req_id.is_empty() || req_id.len() > 128 {
            return Err(Status::invalid_argument("invalid x-request-id"));
        }
        Ok(req_id.to_string())
    }

    fn validate_budget_value(value: f64, field: &str) -> Result<(), Status> {
        if !value.is_finite() || value < 0.0 {
            return Err(Status::invalid_argument(format!(
                "{field} must be finite and >= 0"
            )));
        }
        Ok(())
    }

    fn holdout_scope_for(&self, descriptor: &HoldoutDescriptor) -> HoldoutPoolScope {
        descriptor
            .holdout_pool_scope
            .unwrap_or(self.holdout_pool_scope)
    }

    #[allow(dead_code)]
    fn holdout_budget_for(&self, descriptor: &HoldoutDescriptor) -> (f64, f64) {
        (
            descriptor
                .holdout_k_bits_budget
                .unwrap_or(self.default_holdout_k_bits_budget),
            descriptor
                .holdout_access_credit_budget
                .unwrap_or(self.default_holdout_access_credit_budget),
        )
    }

    fn holdout_pool_keys(
        &self,
        holdout_id: [u8; 32],
        principal_id: &str,
        scope: HoldoutPoolScope,
    ) -> Vec<HoldoutPoolKey> {
        match scope {
            HoldoutPoolScope::Global => vec![HoldoutPoolKey {
                holdout_id,
                principal_id: None,
            }],
            HoldoutPoolScope::PerPrincipal => vec![HoldoutPoolKey {
                holdout_id,
                principal_id: Some(principal_id.to_string()),
            }],
            HoldoutPoolScope::Both => vec![
                HoldoutPoolKey {
                    holdout_id,
                    principal_id: None,
                },
                HoldoutPoolKey {
                    holdout_id,
                    principal_id: Some(principal_id.to_string()),
                },
            ],
        }
    }

    fn require_operator(&self, principal_id: &str) -> Result<(), Status> {
        if self.operator_principals.iter().any(|p| p == principal_id) {
            return Ok(());
        }
        Err(Status::permission_denied("operator role required"))
    }

    fn default_credit_limit_for(&self, principal_id: &str) -> u64 {
        // CREDIT-EXTERNAL: enforcement point.
        // Caller must have been pre-authorized by operator
        // credit service. See docs/CREDIT_AND_ADMISSION.md
        self.admission_provider.max_credit(principal_id)
    }

    fn charge_principal_credit(
        &self,
        principal_id: &str,
        k_bits: Option<u64>,
        fuel: Option<u64>,
        max_memory_pages: Option<u64>,
    ) -> Result<u64, Status> {
        let charge = self
            .access_credit_pricing
            .charge(k_bits, fuel, max_memory_pages);
        // CREDIT-EXTERNAL: enforcement point.
        // Caller must have been pre-authorized by operator
        // credit service. See docs/CREDIT_AND_ADMISSION.md
        let _ = self
            .credit_backend
            .check_and_deduct(principal_id, "", charge as f64)
            .map_err(|_| Status::resource_exhausted("principal credit exhausted"))?;
        let default_limit = self.default_credit_limit_for(principal_id);
        // CREDIT-EXTERNAL: enforcement point.
        // Caller must have been pre-authorized by operator
        // credit service. See docs/CREDIT_AND_ADMISSION.md
        self.admission_provider.admit(principal_id, charge)?;
        let mut store = self.state.account_store.lock();
        let _ = store.ensure_account(principal_id, default_limit)?;
        match store.burn(principal_id, charge, default_limit) {
            Ok(remaining) => {
                self.telemetry.record_credit_burned(principal_id, charge);
                Ok(remaining)
            }
            Err(status) => {
                self.telemetry.record_credit_denied(principal_id);
                Err(status)
            }
        }
    }

    fn canary_key(claim_name: &str, holdout_ref: &str) -> String {
        format!("{claim_name}::{holdout_ref}")
    }
}

const STATE_FILE_NAME: &str = "state.json";
const PENDING_MUTATION_FILE_NAME: &str = "pending_mutation.json";
const PENDING_MUTATIONS_DIR_NAME: &str = "pending_mutations";

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), Status> {
    let dir = File::open(path).map_err(|_| Status::internal("open directory failed"))?;
    dir.sync_all()
        .map_err(|_| Status::internal("sync directory failed"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), Status> {
    Ok(())
}

fn write_file_atomic_durable(
    path: &Path,
    bytes: &[u8],
    write_err: &'static str,
) -> Result<(), Status> {
    let parent = path
        .parent()
        .ok_or_else(|| Status::internal("path parent missing"))?;
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp).map_err(|_| Status::internal(write_err))?;
    f.write_all(bytes)
        .map_err(|_| Status::internal(write_err))?;
    f.sync_all().map_err(|_| Status::internal(write_err))?;
    std::fs::rename(&tmp, path).map_err(|_| Status::internal(write_err))?;
    sync_directory(parent)?;
    Ok(())
}

fn remove_file_durable(path: &Path) -> Result<(), Status> {
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|_| Status::internal("remove pending mutation failed"))?;
        let parent = path
            .parent()
            .ok_or_else(|| Status::internal("path parent missing"))?;
        sync_directory(parent)?;
    }
    Ok(())
}

fn persist_all(state: &ServerState) -> Result<(), Status> {
    persist_all_with_trial_router(state, None)
}

fn persist_all_with_trial_router(
    state: &ServerState,
    trial_router: Option<&TrialRouter>,
) -> Result<(), Status> {
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
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        canary_states: state
            .canary_states
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        trial_allocator_state: trial_router.and_then(TrialRouter::export_blocked_state),
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|_| Status::internal("serialize state failed"))?;
    write_file_atomic_durable(
        &state.data_path.join(STATE_FILE_NAME),
        &bytes,
        "write state failed",
    )
}

fn persist_pending_mutation(state: &ServerState, pending: &PendingMutation) -> Result<(), Status> {
    let claim_id = pending.claim_id();
    let pending_dir = pending_mutations_dir(&state.data_path);
    ensure_directory_durable(&pending_dir)?;
    let bytes = serde_json::to_vec_pretty(pending)
        .map_err(|_| Status::internal("serialize pending mutation failed"))?;
    write_file_atomic_durable(
        &pending_mutation_path_for_claim(&state.data_path, claim_id),
        &bytes,
        "write pending mutation failed",
    )
}

fn clear_pending_mutation(state: &ServerState, claim_id: [u8; 32]) -> Result<(), Status> {
    remove_file_durable(&pending_mutation_path_for_claim(&state.data_path, claim_id))
}

fn recover_pending_mutations(state: &ServerState) -> Result<(), Status> {
    let legacy_path = state.data_path.join(PENDING_MUTATION_FILE_NAME);
    if legacy_path.exists() {
        let bytes = std::fs::read(&legacy_path)
            .map_err(|_| Status::internal("read pending mutation failed"))?;
        let pending: PendingMutation = serde_json::from_slice(&bytes)
            .map_err(|_| Status::internal("decode pending mutation failed"))?;
        apply_pending_mutation(state, pending)?;
        remove_file_durable(&legacy_path)?;
    }

    let pending_dir = pending_mutations_dir(&state.data_path);
    if !pending_dir.exists() {
        return Ok(());
    }
    let mut paths = std::fs::read_dir(&pending_dir)
        .map_err(|_| Status::internal("read pending mutations directory failed"))?
        .map(|entry| {
            entry
                .map(|e| e.path())
                .map_err(|_| Status::internal("read pending mutation directory entry failed"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let bytes =
            std::fs::read(&path).map_err(|_| Status::internal("read pending mutation failed"))?;
        let pending: PendingMutation = serde_json::from_slice(&bytes)
            .map_err(|_| Status::internal("decode pending mutation failed"))?;
        let claim_id = pending.claim_id();
        apply_pending_mutation(state, pending)?;
        clear_pending_mutation(state, claim_id)?;
    }

    Ok(())
}

fn apply_pending_mutation(state: &ServerState, pending: PendingMutation) -> Result<(), Status> {
    match pending {
        PendingMutation::Execute {
            claim_id,
            state: next_state,
            decision,
            capsule_hash,
            capsule_bytes,
            etl_index,
        } => {
            let mut claims = state.claims.lock();
            if let Some(claim) = claims.get_mut(&claim_id) {
                claim.state = next_state;
                claim.last_decision = Some(decision);
                claim.last_capsule_hash = Some(capsule_hash);
                claim.capsule_bytes = Some(capsule_bytes);
                claim.etl_index = etl_index;
            }
        }
        PendingMutation::Revoke {
            claim_id,
            capsule_hash,
            reason,
            timestamp_unix,
            tainted_claim_ids,
            etl_applied,
        } => {
            if !etl_applied {
                return Err(Status::internal(
                    "pending revoke missing durable etl append",
                ));
            }
            {
                let mut claims = state.claims.lock();
                if let Some(claim) = claims.get_mut(&claim_id) {
                    claim.state = ClaimState::Revoked;
                }
                for tainted in tainted_claim_ids {
                    if let Some(claim) = claims.get_mut(&tainted) {
                        claim.state = ClaimState::Tainted;
                    }
                }
            }
            let mut revocations = state.revocations.lock();
            if !revocations.iter().any(|(hash, ts, existing_reason)| {
                *hash == capsule_hash && *ts == timestamp_unix && existing_reason == &reason
            }) {
                revocations.push((capsule_hash, timestamp_unix, reason));
            }
        }
    }

    persist_all(state)?;
    Ok(())
}

fn ensure_directory_durable(path: &Path) -> Result<(), Status> {
    std::fs::create_dir_all(path).map_err(|_| Status::internal("create directory failed"))?;
    sync_directory(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn pending_mutations_dir(data_path: &Path) -> PathBuf {
    data_path.join(PENDING_MUTATIONS_DIR_NAME)
}

fn pending_mutation_path_for_claim(data_path: &Path, claim_id: [u8; 32]) -> PathBuf {
    pending_mutations_dir(data_path).join(format!("{}.json", hex::encode(claim_id)))
}

fn parse_hash32(bytes: &[u8], _field: &str) -> Result<[u8; 32], Status> {
    if bytes.len() != 32 {
        return Err(public_status(
            Code::InvalidArgument,
            PublicErrorCode::InvalidInput,
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn compute_topic_manifest_hash(manifest: &TopicManifestForHash) -> Result<[u8; 32], Status> {
    let canonical = serde_json::to_vec(manifest)
        .map_err(|_| Status::internal("topic manifest serialization failed"))?;
    Ok(sha256_domain(DOMAIN_TOPIC_MANIFEST_HASH_V1, &canonical))
}

fn derive_server_topic_semantic_hash(manifest_hash: [u8; 32]) -> [u8; 32] {
    hash_signal(b"evidenceos/topic_semantic", &manifest_hash)
}

fn derive_server_topic_physhir_hash(
    claim_manifest_hash: [u8; 32],
    output_schema_id: &str,
) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&claim_manifest_hash);
    payload.extend_from_slice(output_schema_id.as_bytes());
    hash_signal(b"evidenceos/topic_physhir", &payload)
}

fn build_topic_oracle_receipt(
    signing_key: &SigningKey,
    claim_manifest_hash: [u8; 32],
    semantic_hash: [u8; 32],
    model_id: &str,
) -> TopicOracleReceipt {
    let timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut payload = Vec::new();
    payload.extend_from_slice(&claim_manifest_hash);
    payload.extend_from_slice(&semantic_hash);
    payload.extend_from_slice(model_id.as_bytes());
    payload.extend_from_slice(&timestamp_unix.to_be_bytes());
    let digest = sha256_domain(DOMAIN_TOPIC_ORACLE_RECEIPT_V1, &payload);
    let signature = sign_payload(signing_key, &digest);
    TopicOracleReceipt {
        claim_manifest_hash,
        semantic_hash,
        model_id: model_id.to_string(),
        timestamp_unix,
        signature: signature.to_vec(),
    }
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

#[cfg(unix)]
fn ensure_secret_key_permissions(path: &Path) -> Result<(), Status> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| Status::internal("read signing key metadata failed"))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Status::failed_precondition(
            "signing key permissions are too broad; require 0600 or stricter",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_secret_key_permissions(_path: &Path) -> Result<(), Status> {
    Ok(())
}

#[allow(clippy::type_complexity)]
fn load_or_create_keyring(
    data_dir: &Path,
) -> Result<([u8; 32], HashMap<[u8; 32], SigningKey>), Status> {
    let keys_dir = data_dir.join(KEYRING_DIR_REL_PATH);
    std::fs::create_dir_all(&keys_dir).map_err(|_| Status::internal("mkdir keys failed"))?;

    if matches!(SigningKeySource::from_env()?, SigningKeySource::Kms) {
        let signing_key = load_signing_key_from_kms()?;
        let key_id = key_id_from_verifying_key(&signing_key.verifying_key());
        let mut keyring = HashMap::new();
        keyring.insert(key_id, signing_key);
        return Ok((key_id, keyring));
    }

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
        ensure_secret_key_permissions(&path)?;
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
        ensure_secret_key_permissions(&legacy_key_path)?;
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&active_path)
            .map_err(|_| Status::internal("write active key id failed"))?;
        f.write_all(format!("{}\n", hex::encode(active_key_id)).as_bytes())
            .and_then(|_| f.flush())
            .map_err(|_| Status::internal("write active key id failed"))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&active_path, format!("{}\n", hex::encode(active_key_id)))
            .map_err(|_| Status::internal("write active key id failed"))?;
    }

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

fn trial_commitment_hash_v1(assignment: Option<&TrialAssignment>) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.push(TRIAL_COMMITMENT_SCHEMA_VERSION_V1);
    match assignment {
        Some(assignment) => {
            payload.extend_from_slice(&assignment.arm_id.to_be_bytes());
            payload.extend_from_slice(assignment.intervention_id.as_bytes());
            payload.extend_from_slice(assignment.intervention_version.as_bytes());
            payload.extend_from_slice(&assignment.arm_parameters_hash);
            payload.extend_from_slice(&assignment.trial_nonce);
        }
        None => {
            payload.extend_from_slice(&0u16.to_be_bytes());
            payload.extend_from_slice(&[0u8; TRIAL_NONCE_LEN]);
        }
    }
    sha256_bytes(&payload)
}

fn trial_commitment_hash_v2(assignment: Option<&TrialAssignment>) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.push(TRIAL_COMMITMENT_SCHEMA_VERSION_V2);
    match assignment {
        Some(assignment) => {
            payload.extend_from_slice(&assignment.arm_id.to_be_bytes());
            payload.extend_from_slice(&(assignment.intervention_id.len() as u16).to_be_bytes());
            payload.extend_from_slice(assignment.intervention_id.as_bytes());
            payload
                .extend_from_slice(&(assignment.intervention_version.len() as u16).to_be_bytes());
            payload.extend_from_slice(assignment.intervention_version.as_bytes());
            payload.extend_from_slice(&assignment.arm_parameters_hash);
            payload.extend_from_slice(&assignment.trial_nonce);
        }
        None => {
            payload.extend_from_slice(&0u16.to_be_bytes());
            payload.extend_from_slice(&0u16.to_be_bytes());
            payload.extend_from_slice(&0u16.to_be_bytes());
            payload.extend_from_slice(&[0u8; 32]);
            payload.extend_from_slice(&[0u8; TRIAL_NONCE_LEN]);
        }
    }
    sha256_bytes(&payload)
}

fn trial_commitment_hash(assignment: Option<&TrialAssignment>, schema_version: u8) -> [u8; 32] {
    match schema_version {
        TRIAL_COMMITMENT_SCHEMA_VERSION_V1 => trial_commitment_hash_v1(assignment),
        TRIAL_COMMITMENT_SCHEMA_VERSION_V2 => trial_commitment_hash_v2(assignment),
        _ => trial_commitment_hash_v2(assignment),
    }
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
    payload.extend_from_slice(&pins.oracle_resolution_hash);
    sha256_bytes(&payload)
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
    let payload = sth_signature_digest(tree_size, root_hash);
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
) -> Result<pb::WatchRevocationsResponse, Status> {
    let entries: Vec<pb::RevocationEntry> = revocations
        .into_iter()
        .map(|(claim_id, timestamp_unix, reason)| pb::RevocationEntry {
            claim_id: claim_id.to_vec(),
            timestamp_unix,
            reason,
        })
        .collect();
    let payload = revocations_snapshot_digest(&entries, &signed_tree_head)
        .map_err(|_| Status::internal("failed to build revocations snapshot digest"))?;
    let signature = sign_payload(signing_key, &payload);
    Ok(pb::WatchRevocationsResponse {
        entries,
        signature: signature.to_vec(),
        signed_tree_head: Some(signed_tree_head),
        key_id: key_id.to_vec(),
    })
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

fn burn_padding_fuel(
    vault: &VaultEngine,
    context: &VaultExecutionContext,
    padding_fuel: u64,
) -> Result<(), Status> {
    if padding_fuel == 0 {
        return Ok(());
    }
    let burn_cfg = VaultConfig {
        max_fuel: padding_fuel,
        max_memory_bytes: 65_536,
        max_output_bytes: 1,
        max_oracle_calls: 1,
    };
    match vault.execute(BURN_WASM_MODULE, context, burn_cfg) {
        Err(VaultError::FuelExhausted) => Ok(()),
        Err(err) => Err(map_vault_error(err)),
        Ok(_) => Err(Status::internal("burn module terminated unexpectedly")),
    }
}

fn padded_fuel_total(
    epoch_budget: u64,
    fuel_used: u64,
    pln_cfg: Option<&ClaimPlnConfig>,
) -> Result<u64, Status> {
    if epoch_budget == 0 {
        return Err(Status::invalid_argument("epoch_size must be > 0"));
    }
    let normalized = if let Some(pln_cfg) = pln_cfg {
        if pln_cfg.target_fuel == 0 || pln_cfg.max_fuel == 0 {
            return Err(Status::failed_precondition("PLN config invalid"));
        }
        if pln_cfg.target_fuel > pln_cfg.max_fuel {
            return Err(Status::failed_precondition("PLN target exceeds max fuel"));
        }
        if fuel_used > pln_cfg.max_fuel {
            return Err(Status::failed_precondition("PLN max fuel exceeded"));
        }
        fuel_used.max(pln_cfg.target_fuel)
    } else {
        fuel_used
    };
    let rem = normalized % epoch_budget;
    let padding_fuel = if rem == 0 { 0 } else { epoch_budget - rem };
    Ok(normalized.saturating_add(padding_fuel))
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
    fuel_total: u64,
    ledger: &ConservationLedger,
    canonical_output: &[u8],
    reason_codes: &[u32],
) -> Result<Vec<u8>, Status> {
    let payload = serde_json::json!({
        "alpha_micros": (ledger.alpha() * 1_000_000.0).round() as u32,
        "log_alpha_target": ledger.log_alpha_target(),
        "log_alpha_prime": ledger.log_alpha_prime(),
        "barrier_threshold": ledger.barrier_threshold(),
        "canonical_output_len": canonical_output.len() as u32,
        "canonical_output_sha256": hex::encode(sha256_bytes(canonical_output)),
        "claim_id": hex::encode(claim.claim_id),
        "epoch": claim.epoch_counter,
        "fuel_used": fuel_total,
        "k_bits_total": ledger.k_bits_total(),
        "lane": EvidenceOsService::lane_name(claim.lane),
        "oracle_calls": vault_result.oracle_calls,
        "reason_codes": reason_codes,
        "topic_id": hex::encode(claim.topic_id),
        "w": ledger.wealth(),
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

fn validate_holdout_ref(holdout_ref: &str) -> Result<(), Status> {
    validate_required_str_field(holdout_ref, "holdout_ref", 128)?;
    if holdout_ref
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "holdout_ref must match [A-Za-z0-9_-]+",
        ))
    }
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

fn unix_epoch_now_secs() -> Result<u64, Status> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Status::internal("system clock before unix epoch"))
}

fn load_operator_runtime_config(
    data_path: &Path,
    enforce_operator_provenance: bool,
) -> Result<OperatorRuntimeConfig, Status> {
    let trusted_path = data_path.join("trusted_oracle_keys.json");
    let trusted_keys = if trusted_path.exists() {
        let bytes = std::fs::read(&trusted_path)
            .map_err(|_| Status::internal("read trusted keys failed"))?;
        let trusted: TrustedKeysFile = serde_json::from_slice(&bytes)
            .map_err(|_| Status::invalid_argument("decode trusted keys failed"))?;
        let mut out = HashMap::new();
        for (kid, key_hex) in trusted.keys {
            let key_bytes = hex::decode(key_hex)
                .map_err(|_| Status::invalid_argument("invalid trusted key hex"))?;
            let key_arr: [u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid trusted key length"))?;
            out.insert(kid, key_arr.to_vec());
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
        verify_signed_oracle_record(oracle_id, rec, &trusted_keys, enforce_operator_provenance)?;
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
    verify_epoch_control_record(&epoch_cfg, &trusted_keys)?;

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
            .filter_map(|(id, rec)| {
                rec.calibration_manifest_hash_hex
                    .clone()
                    .map(|v| (id.clone(), v))
            })
            .collect(),
        forced_epoch: epoch_cfg.forced_epoch,
        active_nullspec_mappings: nullspec_mappings_len,
    })
}

fn verify_signed_oracle_record(
    oracle_id: &str,
    rec: &OracleOperatorRecord,
    trusted_keys: &HashMap<String, Vec<u8>>,
    enforce_operator_provenance: bool,
) -> Result<(), Status> {
    if rec.schema_version != 1 {
        return Err(Status::invalid_argument(
            "unsupported oracle operator schema_version",
        ));
    }
    if rec.ttl_epochs == 0 {
        return Err(Status::invalid_argument("oracle ttl must be > 0"));
    }
    let now_epoch = unix_epoch_now_secs()?;
    if rec.updated_at_epoch > now_epoch {
        return Err(Status::failed_precondition(
            "oracle operator record updated_at_epoch is in the future",
        ));
    }
    if enforce_operator_provenance
        && now_epoch.saturating_sub(rec.updated_at_epoch) > rec.ttl_epochs
    {
        return Err(Status::failed_precondition(
            "oracle operator record expired",
        ));
    }
    let calibration_manifest_hash_hex = rec.calibration_manifest_hash_hex.as_deref().unwrap_or("");
    if enforce_operator_provenance && calibration_manifest_hash_hex.is_empty() {
        return Err(Status::failed_precondition(
            "calibration manifest hash missing",
        ));
    }
    if !calibration_manifest_hash_hex.is_empty() {
        decode_hex_hash32(
            calibration_manifest_hash_hex,
            "calibration_manifest_hash_hex",
        )?;
    }
    let disjointness_attestation = rec.disjointness_attestation.as_ref();
    if enforce_operator_provenance {
        let attestation = disjointness_attestation
            .ok_or_else(|| Status::failed_precondition("disjointness attestation must be set"))?;
        if attestation.statement_type != "oracle_disjointness_v1" {
            return Err(Status::failed_precondition(
                "unsupported disjointness statement_type",
            ));
        }
        if attestation.scope.trim().is_empty() {
            return Err(Status::failed_precondition(
                "disjointness attestation scope must be non-empty",
            ));
        }
        decode_hex_hash32(&attestation.proof_sha256_hex, "proof_sha256_hex")?;
    }
    let key_bytes = trusted_keys
        .get(&rec.key_id)
        .ok_or_else(|| Status::failed_precondition("unknown signing key for oracle config"))?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("invalid trusted key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|_| Status::invalid_argument("invalid trusted oracle verifying key"))?;
    let sig_bytes = hex::decode(&rec.signature_ed25519)
        .map_err(|_| Status::invalid_argument("invalid oracle config signature hex"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| Status::invalid_argument("invalid oracle config signature length"))?;
    let payload = OracleOperatorRecordSigningPayload {
        oracle_id,
        schema_version: rec.schema_version,
        ttl_epochs: rec.ttl_epochs,
        calibration_manifest_hash_hex,
        calibration_epoch: rec.calibration_epoch,
        disjointness_attestation,
        nonoverlap_proof_uri: rec.nonoverlap_proof_uri.as_deref(),
        updated_at_epoch: rec.updated_at_epoch,
        key_id: &rec.key_id,
    };
    let canonical = evidenceos_core::capsule::canonical_json(&payload)
        .map_err(|_| Status::internal("oracle config canonicalization failed"))?;
    let digest = sha256_domain(DOMAIN_ORACLE_OPERATOR_RECORD_V1, &canonical);
    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|_| Status::failed_precondition("oracle config signature verification failed"))
}

fn verify_epoch_control_record(
    epoch_cfg: &EpochControlFile,
    trusted_keys: &HashMap<String, Vec<u8>>,
) -> Result<(), Status> {
    if let Some(forced_epoch) = epoch_cfg.forced_epoch {
        let updated_at_epoch = epoch_cfg
            .updated_at_epoch
            .ok_or_else(|| Status::failed_precondition("epoch control updated_at_epoch missing"))?;
        let key_id = epoch_cfg
            .key_id
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("epoch control key_id missing"))?;
        let signature_hex = epoch_cfg
            .signature_ed25519
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("epoch control signature missing"))?;
        let key_bytes = trusted_keys
            .get(key_id)
            .ok_or_else(|| Status::failed_precondition("unknown signing key for epoch control"))?;
        let key_arr: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid trusted key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|_| Status::invalid_argument("invalid trusted oracle verifying key"))?;
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|_| Status::invalid_argument("invalid epoch control signature hex"))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|_| Status::invalid_argument("invalid epoch control signature length"))?;
        let payload = EpochControlSigningPayload {
            forced_epoch,
            updated_at_epoch,
            key_id,
        };
        let canonical = evidenceos_core::capsule::canonical_json(&payload)
            .map_err(|_| Status::internal("epoch control canonicalization failed"))?;
        let digest = sha256_domain(DOMAIN_EPOCH_CONTROL_V1, &canonical);
        verifying_key
            .verify_strict(&digest, &signature)
            .map_err(|_| {
                Status::failed_precondition("epoch control signature verification failed")
            })?;
    }
    Ok(())
}

fn load_epoch_runtime_config(
    data_dir: &Path,
    epoch_config_ref: &str,
    fallback_epoch_size: u64,
) -> Result<(DlcConfig, Option<PlnRuntimeConfigFile>), Status> {
    validate_required_str_field(epoch_config_ref, "epoch_config_ref", MAX_METADATA_FIELD_LEN)?;
    let mut cfg_path = data_dir.join("epoch_configs").join(epoch_config_ref);
    cfg_path.set_extension("json");
    if !cfg_path.exists() {
        let cfg = DlcConfig::new(fallback_epoch_size)
            .map_err(|_| Status::invalid_argument("epoch_size must be > 0"))?;
        return Ok((cfg, None));
    }
    let bytes = std::fs::read(&cfg_path)
        .map_err(|_| Status::failed_precondition("read epoch config failed"))?;
    let parsed: EpochRuntimeConfigFile = serde_json::from_slice(&bytes)
        .map_err(|_| Status::invalid_argument("decode epoch config failed"))?;
    let mut cfg = DlcConfig::new(parsed.epoch_size)
        .map_err(|_| Status::invalid_argument("epoch config epoch_size must be > 0"))?;
    if let Some(cost) = parsed.pln_constant_cost {
        if cost == 0 {
            return Err(Status::invalid_argument(
                "epoch config pln_constant_cost must be > 0",
            ));
        }
        cfg.pln_constant_cost = Some(cost);
    }
    let pln_cfg = if let Some(pln_cfg) = parsed.pln {
        Some(pln_cfg)
    } else if parsed.pln_target_fuel.is_some()
        || parsed.pln_max_fuel.is_some()
        || parsed.pln_fast_enabled.is_some()
        || parsed.pln_heavy_enabled.is_some()
    {
        Some(PlnRuntimeConfigFile {
            target_fuel: parsed.pln_target_fuel.unwrap_or(0),
            max_fuel: parsed.pln_max_fuel.unwrap_or(0),
            lanes: PlnLaneConfigFile {
                fast: parsed.pln_fast_enabled.unwrap_or(true),
                heavy: parsed.pln_heavy_enabled.unwrap_or(true),
            },
        })
    } else {
        None
    };

    if let Some(pln_cfg) = pln_cfg {
        if pln_cfg.target_fuel == 0 {
            return Err(Status::invalid_argument(
                "epoch config pln.target_fuel must be > 0",
            ));
        }
        if pln_cfg.max_fuel == 0 {
            return Err(Status::invalid_argument(
                "epoch config pln.max_fuel must be > 0",
            ));
        }
        if pln_cfg.target_fuel > pln_cfg.max_fuel {
            return Err(Status::invalid_argument(
                "epoch config pln.target_fuel must be <= pln.max_fuel",
            ));
        }
        if !pln_cfg.lanes.fast && !pln_cfg.lanes.heavy {
            return Err(Status::invalid_argument(
                "epoch config pln must enable at least one lane",
            ));
        }
        Ok((cfg, Some(pln_cfg)))
    } else {
        Ok((cfg, None))
    }
}

fn claim_pln_config(
    lane: Lane,
    pln_cfg: &Option<PlnRuntimeConfigFile>,
) -> Result<ClaimPlnConfig, Status> {
    let cfg = pln_cfg
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("PLN must be configured for claimed lane"))?;
    if !cfg.lanes.supports_lane(lane) {
        return Err(Status::failed_precondition(
            "PLN not enabled for requested lane",
        ));
    }
    Ok(ClaimPlnConfig {
        target_fuel: cfg.target_fuel,
        max_fuel: cfg.max_fuel,
    })
}

fn current_logical_epoch(claim: &Claim) -> Result<u64, Status> {
    let cfg = DlcConfig::new(claim.epoch_size)
        .map_err(|_| Status::invalid_argument("epoch_size must be > 0"))?;
    let mut dlc = DeterministicLogicalClock::new(cfg);
    dlc.tick(claim.dlc_fuel_accumulated)
        .map_err(|_| Status::internal("dlc epoch computation overflow"))
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

fn default_registry_nullspec() -> Result<SignedNullSpecContractV1, Status> {
    let mut null_spec = SignedNullSpecContractV1 {
        schema: NULLSPEC_SCHEMA_V1.to_string(),
        nullspec_id: [0_u8; 32],
        oracle_id: "builtin.accuracy".to_string(),
        oracle_resolution_hash: [0_u8; 32],
        holdout_handle: "synthetic-holdout".to_string(),
        epoch_created: 0,
        ttl_epochs: u64::MAX,
        kind: NullSpecKind::ParametricBernoulli { p: 0.5 },
        eprocess: EProcessKind::LikelihoodRatioFixedAlt {
            alt: vec![0.5, 0.5],
        },
        calibration_manifest_hash: None,
        created_by: "test".to_string(),
        signature_ed25519: vec![0_u8; 64],
    };
    null_spec.nullspec_id = null_spec
        .compute_id()
        .map_err(|_| Status::internal("nullspec id compute failed"))?;
    Ok(null_spec)
}

fn vault_context(
    claim: &Claim,
    null_spec: SignedNullSpecContractV1,
    holdout_provider: &dyn HoldoutProvider,
) -> Result<VaultExecutionContext, Status> {
    let descriptor = holdout_provider.resolve(&claim.holdout_ref)?;
    if descriptor.handle != claim.holdout_handle_id {
        return Err(Status::failed_precondition("claim holdout handle mismatch"));
    }
    let raw_len = if claim.holdout_len == 0 {
        claim.epoch_size
    } else {
        claim.holdout_len
    };
    let claim_len = usize::try_from(raw_len)
        .map_err(|_| Status::failed_precondition("claim holdout length invalid"))?;
    if descriptor.len != claim_len {
        return Err(Status::failed_precondition("claim holdout length mismatch"));
    }
    let holdout_labels = holdout_provider.load_labels(&descriptor)?;
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
    contract: &evidenceos_core::nullspec::SignedNullSpecContractV1,
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
            let _ = reason;
            public_status(
                Code::FailedPrecondition,
                PublicErrorCode::FailedPrecondition,
            )
        }
    }
}

use tokio_stream::StreamExt;

fn current_time_unix_ms() -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis() as u64)
        .map_err(|_| Status::internal("system clock before unix epoch"))
}

fn decompose_request<T>(
    request: Request<T>,
) -> (tonic::metadata::MetadataMap, tonic::Extensions, T) {
    let (metadata, extensions, message) = request.into_parts();
    (metadata, extensions, message)
}

fn recompose_request<T>(
    metadata: tonic::metadata::MetadataMap,
    extensions: tonic::Extensions,
    message: T,
) -> Request<T> {
    Request::from_parts(metadata, extensions, message)
}

fn transcode_request<T, U>(request: Request<T>) -> Result<Request<U>, Status>
where
    T: Message,
    U: Message + Default,
{
    let (metadata, extensions, message) = decompose_request(request);
    let transcoded: U = transcode_message(message)?;
    Ok(recompose_request(metadata, extensions, transcoded))
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;
    use tonic::Code;

    fn dependency_artifact(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn test_assignment(intervention_id: &str, intervention_version: &str) -> TrialAssignment {
        TrialAssignment {
            trial_nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            arm_id: 7,
            intervention_id: intervention_id.to_string(),
            intervention_version: intervention_version.to_string(),
            arm_parameters_hash: [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            descriptors: crate::trial::InterventionDescriptors {
                oracle_policy: crate::trial::OraclePolicyDescriptor {
                    policy_id: "oracle.default.v1".to_string(),
                    params: json!({}),
                },
                dependence_policy: crate::trial::DependencePolicyDescriptor {
                    policy_id: "dependence.default.v1".to_string(),
                    params: json!({}),
                },
                nullspec_policy: crate::trial::NullSpecPolicyDescriptor {
                    policy_id: "nullspec.default.v1".to_string(),
                    params: json!({}),
                },
                output_policy: crate::trial::OutputPolicyDescriptor {
                    policy_id: "output.default.v1".to_string(),
                    params: json!({}),
                },
            },
            schema_version: u32::from(TRIAL_COMMITMENT_SCHEMA_VERSION_V2),
            allocator_snapshot_hash: None,
        }
    }

    #[test]
    fn trial_commitment_hash_v2_is_prefix_free_for_strings() {
        let assignment_left = test_assignment("ab", "c");
        let assignment_right = test_assignment("a", "bc");
        let left_hash = trial_commitment_hash_v2(Some(&assignment_left));
        let right_hash = trial_commitment_hash_v2(Some(&assignment_right));
        assert_ne!(left_hash, right_hash);
    }

    #[test]
    fn trial_commitment_hash_v1_matches_legacy_fixture() {
        let assignment = test_assignment("ab", "c");
        let hash = trial_commitment_hash_v1(Some(&assignment));
        assert_eq!(
            hex::encode(hash),
            "631f48bbf3b73770732b67d2a5644f14d8164295508687c329a4b4614da6c0fb"
        );
    }

    #[test]
    fn canonical_encoding_rejects_invalid_without_charge() {
        let mut ledger = ConservationLedger::new(0.1).expect("valid ledger");
        let oracle = OracleResolution::new(2, 0.0).expect("resolution");
        assert!(oracle.decode_bucket(&[0xFF]).is_err());
        assert_eq!(ledger.k_bits_total(), 0.0);
        ledger
            .charge(1.0, "structured_output", json!({}))
            .expect("charge should pass");
        assert_eq!(ledger.k_bits_total(), 1.0);
    }

    #[test]
    fn signed_tree_head_signature_verifies_and_tamper_fails() {
        let secret = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let root_hash = [11u8; 32];
        let digest = sth_signature_digest(42, root_hash);
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
    fn trial_harness_validation_rejects_identical_multi_arm_parameters() {
        let mut cfg = default_trial_arms_config();
        cfg.arms[1].arm_parameters = cfg.arms[0].arm_parameters.clone();
        let interventions = interventions_from_trial_config(&cfg);

        let err = validate_trial_harness_variation(true, cfg.arms.len() as u16, &interventions)
            .expect_err("identical arm parameters must be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("distinct arm_parameters_hash"));
    }

    #[test]
    fn trial_harness_validation_allows_distinct_multi_arm_parameters() {
        let cfg = default_trial_arms_config();
        let interventions = interventions_from_trial_config(&cfg);

        validate_trial_harness_variation(true, cfg.arms.len() as u16, &interventions)
            .expect("distinct arm parameters should be accepted");
    }

    #[test]
    fn domain_safety_policy_rejects_unsafe_modes_for_high_risk_domain() {
        let cfg = DomainSafetyConfig {
            require_structured_outputs: true,
            require_structured_output_domains: HashSet::from(["CBRN".to_string()]),
            deny_free_text_outputs: true,
            force_heavy_lane_on_domain: HashSet::from(["CBRN".to_string()]),
        };

        assert_eq!(
            cfg.decision_for("CBRN", structured_claims::LEGACY_SCHEMA_ID, Lane::Fast),
            DomainSafetyDecision::Reject
        );
        assert_eq!(
            cfg.decision_for("CBRN", structured_claims::SCHEMA_ID, Lane::Fast),
            DomainSafetyDecision::ForceHeavyLane
        );
        assert_eq!(
            cfg.decision_for("CBRN", structured_claims::SCHEMA_ID, Lane::Heavy),
            DomainSafetyDecision::Allow
        );
    }

    #[test]
    fn epoch_runtime_config_requires_pln_for_claimed_lanes() {
        let dir = TempDir::new().expect("tmp");
        let epoch_dir = dir.path().join("epoch_configs");
        std::fs::create_dir_all(&epoch_dir).expect("mkdir");
        std::fs::write(
            epoch_dir.join("epoch-a.json"),
            r#"{
                "epoch_size": 10,
                "pln_target_fuel": 100,
                "pln_max_fuel": 500,
                "pln_fast_enabled": false,
                "pln_heavy_enabled": true
            }"#,
        )
        .expect("write");

        let (_cfg, pln_cfg) = load_epoch_runtime_config(dir.path(), "epoch-a", 10).expect("cfg");
        let fast_err = claim_pln_config(Lane::Fast, &pln_cfg).expect_err("fast disabled");
        assert_eq!(fast_err.code(), Code::FailedPrecondition);
        let heavy_cfg = claim_pln_config(Lane::Heavy, &pln_cfg).expect("heavy enabled");
        assert_eq!(heavy_cfg.target_fuel, 100);
        assert_eq!(heavy_cfg.max_fuel, 500);
    }

    #[test]
    fn padded_fuel_total_enforces_target_and_max() {
        let pln_cfg = ClaimPlnConfig {
            target_fuel: 120,
            max_fuel: 200,
        };
        assert_eq!(padded_fuel_total(10, 25, Some(&pln_cfg)).expect("pad"), 120);
        assert_eq!(
            padded_fuel_total(10, 137, Some(&pln_cfg)).expect("pad"),
            140
        );
        let err = padded_fuel_total(10, 201, Some(&pln_cfg)).expect_err("max violated");
        assert_eq!(err.code(), Code::FailedPrecondition);
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

        let signed_tree_head = pb::SignedTreeHead {
            tree_size: 2,
            root_hash: vec![9; 32],
            signature: vec![0; 64],
            key_id: vec![7; 32],
        };
        let digest_ab =
            revocations_snapshot_digest(&entries_ab, &signed_tree_head).expect("digest");
        let digest_a_b =
            revocations_snapshot_digest(&entries_a_b, &signed_tree_head).expect("digest");
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

    fn write_holdout_registry(
        root: &Path,
        holdout_ref: &str,
        handle: [u8; 32],
        labels: &[u8],
        manifest_hash: [u8; 32],
        manifest_len: usize,
        encryption_key_id: Option<&str>,
    ) {
        let dir = root.join("holdouts").join(holdout_ref);
        std::fs::create_dir_all(&dir).expect("mkdir holdout dir");
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let labels_name = if encryption_key_id.is_some() {
            "labels.enc"
        } else {
            "labels.bin"
        };
        let labels_path = dir.join(labels_name);
        std::fs::write(&labels_path, labels).expect("write labels");
        #[cfg(unix)]
        std::fs::set_permissions(&labels_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod file");
        let manifest = serde_json::json!({
            "holdout_handle_hex": hex::encode(handle),
            "len": manifest_len,
            "labels_sha256_hex": hex::encode(manifest_hash),
            "created_at_unix": 1,
            "schema_version": HOLDOUT_MANIFEST_SCHEMA_VERSION,
            "encryption_key_id": encryption_key_id,
        });
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("manifest encode"),
        )
        .expect("write manifest");
    }

    fn write_holdout_registry_with_policy(
        root: &Path,
        holdout_ref: &str,
        handle: [u8; 32],
        labels: &[u8],
        holdout_k_bits_budget: Option<f64>,
        holdout_access_credit_budget: Option<f64>,
        holdout_pool_scope: Option<&str>,
    ) {
        let dir = root.join("holdouts").join(holdout_ref);
        std::fs::create_dir_all(&dir).expect("mkdir holdout dir");
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let labels_path = dir.join("labels.bin");
        std::fs::write(&labels_path, labels).expect("write labels");
        #[cfg(unix)]
        std::fs::set_permissions(&labels_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod file");
        let manifest = serde_json::json!({
            "holdout_handle_hex": hex::encode(handle),
            "len": labels.len(),
            "labels_sha256_hex": hex::encode(sha256_bytes(labels)),
            "created_at_unix": 1,
            "schema_version": HOLDOUT_MANIFEST_SCHEMA_VERSION,
            "encryption_key_id": serde_json::Value::Null,
            "holdout_k_bits_budget": holdout_k_bits_budget,
            "holdout_access_credit_budget": holdout_access_credit_budget,
            "holdout_pool_scope": holdout_pool_scope,
        });
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("manifest encode"),
        )
        .expect("write manifest");
    }

    fn request_with_principal(
        req: pb::CreateClaimV2Request,
        principal: &str,
    ) -> Request<pb::CreateClaimV2Request> {
        let mut request = Request::new(req);
        request.metadata_mut().insert(
            "x-principal-id",
            principal.parse().expect("principal metadata"),
        );
        request
    }

    fn claim_request(holdout_ref: &str) -> pb::CreateClaimV2Request {
        pb::CreateClaimV2Request {
            claim_name: "claim-a".to_string(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".to_string(),
                alpha_micros: 50_000,
                epoch_config_ref: "epoch-a".to_string(),
                output_schema_id: "legacy/v1".to_string(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: vec![1; 32],
                phys_hir_signature_hash: vec![2; 32],
                dependency_merkle_root: vec![3; 32],
            }),
            holdout_ref: holdout_ref.to_string(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            dp_epsilon_budget: None,
            dp_delta_budget: None,
            access_credit: 32,
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
        }
    }

    #[tokio::test]
    async fn create_claim_v2_rejects_unknown_holdout_ref() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");
        let err = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            Request::new(claim_request("unknown-holdout")),
        )
        .await
        .expect_err("unknown holdout should fail");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "unknown holdout_ref");
    }

    #[tokio::test]
    async fn create_claim_v2_rejects_negative_dp_budget() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let holdout_ref = "holdout-a";
        let handle = [7u8; 32];
        let labels = vec![0_u8, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );

        let mut req = claim_request(holdout_ref);
        req.dp_epsilon_budget = Some(-0.1);
        let err = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req))
            .await
            .expect_err("negative dp budget should fail");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("dp_epsilon_budget"));
    }

    #[tokio::test]
    async fn create_claim_v2_reservation_expires_and_is_reclaimed() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let holdout_ref = "holdout-a";
        let handle = [7u8; 32];
        let labels = vec![0_u8, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );

        let created = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            Request::new(claim_request(holdout_ref)),
        )
        .await
        .expect("create")
        .into_inner();
        let claim_id: [u8; 32] = created
            .claim_id
            .as_slice()
            .try_into()
            .expect("claim_id len");

        let (topic_id, holdout_handle_id, reserved_before) = {
            let claims = svc.state.claims.lock();
            let claim = claims.get(&claim_id).expect("claim");
            assert_eq!(claim.state, ClaimState::Uncommitted);
            assert!(claim.reserved_k_bits > 0.0);
            assert!(claim.reserved_access_credit > 0.0);
            assert!(claim.reserved_expires_at_unix_ms > 0);
            (
                claim.topic_id,
                claim.holdout_handle_id,
                claim.reserved_k_bits,
            )
        };

        {
            let mut claims = svc.state.claims.lock();
            let claim = claims.get_mut(&claim_id).expect("claim");
            claim.reserved_expires_at_unix_ms = 1;
        }

        let swept = svc.sweep_expired_reservations().expect("sweep");
        assert_eq!(swept, 1);

        let claim = svc
            .state
            .claims
            .lock()
            .get(&claim_id)
            .cloned()
            .expect("claim");
        assert_eq!(claim.state, ClaimState::Stale);
        assert_eq!(claim.reserved_k_bits, 0.0);
        assert_eq!(claim.reserved_access_credit, 0.0);

        let topic_pool = svc
            .state
            .topic_pools
            .lock()
            .get(&topic_id)
            .cloned()
            .expect("topic pool");
        assert_eq!(topic_pool.reserved_k_bits(), 0.0);

        let holdout_keys =
            svc.holdout_pool_keys(holdout_handle_id, "anonymous", HoldoutPoolScope::Global);
        let holdout_pools = svc.state.holdout_pools.lock();
        for key in holdout_keys {
            let pool = holdout_pools.get(&key).expect("holdout pool");
            assert_eq!(pool.reserved_k_bits, 0.0);
        }
        assert!(reserved_before > 0.0);
    }

    #[tokio::test]
    async fn dependency_root_mismatch_rejected() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let holdout_ref = "holdout-a";
        let handle = [7u8; 32];
        let labels = vec![0_u8, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );

        let deps = vec![dependency_artifact(10), dependency_artifact(20)];
        let mut sorted_deps = deps.clone();
        sorted_deps.sort();
        let root = dependency_merkle_root(&sorted_deps);

        let mut req = claim_request(holdout_ref);
        req.signals
            .as_mut()
            .expect("signals")
            .dependency_merkle_root = root.to_vec();
        let created = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req))
            .await
            .expect("create")
            .into_inner();

        let mut artifacts = vec![pb::Artifact {
            artifact_hash: sha256_bytes(BURN_WASM_MODULE).to_vec(),
            kind: "wasm".to_string(),
        }];
        artifacts.push(pb::Artifact {
            artifact_hash: dependency_artifact(30).to_vec(),
            kind: "dependency".to_string(),
        });

        let err = <EvidenceOsService as EvidenceOsV2>::commit_artifacts(
            &svc,
            Request::new(pb::CommitArtifactsRequest {
                claim_id: created.claim_id,
                artifacts,
                wasm_module: BURN_WASM_MODULE.to_vec(),
            }),
        )
        .await
        .expect_err("dependency root mismatch must fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn dependencies_forbidden_if_root_missing() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let holdout_ref = "holdout-a";
        let handle = [7u8; 32];
        let labels = vec![0_u8, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );

        let mut req = claim_request(holdout_ref);
        req.signals
            .as_mut()
            .expect("signals")
            .dependency_merkle_root = Vec::new();
        let created = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req))
            .await
            .expect("create")
            .into_inner();

        let artifacts = vec![
            pb::Artifact {
                artifact_hash: sha256_bytes(BURN_WASM_MODULE).to_vec(),
                kind: "wasm".to_string(),
            },
            pb::Artifact {
                artifact_hash: dependency_artifact(42).to_vec(),
                kind: "dependency".to_string(),
            },
        ];

        let err = <EvidenceOsService as EvidenceOsV2>::commit_artifacts(
            &svc,
            Request::new(pb::CommitArtifactsRequest {
                claim_id: created.claim_id,
                artifacts,
                wasm_module: BURN_WASM_MODULE.to_vec(),
            }),
        )
        .await
        .expect_err("dependencies without root commitment must fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn create_claim_v2_stores_trial_assignment_once() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let holdout_ref = "holdout-a";
        let handle = [7u8; 32];
        let labels = vec![0_u8, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );

        let response = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            Request::new(claim_request(holdout_ref)),
        )
        .await
        .expect("create");
        assert_eq!(response.get_ref().topic_id.len(), 32);

        let claim_id = parse_hash32(&response.get_ref().claim_id, "claim_id").expect("claim id");
        let first_assignment = {
            let claims = svc.state.claims.lock();
            claims
                .get(&claim_id)
                .and_then(|claim| claim.trial_assignment.clone())
                .expect("trial assignment")
        };

        let _ = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            Request::new(claim_request(holdout_ref)),
        )
        .await
        .expect("create duplicate");

        let second_assignment = {
            let claims = svc.state.claims.lock();
            claims
                .get(&claim_id)
                .and_then(|claim| claim.trial_assignment.clone())
                .expect("trial assignment")
        };
        assert_eq!(first_assignment, second_assignment);
    }

    #[tokio::test]
    async fn create_claim_v2_trial_interventions_scale_k_budget_between_arms() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let holdout_ref = "holdout-trial-scale";
        let handle = [6u8; 32];
        let labels = vec![0_u8, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );

        let mut req_a = claim_request(holdout_ref);
        req_a.claim_name = "claim-a".to_string();
        req_a.signals.as_mut().expect("signals").semantic_hash = vec![11; 32];
        let resp_a =
            <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req_a))
                .await
                .expect("create a");
        let claim_a = parse_hash32(&resp_a.get_ref().claim_id, "claim_id").expect("claim a id");

        let mut req_b = claim_request(holdout_ref);
        req_b.claim_name = "claim-b".to_string();
        req_b.signals.as_mut().expect("signals").semantic_hash = vec![12; 32];
        let resp_b =
            <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req_b))
                .await
                .expect("create b");
        let claim_b = parse_hash32(&resp_b.get_ref().claim_id, "claim_id").expect("claim b id");

        let (arm_a, budget_a) = {
            let claims = svc.state.claims.lock();
            let claim = claims.get(&claim_a).expect("claim a");
            (
                claim
                    .trial_assignment
                    .as_ref()
                    .expect("trial assignment a")
                    .arm_id,
                claim.ledger.k_bits_budget().expect("k budget a"),
            )
        };
        let (arm_b, budget_b) = {
            let claims = svc.state.claims.lock();
            let claim = claims.get(&claim_b).expect("claim b");
            (
                claim
                    .trial_assignment
                    .as_ref()
                    .expect("trial assignment b")
                    .arm_id,
                claim.ledger.k_bits_budget().expect("k budget b"),
            )
        };

        assert_ne!(arm_a, arm_b);
        let (control_budget, treatment_budget) = if arm_a == 0 {
            (budget_a, budget_b)
        } else {
            (budget_b, budget_a)
        };
        assert!((treatment_budget - (control_budget * 0.75)).abs() < 1e-6);
    }

    #[tokio::test]
    async fn holdout_pool_per_principal_isolates_budgets() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");
        let holdout_ref = "holdout-per-principal";
        write_holdout_registry_with_policy(
            dir.path(),
            holdout_ref,
            [8u8; 32],
            &[0, 1, 1, 0],
            Some(100.0),
            Some(55.0),
            Some("per_principal"),
        );

        let _ = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            request_with_principal(claim_request(holdout_ref), "principal-a"),
        )
        .await
        .expect("create a");
        let _ = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            request_with_principal(claim_request(holdout_ref), "principal-b"),
        )
        .await
        .expect("create b");

        let pools = svc.state.holdout_pools.lock();
        assert_eq!(pools.len(), 2);
        for (key, pool) in pools.iter() {
            assert_eq!(key.holdout_id, [8u8; 32]);
            assert!(key.principal_id.is_some());
            assert_eq!(pool.k_bits_budget, 100.0);
            assert_eq!(pool.access_credit_budget, 55.0);
        }
    }

    #[tokio::test]
    async fn holdout_pool_global_uses_policy_budget_not_first_claim() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");
        let holdout_ref = "holdout-global";
        write_holdout_registry_with_policy(
            dir.path(),
            holdout_ref,
            [9u8; 32],
            &[0, 1, 1, 0],
            Some(77.0),
            Some(33.0),
            Some("global"),
        );

        let mut req_a = claim_request(holdout_ref);
        req_a.access_credit = 1;
        let _ = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            request_with_principal(req_a, "principal-a"),
        )
        .await
        .expect("create a");
        let mut req_b = claim_request(holdout_ref);
        req_b.access_credit = 999;
        let _ = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &svc,
            request_with_principal(req_b, "principal-b"),
        )
        .await
        .expect("create b");

        let pools = svc.state.holdout_pools.lock();
        let pool = pools
            .get(&HoldoutPoolKey {
                holdout_id: [9u8; 32],
                principal_id: None,
            })
            .expect("global pool");
        assert_eq!(pool.k_bits_budget, 77.0);
        assert_eq!(pool.access_credit_budget, 33.0);
    }

    #[test]
    fn holdout_pool_both_scope_freezes_if_either_pool_exhausted() {
        let mut global_pool = HoldoutBudgetPool::new(
            HoldoutPoolKey {
                holdout_id: [1u8; 32],
                principal_id: None,
            },
            10.0,
            10.0,
        )
        .expect("global pool");
        let mut principal_pool = HoldoutBudgetPool::new(
            HoldoutPoolKey {
                holdout_id: [1u8; 32],
                principal_id: Some("principal-a".to_string()),
            },
            1.0,
            1.0,
        )
        .expect("principal pool");

        assert!(global_pool.charge(2.0, 2.0).is_ok());
        assert!(principal_pool.charge(2.0, 2.0).is_err());
        assert!(principal_pool.frozen);
    }

    #[test]
    fn registry_holdout_provider_decrypts_encrypted_labels() {
        let dir = TempDir::new().expect("tmp");
        let holdout_ref = "holdout-enc";
        let handle = [3u8; 32];
        let labels = vec![0, 1, 0, 1];
        let key_id = "dev-main";
        std::env::set_var(
            "EVIDENCEOS_HOLDOUT_KEY_DEV_MAIN",
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let key = [0x11u8; 32];
        let encrypted = evidenceos_core::holdout_crypto::encrypt_holdout_labels(&labels, &key)
            .expect("encrypt");
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &encrypted,
            sha256_bytes(&labels),
            labels.len(),
            Some(key_id),
        );

        let provider = RegistryHoldoutProvider::new(
            dir.path().join("holdouts"),
            false,
            Arc::new(EnvKeyProvider::new()),
        );
        let desc = provider.resolve(holdout_ref).expect("resolve");
        let out = provider.load_labels(&desc).expect("decrypt labels");
        assert_eq!(out, labels);
    }

    #[test]
    fn registry_holdout_provider_fails_closed_when_key_missing() {
        let dir = TempDir::new().expect("tmp");
        let holdout_ref = "holdout-missing-key";
        let handle = [4u8; 32];
        let labels = vec![1, 0, 1, 0];
        let key = [0x22u8; 32];
        let encrypted = evidenceos_core::holdout_crypto::encrypt_holdout_labels(&labels, &key)
            .expect("encrypt");
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &encrypted,
            sha256_bytes(&labels),
            labels.len(),
            Some("missing-key"),
        );
        std::env::remove_var("EVIDENCEOS_HOLDOUT_KEY_MISSING_KEY");

        let provider = RegistryHoldoutProvider::new(
            dir.path().join("holdouts"),
            false,
            Arc::new(EnvKeyProvider::new()),
        );
        let desc = provider.resolve(holdout_ref).expect("resolve");
        let err = provider
            .load_labels(&desc)
            .expect_err("missing key must fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "holdout key lookup failed");
    }

    #[cfg(unix)]
    #[test]
    fn registry_holdout_provider_rejects_weak_permissions() {
        let dir = TempDir::new().expect("tmp");
        let holdout_ref = "holdout-perms";
        let handle = [5u8; 32];
        let labels = vec![0, 1, 1, 0];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &labels,
            sha256_bytes(&labels),
            labels.len(),
            None,
        );
        let holdout_dir = dir.path().join("holdouts").join(holdout_ref);
        std::fs::set_permissions(&holdout_dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod dir weak");

        let provider = RegistryHoldoutProvider::new(
            dir.path().join("holdouts"),
            true,
            Arc::new(EnvKeyProvider::new()),
        );
        let desc = provider.resolve(holdout_ref).expect("resolve");
        let err = provider
            .load_labels(&desc)
            .expect_err("weak permissions must fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "holdout directory permissions must be 0700");
    }

    #[test]
    fn vault_context_rejects_holdout_label_hash_mismatch() {
        let dir = TempDir::new().expect("tmp");
        let holdout_ref = "holdout-a";
        let handle = [9u8; 32];
        let expected_labels = vec![0, 1, 0, 1];
        let wrong_labels = vec![1, 1, 1, 1];
        write_holdout_registry(
            dir.path(),
            holdout_ref,
            handle,
            &wrong_labels,
            sha256_bytes(&expected_labels),
            expected_labels.len(),
            None,
        );
        let provider = RegistryHoldoutProvider::new(
            dir.path().join("holdouts"),
            true,
            Arc::new(EnvKeyProvider::new()),
        );
        let claim = Claim {
            claim_id: [0; 32],
            topic_id: [0; 32],
            holdout_handle_id: handle,
            holdout_ref: holdout_ref.to_string(),
            epoch_config_ref: "epoch-a".to_string(),
            holdout_len: 4,
            metadata_locked: false,
            claim_name: "c".to_string(),
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash: [0; 32],
            semantic_hash: [0; 32],
            topic_oracle_receipt: None,
            output_schema_id_hash: [0; 32],
            holdout_handle_hash: [0; 32],
            lineage_root_hash: [0; 32],
            disagreement_score: 0,
            semantic_physhir_distance_bits: 0,
            escalate_to_heavy: false,
            epoch_size: 10,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: None,
            oracle_num_symbols: 4,
            oracle_resolution: OracleResolution::new(4, 0.0).expect("resolution"),
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            dependency_merkle_root: None,
            wasm_module: Vec::new(),
            aspec_rejection: None,
            aspec_report_summary: None,
            lane: Lane::Fast,
            heavy_lane_diversion_recorded: false,
            ledger: ConservationLedger::new(0.1).expect("ledger"),
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id: "op".to_string(),
            owner_principal_id: "test-owner".to_string(),
            created_at_unix_ms: 1,
            trial_assignment: None,
            trial_commitment_hash: [0u8; 32],
            execution_nonce: 0,
            holdout_pool_scope: HoldoutPoolScope::Global,
            reserved_k_bits: 0.0,
            reserved_access_credit: 0.0,
            reserved_expires_at_unix_ms: 0,
        };
        let err = vault_context(
            &claim,
            default_registry_nullspec().expect("nullspec"),
            &provider,
        )
        .expect_err("hash mismatch should fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "holdout label hash mismatch");
    }

    fn dummy_claim(claim_id: [u8; 32], capsule_hash: Option<[u8; 32]>) -> Claim {
        Claim {
            claim_id,
            topic_id: [0; 32],
            holdout_handle_id: [0; 32],
            holdout_ref: "holdout".to_string(),
            epoch_config_ref: "epoch-a".to_string(),
            holdout_len: 4,
            metadata_locked: false,
            claim_name: "c".to_string(),
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash: [0; 32],
            semantic_hash: [0; 32],
            topic_oracle_receipt: None,
            output_schema_id_hash: [0; 32],
            holdout_handle_hash: [0; 32],
            lineage_root_hash: [0; 32],
            disagreement_score: 0,
            semantic_physhir_distance_bits: 0,
            escalate_to_heavy: false,
            epoch_size: 10,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: None,
            oracle_num_symbols: 4,
            oracle_resolution: OracleResolution::new(4, 0.0).expect("resolution"),
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            dependency_merkle_root: None,
            wasm_module: Vec::new(),
            aspec_rejection: None,
            aspec_report_summary: None,
            lane: Lane::Fast,
            heavy_lane_diversion_recorded: false,
            ledger: ConservationLedger::new(0.1).expect("ledger"),
            last_decision: None,
            last_capsule_hash: capsule_hash,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id: "op".to_string(),
            owner_principal_id: "test-owner".to_string(),
            created_at_unix_ms: 1,
            trial_assignment: None,
            trial_commitment_hash: [0u8; 32],
            execution_nonce: 0,
            holdout_pool_scope: HoldoutPoolScope::Global,
            reserved_k_bits: 0.0,
            reserved_access_credit: 0.0,
            reserved_expires_at_unix_ms: 0,
        }
    }

    #[test]
    fn reservation_sweeper_releases_expired_claim_reservations() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            true,
            telemetry,
        )
        .expect("service");

        let claim_id = [11u8; 32];
        let topic_id = [12u8; 32];
        let holdout_handle_id = [13u8; 32];
        let reserved = 7.0;

        {
            let mut claim = dummy_claim(claim_id, None);
            claim.topic_id = topic_id;
            claim.holdout_handle_id = holdout_handle_id;
            claim.reserved_k_bits = reserved;
            claim.reserved_access_credit = reserved;
            claim.reserved_expires_at_unix_ms = 1;
            svc.state.claims.lock().insert(claim_id, claim);
        }

        {
            let mut topic_pools = svc.state.topic_pools.lock();
            let mut pool = TopicBudgetPool::new("topic".to_string(), 100.0, 100.0).expect("pool");
            pool.reserve(reserved, reserved).expect("reserve");
            topic_pools.insert(topic_id, pool);
        }

        {
            let holdout_keys =
                svc.holdout_pool_keys(holdout_handle_id, "test-owner", HoldoutPoolScope::Global);
            let mut holdout_pools = svc.state.holdout_pools.lock();
            for key in holdout_keys {
                let mut pool = HoldoutBudgetPool::new(key.clone(), 100.0, 100.0).expect("pool");
                pool.reserve(reserved, reserved).expect("reserve");
                holdout_pools.insert(key, pool);
            }
        }

        let swept = svc.sweep_expired_reservations().expect("sweep");
        assert_eq!(swept, 1);

        let claim = svc
            .state
            .claims
            .lock()
            .get(&claim_id)
            .cloned()
            .expect("claim");
        assert_eq!(claim.state, ClaimState::Stale);
        assert_eq!(claim.reserved_k_bits, 0.0);
        assert_eq!(claim.reserved_access_credit, 0.0);
        assert_eq!(claim.reserved_expires_at_unix_ms, 0);

        let topic_pool = svc
            .state
            .topic_pools
            .lock()
            .get(&topic_id)
            .cloned()
            .expect("topic pool");
        assert_eq!(topic_pool.reserved_k_bits(), 0.0);

        let holdout_keys =
            svc.holdout_pool_keys(holdout_handle_id, "test-owner", HoldoutPoolScope::Global);
        let holdout_pools = svc.state.holdout_pools.lock();
        for holdout_key in holdout_keys {
            let holdout_pool = holdout_pools.get(&holdout_key).expect("holdout pool");
            assert_eq!(holdout_pool.reserved_k_bits, 0.0);
            assert_eq!(holdout_pool.reserved_access_credit, 0.0);
        }

        let etl_bytes = std::fs::read(dir.path().join("etl.log")).expect("etl");
        let etl_text = String::from_utf8_lossy(&etl_bytes);
        assert!(etl_text.contains("\"kind\":\"reservation_expired\""));
        assert!(etl_text.contains(&hex::encode(claim_id)));
        assert!(etl_text.contains("\"released_k_bits\":7.0"));
        assert!(etl_text.contains("\"released_access_credit\":7.0"));
    }

    #[test]
    fn reservation_sweeper_skips_unexpired_claims() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            true,
            telemetry,
        )
        .expect("service");

        let claim_id = [21u8; 32];
        let mut claim = dummy_claim(claim_id, None);
        claim.reserved_k_bits = 5.0;
        claim.reserved_access_credit = 5.0;
        claim.reserved_expires_at_unix_ms = u64::MAX;
        svc.state.claims.lock().insert(claim_id, claim);

        let swept = svc.sweep_expired_reservations().expect("sweep");
        assert_eq!(swept, 0);
        let state = svc
            .state
            .claims
            .lock()
            .get(&claim_id)
            .map(|c| c.state)
            .expect("claim");
        assert_eq!(state, ClaimState::Uncommitted);
    }

    #[test]
    fn recover_pending_execute_mutation_replays_claim_state() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            true,
            telemetry,
        )
        .expect("service");

        let claim_id = [7u8; 32];
        svc.state
            .claims
            .lock()
            .insert(claim_id, dummy_claim(claim_id, None));

        let capsule_hash = [9u8; 32];
        let pending = PendingMutation::Execute {
            claim_id,
            state: ClaimState::Certified,
            decision: pb::Decision::Approve as i32,
            capsule_hash,
            capsule_bytes: b"capsule".to_vec(),
            etl_index: Some(3),
        };
        persist_pending_mutation(&svc.state, &pending).expect("persist pending");

        recover_pending_mutations(&svc.state).expect("recover pending");

        let claims = svc.state.claims.lock();
        let claim = claims.get(&claim_id).expect("claim present");
        assert_eq!(claim.state, ClaimState::Certified);
        assert_eq!(claim.last_capsule_hash, Some(capsule_hash));
        assert_eq!(claim.etl_index, Some(3));
        assert_eq!(claim.last_decision, Some(pb::Decision::Approve as i32));
        assert!(!svc
            .state
            .data_path
            .join(PENDING_MUTATIONS_DIR_NAME)
            .join(format!("{}.json", hex::encode(claim_id)))
            .exists());
    }

    #[test]
    fn recover_pending_revoke_mutation_replays_revocation_state() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            true,
            telemetry,
        )
        .expect("service");

        let claim_id = [1u8; 32];
        let tainted_id = [2u8; 32];
        let capsule_hash = [4u8; 32];
        svc.state
            .claims
            .lock()
            .insert(claim_id, dummy_claim(claim_id, Some(capsule_hash)));
        svc.state
            .claims
            .lock()
            .insert(tainted_id, dummy_claim(tainted_id, Some([5u8; 32])));

        let pending = PendingMutation::Revoke {
            claim_id,
            capsule_hash,
            reason: "incident".to_string(),
            timestamp_unix: 42,
            tainted_claim_ids: vec![tainted_id],
            etl_applied: true,
        };
        persist_pending_mutation(&svc.state, &pending).expect("persist pending");

        recover_pending_mutations(&svc.state).expect("recover pending");

        let claims = svc.state.claims.lock();
        assert_eq!(
            claims.get(&claim_id).expect("claim").state,
            ClaimState::Revoked
        );
        assert_eq!(
            claims.get(&tainted_id).expect("tainted").state,
            ClaimState::Tainted
        );
        drop(claims);

        let revocations = svc.state.revocations.lock();
        assert!(revocations
            .iter()
            .any(|(hash, ts, reason)| *hash == capsule_hash && *ts == 42 && reason == "incident"));
        assert!(!svc
            .state
            .data_path
            .join(PENDING_MUTATIONS_DIR_NAME)
            .join(format!("{}.json", hex::encode(claim_id)))
            .exists());
    }

    #[test]
    fn persist_pending_mutation_uses_per_claim_wal_files_under_concurrency() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = Arc::new(
            EvidenceOsService::build_with_options(
                dir.path().to_str().expect("utf8"),
                true,
                telemetry,
            )
            .expect("service"),
        );

        let pending_a = PendingMutation::Execute {
            claim_id: [11u8; 32],
            state: ClaimState::Certified,
            decision: pb::Decision::Approve as i32,
            capsule_hash: [21u8; 32],
            capsule_bytes: b"capsule-a".to_vec(),
            etl_index: Some(1),
        };
        let pending_b = PendingMutation::Execute {
            claim_id: [12u8; 32],
            state: ClaimState::Revoked,
            decision: pb::Decision::Reject as i32,
            capsule_hash: [22u8; 32],
            capsule_bytes: b"capsule-b".to_vec(),
            etl_index: Some(2),
        };

        let svc_a = Arc::clone(&svc);
        let t1 = std::thread::spawn(move || persist_pending_mutation(&svc_a.state, &pending_a));
        let svc_b = Arc::clone(&svc);
        let t2 = std::thread::spawn(move || persist_pending_mutation(&svc_b.state, &pending_b));

        t1.join().expect("join a").expect("persist a");
        t2.join().expect("join b").expect("persist b");

        let wal_dir = svc.state.data_path.join(PENDING_MUTATIONS_DIR_NAME);
        let mut files = std::fs::read_dir(&wal_dir)
            .expect("read wal dir")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn recover_pending_execute_after_commit_before_cleanup_is_idempotent_and_cleans_wal() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            true,
            telemetry,
        )
        .expect("service");

        let claim_id = [13u8; 32];
        let capsule_hash = [31u8; 32];
        let mut claim = dummy_claim(claim_id, Some(capsule_hash));
        claim.state = ClaimState::Certified;
        claim.last_decision = Some(pb::Decision::Approve as i32);
        claim.etl_index = Some(5);
        claim.capsule_bytes = Some(b"capsule".to_vec());
        svc.state.claims.lock().insert(claim_id, claim);

        let pending = PendingMutation::Execute {
            claim_id,
            state: ClaimState::Certified,
            decision: pb::Decision::Approve as i32,
            capsule_hash,
            capsule_bytes: b"capsule".to_vec(),
            etl_index: Some(5),
        };
        persist_pending_mutation(&svc.state, &pending).expect("persist pending");

        recover_pending_mutations(&svc.state).expect("recover");
        recover_pending_mutations(&svc.state).expect("recover second");

        assert!(!pending_mutation_path_for_claim(&svc.state.data_path, claim_id).exists());
        let claim = svc
            .state
            .claims
            .lock()
            .get(&claim_id)
            .cloned()
            .expect("claim");
        assert_eq!(claim.state, ClaimState::Certified);
        assert_eq!(claim.last_decision, Some(pb::Decision::Approve as i32));
    }
    #[test]
    fn tee_backend_populates_capsule_environment_attestations() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock");

        std::env::set_var("EVIDENCEOS_TEE_BACKEND", "noop");
        std::env::set_var("EVIDENCEOS_TEE_ALLOW_NOOP", "1");
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let ledger = ConservationLedger::new(0.05).expect("ledger");
        let mut capsule = ClaimCapsule::new(
            "c".into(),
            "t".into(),
            "schema".into(),
            Vec::new(),
            Vec::new(),
            b"output",
            b"wasm-bytes",
            b"holdout",
            &ledger,
            1.0,
            false,
            pb::Decision::Approve as i32,
            Vec::new(),
            Vec::new(),
            b"trace",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            0.0,
        );

        svc.populate_tee_attestation(&mut capsule, b"wasm-bytes")
            .expect("tee attestation");

        assert_eq!(
            capsule.environment_attestations.tee_backend_name.as_deref(),
            Some("noop")
        );
        assert!(capsule
            .environment_attestations
            .tee_measurement_hex
            .as_deref()
            .is_some_and(|v| v.len() == 64));
        assert!(capsule
            .environment_attestations
            .tee_attestation_blob_b64
            .as_deref()
            .is_some_and(|v| !v.is_empty()));

        std::env::remove_var("EVIDENCEOS_TEE_BACKEND");
        std::env::remove_var("EVIDENCEOS_TEE_ALLOW_NOOP");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn create_claim_v2_ignores_client_topic_signal_hints_for_topic_pooling() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock");

        std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let mut req_a = claim_request("synthetic-holdout");
        req_a.claim_name = "pool-claim".to_string();
        req_a.signals.as_mut().expect("signals").semantic_hash = vec![7; 32];

        let mut req_b = claim_request("synthetic-holdout");
        req_b.claim_name = "pool-claim".to_string();
        req_b.signals.as_mut().expect("signals").semantic_hash = vec![201; 32];

        let created_a =
            <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req_a))
                .await
                .expect("create a")
                .into_inner();
        let created_b =
            <EvidenceOsService as EvidenceOsV2>::create_claim_v2(&svc, Request::new(req_b))
                .await
                .expect("create b")
                .into_inner();

        assert_eq!(created_a.topic_id, created_b.topic_id);
        assert_eq!(svc.state.topic_pools.lock().len(), 1);

        let claims = svc.state.claims.lock();
        let claim_a = claims
            .get(&parse_hash32(&created_a.claim_id, "claim_id").expect("claim id"))
            .expect("claim a present");
        let claim_b = claims
            .get(&parse_hash32(&created_b.claim_id, "claim_id").expect("claim id"))
            .expect("claim b present");
        assert_eq!(claim_a.semantic_hash, claim_b.semantic_hash);
        assert!(claim_a.topic_oracle_receipt.is_some());

        std::env::remove_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn synthetic_holdout_only_works_when_explicitly_enabled() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock");

        std::env::remove_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT");
        let strict_dir = TempDir::new().expect("tmp");
        let strict_telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let strict_svc = EvidenceOsService::build_with_options(
            strict_dir.path().to_str().expect("utf8"),
            false,
            strict_telemetry,
        )
        .expect("strict service");
        let strict_err = <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &strict_svc,
            Request::new(claim_request("synthetic-holdout")),
        )
        .await
        .expect_err("strict mode should reject synthetic holdout");
        assert_eq!(strict_err.code(), Code::InvalidArgument);

        std::env::set_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", "1");
        let insecure_dir = TempDir::new().expect("tmp");
        let insecure_telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let insecure_svc = EvidenceOsService::build_with_options(
            insecure_dir.path().to_str().expect("utf8"),
            false,
            insecure_telemetry,
        )
        .expect("insecure service");
        <EvidenceOsService as EvidenceOsV2>::create_claim_v2(
            &insecure_svc,
            Request::new(claim_request("synthetic-holdout")),
        )
        .await
        .expect("insecure synthetic holdout should be accepted");
        std::env::remove_var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT");
    }

    #[test]
    fn strict_pln_padding_applies_minimum_floor() {
        let elapsed = Duration::from_millis(3);
        let pad = strict_pln_padding_duration(elapsed, 10).expect("pad");
        assert!(pad >= Duration::from_millis(7));
        assert!(strict_pln_padding_duration(Duration::from_millis(12), 10).is_none());
    }

    #[tokio::test]
    async fn golden_execute_claim_capsule_hash_and_etl_index_stable() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            true,
            telemetry,
        )
        .expect("service");

        let created = <EvidenceOsService as EvidenceOsV2>::create_claim(
            &svc,
            Request::new(pb::CreateClaimRequest {
                topic_id: vec![5; 32],
                holdout_handle_id: vec![6; 32],
                phys_hir_hash: vec![7; 32],
                oracle_num_symbols: 4,
                alpha: 0.05,
                epoch_size: 16,
                access_credit: 64,
            }),
        )
        .await
        .expect("create")
        .into_inner();

        let wasm_hash = sha256_bytes(BURN_WASM_MODULE).to_vec();
        <EvidenceOsService as EvidenceOsV2>::commit_artifacts(
            &svc,
            Request::new(pb::CommitArtifactsRequest {
                claim_id: created.claim_id.clone(),
                artifacts: vec![pb::Artifact {
                    artifact_hash: wasm_hash,
                    kind: "wasm".to_string(),
                }],
                wasm_module: BURN_WASM_MODULE.to_vec(),
            }),
        )
        .await
        .expect("commit");

        <EvidenceOsService as EvidenceOsV2>::seal_claim(
            &svc,
            Request::new(pb::SealClaimRequest {
                claim_id: created.claim_id.clone(),
            }),
        )
        .await
        .expect("seal");

        let executed = <EvidenceOsService as EvidenceOsV2>::execute_claim(
            &svc,
            Request::new(pb::ExecuteClaimRequest {
                claim_id: created.claim_id,
                canonical_output: Vec::new(),
                reason_codes: Vec::new(),
                decision: pb::Decision::Approve as i32,
            }),
        )
        .await
        .expect("execute")
        .into_inner();

        let dir_2 = TempDir::new().expect("tmp");
        let telemetry_2 = Arc::new(Telemetry::new().expect("telemetry"));
        let svc_2 = EvidenceOsService::build_with_options(
            dir_2.path().to_str().expect("utf8"),
            true,
            telemetry_2,
        )
        .expect("service");
        let created_2 = <EvidenceOsService as EvidenceOsV2>::create_claim(
            &svc_2,
            Request::new(pb::CreateClaimRequest {
                topic_id: vec![5; 32],
                holdout_handle_id: vec![6; 32],
                phys_hir_hash: vec![7; 32],
                oracle_num_symbols: 4,
                alpha: 0.05,
                epoch_size: 16,
                access_credit: 64,
            }),
        )
        .await
        .expect("create")
        .into_inner();
        <EvidenceOsService as EvidenceOsV2>::commit_artifacts(
            &svc_2,
            Request::new(pb::CommitArtifactsRequest {
                claim_id: created_2.claim_id.clone(),
                artifacts: vec![pb::Artifact {
                    artifact_hash: sha256_bytes(BURN_WASM_MODULE).to_vec(),
                    kind: "wasm".to_string(),
                }],
                wasm_module: BURN_WASM_MODULE.to_vec(),
            }),
        )
        .await
        .expect("commit");
        <EvidenceOsService as EvidenceOsV2>::seal_claim(
            &svc_2,
            Request::new(pb::SealClaimRequest {
                claim_id: created_2.claim_id.clone(),
            }),
        )
        .await
        .expect("seal");
        let executed_2 = <EvidenceOsService as EvidenceOsV2>::execute_claim(
            &svc_2,
            Request::new(pb::ExecuteClaimRequest {
                claim_id: created_2.claim_id,
                canonical_output: Vec::new(),
                reason_codes: Vec::new(),
                decision: pb::Decision::Approve as i32,
            }),
        )
        .await
        .expect("execute")
        .into_inner();

        assert_eq!(executed.capsule_hash, executed_2.capsule_hash);
        assert_eq!(executed.etl_index, executed_2.etl_index);
    }

    #[test]
    fn nullspec_e_value_parametric_bernoulli_matches_reference() {
        let mut contract = SignedNullSpecContractV1 {
            schema: NULLSPEC_SCHEMA_V1.to_string(),
            nullspec_id: [0; 32],
            oracle_id: "builtin.accuracy".to_string(),
            oracle_resolution_hash: [0; 32],
            holdout_handle: "h1".to_string(),
            epoch_created: 0,
            ttl_epochs: 10,
            kind: NullSpecKind::ParametricBernoulli { p: 0.4 },
            eprocess: EProcessKind::LikelihoodRatioFixedAlt {
                alt: vec![0.3, 0.7],
            },
            calibration_manifest_hash: None,
            created_by: "test".to_string(),
            signature_ed25519: vec![0; 64],
        };
        contract.nullspec_id = contract.compute_id().expect("compute id");

        let (e, kind) = compute_nullspec_e_value(&contract, &[1, 0, 1]).expect("compute e-value");
        assert_eq!(kind, "likelihood_ratio_fixed_alt");
        assert!((e - 1.53125).abs() < 1e-12);
    }

    #[test]
    fn nullspec_e_value_dirichlet_matches_reference() {
        let mut contract = SignedNullSpecContractV1 {
            schema: NULLSPEC_SCHEMA_V1.to_string(),
            nullspec_id: [0; 32],
            oracle_id: "builtin.accuracy".to_string(),
            oracle_resolution_hash: [0; 32],
            holdout_handle: "h1".to_string(),
            epoch_created: 0,
            ttl_epochs: 10,
            kind: NullSpecKind::DiscreteBuckets {
                p0: vec![0.2, 0.3, 0.5],
            },
            eprocess: EProcessKind::DirichletMultinomialMixture {
                alpha: vec![1.0, 1.0, 1.0],
            },
            calibration_manifest_hash: None,
            created_by: "test".to_string(),
            signature_ed25519: vec![0; 64],
        };
        contract.nullspec_id = contract.compute_id().expect("compute id");

        let (e, kind) = compute_nullspec_e_value(&contract, &[2, 1, 2]).expect("compute e-value");
        assert_eq!(kind, "dirichlet_multinomial_mixture");
        assert!((e - (4.0 / 9.0)).abs() < 1e-12);
    }
}
