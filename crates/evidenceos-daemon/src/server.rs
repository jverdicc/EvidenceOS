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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
use evidenceos_core::capsule::{
    ClaimCapsule, ClaimState as CoreClaimState, ManifestEntry, TopicOracleReceiptLike,
};
use evidenceos_core::crypto_transcripts::{revocations_snapshot_digest, sth_signature_digest};
use evidenceos_core::dlc::{DeterministicLogicalClock, DlcConfig};
use evidenceos_core::eprocess::DirichletMixtureEProcess;
use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};
use evidenceos_core::holdout_crypto::{decrypt_holdout_labels, EnvKeyProvider, HoldoutKeyProvider};
use evidenceos_core::ledger::{ConservationLedger, TopicBudgetPool};
use evidenceos_core::nullspec::{EProcessKind, NullSpecKind};
use evidenceos_core::nullspec_contract::NullSpecContractV1 as RegistryNullSpecContractV1;
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
const DOMAIN_CLAIM_ID: &[u8] = b"evidenceos:claim_id:v2";
const DOMAIN_TOPIC_MANIFEST_HASH_V1: &[u8] = b"evidenceos:topic_manifest_hash:v1";
const DOMAIN_TOPIC_ORACLE_RECEIPT_V1: &[u8] = b"evidenceos:topic_oracle_receipt:v1";
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
struct HoldoutDescriptor {
    holdout_ref: String,
    handle: [u8; 32],
    len: usize,
    labels_hash: [u8; 32],
    encryption_key_id: Option<String>,
}

trait HoldoutProvider: Send + Sync {
    fn resolve(&self, holdout_ref: &str) -> Result<HoldoutDescriptor, Status>;
    fn load_labels(&self, descriptor: &HoldoutDescriptor) -> Result<Vec<u8>, Status>;
}

#[derive(Debug, Clone, Deserialize)]
struct HoldoutManifest {
    holdout_handle_hex: String,
    len: usize,
    labels_sha256_hex: String,
    created_at_unix: u64,
    schema_version: u32,
    encryption_key_id: Option<String>,
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
        let manifest: HoldoutManifest = serde_json::from_slice(&bytes)
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
        Ok(HoldoutDescriptor {
            holdout_ref: holdout_ref.to_string(),
            handle,
            len: manifest.len,
            labels_hash,
            encryption_key_id: manifest.encryption_key_id,
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
    holdout_pools: Vec<([u8; 32], HoldoutBudgetPool)>,
    canary_states: Vec<(String, CanaryState)>,
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

type RevocationSubscriber = mpsc::Sender<pb::WatchRevocationsResponse>;

const ORACLE_EXPIRED_REASON_CODE: u32 = 9202;
const ORACLE_TTL_ESCALATED_REASON_CODE: u32 = 9203;
const MAGNITUDE_ENVELOPE_REASON_CODE: u32 = 9205;
const LEDGER_NUMERIC_GUARD_REASON_CODE: u32 = 9206;

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
    nullspec_registry_state: Mutex<NullSpecRegistryState>,
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
            nullspec_registry_state: Mutex::new(NullSpecRegistryState {
                registry_dir: nullspec_config.registry_dir,
                authority_keys_dir: nullspec_config.authority_keys_dir,
                keyring: Arc::new(nullspec_keyring),
                registry: Arc::new(nullspec_registry),
                healthy: nullspec_healthy,
                last_reload_attempt: Instant::now(),
                reload_interval: nullspec_config.reload_interval,
            }),
        });
        recover_pending_mutation(&state)?;
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
                Status::invalid_argument(format!("tee backend configuration error: {e:?}"))
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
        })
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
        current_logical_epoch(claim)
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
        let pinned_epoch = self.current_epoch_for_claim(claim)?;
        let ttl_epochs = self.oracle_ttl_for_claim(claim);
        let oracle_id = claim.oracle_id.clone();
        let calibration_hash = {
            let operator_config = self.state.operator_config.lock();
            match operator_config.oracle_calibration_hash.get(&oracle_id) {
                Some(v) => decode_hex_hash32(v, "calibration_manifest_hash_hex")?,
                None => {
                    if self.enforce_operator_provenance {
                        return Err(Status::failed_precondition(
                            "missing oracle calibration manifest hash",
                        ));
                    }
                    claim.oracle_resolution.calibration_manifest_hash
                }
            }
        };
        claim.oracle_resolution = claim
            .oracle_resolution
            .with_calibration(calibration_hash, pinned_epoch);
        claim.oracle_resolution.ttl_epochs = Some(ttl_epochs);
        let resolution_hash = oracle_resolution_hash(&claim.oracle_resolution)?;
        let oracle_pins = OraclePins {
            codec_hash: sha256_bytes(b"evidenceos.oracle.codec.v1"),
            bit_width,
            ttl_epochs,
            pinned_epoch,
            oracle_resolution_hash: resolution_hash,
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

const STATE_FILE_NAME: &str = "state.json";
const PENDING_MUTATION_FILE_NAME: &str = "pending_mutation.json";

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
    write_file_atomic_durable(
        &state.data_path.join(STATE_FILE_NAME),
        &bytes,
        "write state failed",
    )
}

fn persist_pending_mutation(state: &KernelState, pending: &PendingMutation) -> Result<(), Status> {
    let bytes = serde_json::to_vec_pretty(pending)
        .map_err(|_| Status::internal("serialize pending mutation failed"))?;
    write_file_atomic_durable(
        &state.data_path.join(PENDING_MUTATION_FILE_NAME),
        &bytes,
        "write pending mutation failed",
    )
}

fn clear_pending_mutation(state: &KernelState) -> Result<(), Status> {
    remove_file_durable(&state.data_path.join(PENDING_MUTATION_FILE_NAME))
}

fn recover_pending_mutation(state: &KernelState) -> Result<(), Status> {
    let path = state.data_path.join(PENDING_MUTATION_FILE_NAME);
    if !path.exists() {
        return Ok(());
    }
    let bytes =
        std::fs::read(&path).map_err(|_| Status::internal("read pending mutation failed"))?;
    let pending: PendingMutation = serde_json::from_slice(&bytes)
        .map_err(|_| Status::internal("decode pending mutation failed"))?;

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
    clear_pending_mutation(state)?;
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
        "alpha_micros": (ledger.alpha * 1_000_000.0).round() as u32,
        "log_alpha_target": ledger.log_alpha_target(),
        "log_alpha_prime": ledger.log_alpha_prime(),
        "barrier_threshold": ledger.barrier_threshold(),
        "canonical_output_len": canonical_output.len() as u32,
        "canonical_output_sha256": hex::encode(sha256_bytes(canonical_output)),
        "claim_id": hex::encode(claim.claim_id),
        "epoch": claim.epoch_counter,
        "fuel_used": fuel_total,
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

    async fn get_server_info(
        &self,
        _request: Request<pb::GetServerInfoRequest>,
    ) -> Result<Response<pb::GetServerInfoResponse>, Status> {
        Ok(Response::new(pb::GetServerInfoResponse {
            protocol_semver: evidenceos_protocol::PROTOCOL_SEMVER.to_string(),
            proto_hash: evidenceos_protocol::PROTO_SHA256.to_string(),
            build_git_commit: BUILD_GIT_COMMIT.to_string(),
            build_time_utc: BUILD_TIME_UTC.to_string(),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            feature_flags: Some(self.protocol_feature_flags()),
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
            epoch_config_ref: "legacy-v1".to_string(),
            holdout_len: req.epoch_size,
            metadata_locked: false,
            claim_name: "legacy-v1".to_string(),
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash,
            semantic_hash: [0u8; 32],
            topic_oracle_receipt: None,
            output_schema_id_hash: hash_signal(b"evidenceos/schema_id", b"legacy/v1"),
            holdout_handle_hash: hash_signal(b"evidenceos/holdout_handle", &holdout_handle_id),
            lineage_root_hash: topic_id,
            disagreement_score: 0,
            semantic_physhir_distance_bits: 0,
            escalate_to_heavy: false,
            epoch_size: req.epoch_size,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: None,
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

    async fn freeze(
        &self,
        request: Request<pb::FreezeRequest>,
    ) -> Result<Response<pb::FreezeResponse>, Status> {
        let req = request.into_inner();
        let response = <Self as EvidenceOsV2>::freeze_gates(
            self,
            Request::new(pb::FreezeGatesRequest {
                claim_id: req.claim_id,
            }),
        )
        .await?;
        Ok(Response::new(pb::FreezeResponse {
            state: response.into_inner().state,
        }))
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

    async fn seal(
        &self,
        request: Request<pb::SealRequest>,
    ) -> Result<Response<pb::SealResponse>, Status> {
        let req = request.into_inner();
        let response = <Self as EvidenceOsV2>::seal_claim(
            self,
            Request::new(pb::SealClaimRequest {
                claim_id: req.claim_id,
            }),
        )
        .await?;
        Ok(Response::new(pb::SealResponse {
            state: response.into_inner().state,
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

        let (capsule_hash, etl_index, state, decision, claim_id, capsule_bytes) = {
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
            let context = vault_context(
                claim,
                default_registry_nullspec()?,
                self.holdout_provider.as_ref(),
            )?;
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
            let epoch_budget = claim.epoch_size;
            let fuel_total = padded_fuel_total(epoch_budget, fuel_used, claim.pln_config.as_ref())?;
            let padding_fuel = fuel_total.saturating_sub(fuel_used);
            burn_padding_fuel(&vault, &context, padding_fuel)?;
            claim.dlc_fuel_accumulated = claim.dlc_fuel_accumulated.saturating_add(fuel_total);
            claim.epoch_counter = current_logical_epoch(claim)?;
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
                fuel_total as f64,
            );
            self.populate_tee_attestation(&mut capsule, &claim.wasm_module)?;
            capsule.semantic_hash_hex = Some(hex::encode(claim.semantic_hash));
            capsule.physhir_hash_hex = Some(hex::encode(claim.phys_hir_hash));
            capsule.lineage_root_hash_hex = Some(hex::encode(claim.lineage_root_hash));
            capsule.output_schema_id_hash_hex = Some(hex::encode(claim.output_schema_id_hash));
            capsule.holdout_handle_hash_hex = Some(hex::encode(claim.holdout_handle_hash));
            capsule.disagreement_score = Some(claim.disagreement_score);
            capsule.semantic_physhir_distance_bits = Some(claim.semantic_physhir_distance_bits);
            capsule.escalate_to_heavy = Some(claim.escalate_to_heavy);
            capsule.topic_oracle_receipt =
                claim
                    .topic_oracle_receipt
                    .as_ref()
                    .map(|receipt| TopicOracleReceiptLike {
                        claim_manifest_hash_hex: hex::encode(receipt.claim_manifest_hash),
                        semantic_hash_hex: hex::encode(receipt.semantic_hash),
                        model_id: receipt.model_id.clone(),
                        timestamp_unix: receipt.timestamp_unix,
                        signature_hex: hex::encode(&receipt.signature),
                    });
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
                etl.sync_data()
                    .map_err(|_| Status::internal("etl sync failed"))?;
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
            claim.capsule_bytes = Some(capsule_bytes.clone());
            claim.etl_index = Some(etl_index);
            (
                capsule_hash,
                etl_index,
                claim.state,
                req.decision,
                claim.claim_id,
                capsule_bytes,
            )
        };

        let pending = PendingMutation::Execute {
            claim_id,
            state,
            decision,
            capsule_hash,
            capsule_bytes,
            etl_index: Some(etl_index),
        };
        persist_pending_mutation(&self.state, &pending)?;
        maybe_abort_failpoint("after_etl_append_execute_claim");
        persist_all(&self.state)?;
        clear_pending_mutation(&self.state)?;

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
        let oracle_id = if req.oracle_id.trim().is_empty() {
            "builtin.accuracy".to_string()
        } else {
            req.oracle_id.trim().to_string()
        };
        validate_required_str_field(&oracle_id, "oracle_id", 128)?;
        {
            let operator_config = self.state.operator_config.lock();
            if !operator_config.oracle_ttl_epochs.is_empty()
                && !operator_config.oracle_ttl_epochs.contains_key(&oracle_id)
            {
                return Err(Status::invalid_argument("unknown oracle_id"));
            }
        }
        let nullspec_id = req.nullspec_id.trim().to_string();
        if !nullspec_id.is_empty() {
            validate_required_str_field(&nullspec_id, "nullspec_id", 128)?;
        }
        if req.epoch_size == 0 {
            return Err(Status::invalid_argument("epoch_size must be > 0"));
        }
        let holdout_descriptor = self.holdout_provider.resolve(&req.holdout_ref)?;
        let metadata = req
            .metadata
            .ok_or_else(|| Status::invalid_argument("metadata is required"))?;
        let epoch_config_ref = metadata.epoch_config_ref.clone();
        validate_required_str_field(
            &epoch_config_ref,
            "metadata.epoch_config_ref",
            MAX_METADATA_FIELD_LEN,
        )?;
        let (dlc_cfg, pln_cfg) =
            load_epoch_runtime_config(&self.state.data_path, &epoch_config_ref, req.epoch_size)?;
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
        let signals_hint = req.signals.as_ref();
        if let Some(signals) = signals_hint {
            if !signals.phys_hir_signature_hash.is_empty()
                && signals.phys_hir_signature_hash.len() != 32
            {
                return Err(Status::invalid_argument(
                    "signals.phys_hir_signature_hash must be 0 or 32 bytes",
                ));
            }
            if !signals.semantic_hash.is_empty() && signals.semantic_hash.len() != 32 {
                return Err(Status::invalid_argument(
                    "signals.semantic_hash must be 0 or 32 bytes",
                ));
            }
            if !signals.dependency_merkle_root.is_empty()
                && signals.dependency_merkle_root.len() != 32
            {
                return Err(Status::invalid_argument(
                    "signals.dependency_merkle_root must be 0 or 32 bytes",
                ));
            }
        }
        let dependency_merkle_root = signals_hint.and_then(|signals| {
            if signals.dependency_merkle_root.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&signals.dependency_merkle_root);
                Some(b)
            } else {
                None
            }
        });
        let holdout_handle_id = holdout_descriptor.handle;
        let topic_manifest = TopicManifestForHash {
            claim_name: req.claim_name.clone(),
            epoch_config_ref: epoch_config_ref.clone(),
            output_schema_id: canonical_output_schema_id.clone(),
            holdout_ref: req.holdout_ref.clone(),
            holdout_handle_hex: hex::encode(holdout_handle_id),
            nullspec_id_hex: None,
            wasm_code_hash_hex: hex::encode([0u8; 32]),
            oracle_num_symbols: req.oracle_num_symbols,
            epoch_size: dlc_cfg.epoch_size,
        };
        let claim_manifest_hash = compute_topic_manifest_hash(&topic_manifest)?;
        let semantic_hash = derive_server_topic_semantic_hash(claim_manifest_hash);
        let phys =
            derive_server_topic_physhir_hash(claim_manifest_hash, &canonical_output_schema_id);
        let topic_oracle_receipt = build_topic_oracle_receipt(
            self.active_signing_key()?,
            claim_manifest_hash,
            semantic_hash,
            "deterministic.manifest.v1",
        );
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
                epoch_config_ref: epoch_config_ref.clone(),
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
        let claim_pln_cfg = claim_pln_config(lane, &pln_cfg)?;
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
        id_payload.extend_from_slice(&dlc_cfg.epoch_size.to_be_bytes());
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
            hex::encode(semantic_hash),
        )?;
        let claim = Claim {
            claim_id,
            topic_id: topic.topic_id,
            dependency_merkle_root,
            holdout_handle_id,
            holdout_ref: req.holdout_ref,
            epoch_config_ref,
            holdout_len: holdout_descriptor.len as u64,
            metadata_locked: false,
            claim_name: req.claim_name,
            oracle_id,
            nullspec_id,
            output_schema_id: canonical_output_schema_id,
            phys_hir_hash: phys,
            semantic_hash,
            topic_oracle_receipt: Some(topic_oracle_receipt),
            output_schema_id_hash,
            holdout_handle_hash,
            lineage_root_hash,
            disagreement_score: topic.disagreement_score,
            semantic_physhir_distance_bits: topic.semantic_physhir_distance_bits,
            escalate_to_heavy: topic.escalate_to_heavy,
            epoch_size: dlc_cfg.epoch_size,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: Some(claim_pln_cfg),
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
            claim_id,
            capsule_bytes,
            stored_etl_index,
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
            let pins = claim
                .oracle_pins
                .as_ref()
                .ok_or_else(|| Status::failed_precondition("oracle pins missing"))?;
            let current_resolution_hash = oracle_resolution_hash(&claim.oracle_resolution)?;
            if pins.oracle_resolution_hash != current_resolution_hash {
                self.record_incident(claim, "oracle_resolution_pins_mismatch")?;
                return Err(Status::failed_precondition(
                    "oracle resolution hash mismatch with sealed pins",
                ));
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
            let active_id = if claim.nullspec_id.is_empty() {
                match nullspec_store
                    .active_for(&claim.claim_name, &claim.holdout_ref)
                    .map_err(|_| Status::internal("nullspec mapping read failed"))?
                {
                    Some(id) => id,
                    None => {
                        self.record_incident(claim, "nullspec_missing")?;
                        return Err(Status::failed_precondition("missing active nullspec"));
                    }
                }
            } else {
                let decoded = hex::decode(&claim.nullspec_id)
                    .map_err(|_| Status::invalid_argument("invalid nullspec_id hex"))?;
                decoded
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid nullspec_id length"))?
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
            if let Some(contract_calibration_hash) = contract.calibration_manifest_hash {
                if contract_calibration_hash != claim.oracle_resolution.calibration_manifest_hash {
                    self.record_incident(claim, "nullspec_calibration_hash_mismatch")?;
                    return Err(Status::failed_precondition(
                        "nullspec calibration hash mismatch",
                    ));
                }
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
            let registry = self.ensure_nullspec_registry_fresh()?;
            let reg_nullspec = registry
                .get(&hex::encode(contract.nullspec_id))
                .cloned()
                .ok_or_else(|| Status::failed_precondition("active nullspec id not in registry"))?;
            let context = vault_context(claim, reg_nullspec, self.holdout_provider.as_ref())?;
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
            let epoch_budget = claim.epoch_size;
            let fuel_total = padded_fuel_total(epoch_budget, fuel_used, claim.pln_config.as_ref())?;
            let padding_fuel = fuel_total.saturating_sub(fuel_used);
            burn_padding_fuel(&vault, &context, padding_fuel)?;
            claim.dlc_fuel_accumulated = claim.dlc_fuel_accumulated.saturating_add(fuel_total);
            claim.epoch_counter = current_logical_epoch(claim)?;
            let trace_hash = vault_result.judge_trace_hash;
            if claim.output_schema_id == structured_claims::LEGACY_SCHEMA_ID {
                let _sym = decode_canonical_symbol(&canonical_output, claim.oracle_num_symbols)?;
            }
            let mut physhir_mismatch = false;
            let mut magnitude_envelope_violation = false;
            if claim.output_schema_id != structured_claims::LEGACY_SCHEMA_ID {
                if let Ok(validated) = structured_claims::validate_and_canonicalize(
                    &claim.output_schema_id,
                    &canonical_output,
                ) {
                    magnitude_envelope_violation = validated.envelope_violation.is_some();
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
            let ledger_numeric_guard_failure = claim.ledger.certification_guard_failure();
            let can_certify = claim.ledger.can_certify();
            let mut decision = if claim.ledger.frozen
                || ledger_numeric_guard_failure.is_some()
                || claim.lane == Lane::Heavy
                || physhir_mismatch
                || magnitude_envelope_violation
            {
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
            if magnitude_envelope_violation {
                reason_codes.push(MAGNITUDE_ENVELOPE_REASON_CODE);
            }
            if ledger_numeric_guard_failure.is_some() {
                reason_codes.push(LEDGER_NUMERIC_GUARD_REASON_CODE);
            }
            let oracle_input = policy_oracle_input_json(
                claim,
                &vault_result,
                fuel_total,
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
                fuel_total as f64,
            );
            self.populate_tee_attestation(&mut capsule, &claim.wasm_module)?;
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
            capsule.topic_oracle_receipt =
                claim
                    .topic_oracle_receipt
                    .as_ref()
                    .map(|receipt| TopicOracleReceiptLike {
                        claim_manifest_hash_hex: hex::encode(receipt.claim_manifest_hash),
                        semantic_hash_hex: hex::encode(receipt.semantic_hash),
                        model_id: receipt.model_id.clone(),
                        timestamp_unix: receipt.timestamp_unix,
                        signature_hex: hex::encode(&receipt.signature),
                    });
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
                etl.sync_data()
                    .map_err(|_| Status::internal("etl sync failed"))?;
                idx
            };
            claim.last_decision = Some(decision);
            claim.last_capsule_hash = Some(capsule_hash);
            claim.capsule_bytes = Some(capsule_bytes.clone());
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
                claim.claim_id,
                capsule_bytes,
                claim.etl_index,
            )
        };
        let pending = PendingMutation::Execute {
            claim_id,
            state,
            decision,
            capsule_hash,
            capsule_bytes,
            etl_index: stored_etl_index,
        };
        persist_pending_mutation(&self.state, &pending)?;
        maybe_abort_failpoint("after_etl_append_execute_claim_v2");
        persist_all(&self.state)?;
        clear_pending_mutation(&self.state)?;

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

        let mut tainted_claim_ids = Vec::new();
        {
            let mut etl = self.state.etl.lock();
            etl.revoke(&hex::encode(capsule_hash), &req.reason)
                .map_err(|_| Status::internal("etl revoke failed"))?;
            etl.sync_data()
                .map_err(|_| Status::internal("etl sync failed"))?;
            let tainted = etl.taint_descendants(&hex::encode(capsule_hash));
            if !tainted.is_empty() {
                let mut claims = self.state.claims.lock();
                for claim in claims.values_mut() {
                    if let Some(hash) = claim.last_capsule_hash {
                        let hash_hex = hex::encode(hash);
                        if tainted.iter().any(|t| t == &hash_hex) {
                            claim.state = ClaimState::Tainted;
                            tainted_claim_ids.push(claim.claim_id);
                        }
                    }
                }
            }
        }

        self.state
            .revocations
            .lock()
            .push((capsule_hash, timestamp_unix, req.reason.clone()));

        let pending = PendingMutation::Revoke {
            claim_id,
            capsule_hash,
            reason: req.reason.clone(),
            timestamp_unix,
            tainted_claim_ids,
            etl_applied: true,
        };
        persist_pending_mutation(&self.state, &pending)?;
        maybe_abort_failpoint("after_etl_append_revoke_claim");
        persist_all(&self.state)?;
        clear_pending_mutation(&self.state)?;

        let message = {
            let etl = self.state.etl.lock();
            build_revocations_snapshot(
                self.active_signing_key()?,
                self.state.active_key_id,
                vec![(capsule_hash, timestamp_unix, req.reason)],
                build_signed_tree_head(&etl, self.active_signing_key()?, self.state.active_key_id),
            )?
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
        )?;
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

    async fn get_server_info(
        &self,
        request: Request<v1::GetServerInfoRequest>,
    ) -> Result<Response<v1::GetServerInfoResponse>, Status> {
        let req_v2: v2::GetServerInfoRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::get_server_info(self, Request::new(req_v2)).await?;
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

    async fn freeze(
        &self,
        request: Request<v1::FreezeRequest>,
    ) -> Result<Response<v1::FreezeResponse>, Status> {
        let req_v2: v2::FreezeRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::freeze(self, Request::new(req_v2)).await?;
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

    async fn seal(
        &self,
        request: Request<v1::SealRequest>,
    ) -> Result<Response<v1::SealResponse>, Status> {
        let req_v2: v2::SealRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::seal(self, Request::new(req_v2)).await?;
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
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;
    use tonic::Code;

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
        }
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

        recover_pending_mutation(&svc.state).expect("recover pending");

        let claims = svc.state.claims.lock();
        let claim = claims.get(&claim_id).expect("claim present");
        assert_eq!(claim.state, ClaimState::Certified);
        assert_eq!(claim.last_capsule_hash, Some(capsule_hash));
        assert_eq!(claim.etl_index, Some(3));
        assert_eq!(claim.last_decision, Some(pb::Decision::Approve as i32));
        assert!(!svc
            .state
            .data_path
            .join(PENDING_MUTATION_FILE_NAME)
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

        recover_pending_mutation(&svc.state).expect("recover pending");

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
            .join(PENDING_MUTATION_FILE_NAME)
            .exists());
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
}
