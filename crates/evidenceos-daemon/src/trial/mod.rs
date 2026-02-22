use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use getrandom::getrandom;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tonic::Status;

const DEFAULT_SCHEMA_VERSION: u32 = 1;
const SCALE_PPM_MIN: u32 = 100_000;
const SCALE_PPM_MAX: u32 = 2_000_000;
pub const MAX_INTERVENTION_DESCRIPTOR_BYTES: usize = 4096;
type ArmId = u16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencePolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullSpecPolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputPolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterventionDescriptors {
    pub oracle_policy: OraclePolicyDescriptor,
    pub dependence_policy: DependencePolicyDescriptor,
    pub nullspec_policy: NullSpecPolicyDescriptor,
    pub output_policy: OutputPolicyDescriptor,
}

pub fn canonicalize_descriptor_json(value: &Value) -> Result<Vec<u8>, Status> {
    let bytes = evidenceos_core::capsule::canonical_json(value)
        .map_err(|_| Status::invalid_argument("invalid intervention descriptor"))?;
    if bytes.len() > MAX_INTERVENTION_DESCRIPTOR_BYTES {
        return Err(Status::invalid_argument(
            "intervention descriptor exceeds max size",
        ));
    }
    Ok(bytes)
}

pub fn hash_arm_parameters(value: &Value) -> Result<[u8; 32], Status> {
    let bytes = canonicalize_descriptor_json(value)?;
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    Ok(digest)
}

/// Allowed baseline covariates for stratified randomization.
///
/// These fields are immutable at assignment time and not sourced from mutable DiscOS runtime
/// payloads, preventing adversaries from steering strata by post-hoc request shaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCovariates {
    pub lane: String,
    pub holdout_ref: String,
    pub oracle_id: String,
    pub nullspec_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialAssignment {
    pub trial_nonce: [u8; 16],
    pub arm_id: u16,
    pub intervention_id: String,
    pub intervention_version: String,
    pub arm_parameters_hash: [u8; 32],
    pub descriptors: InterventionDescriptors,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentMode {
    Hashed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialArmConfig {
    pub arm_id: u16,
    pub intervention_id: String,
    pub intervention_version: String,
    pub actions: Vec<InterventionActionConfig>,
    pub descriptors: InterventionDescriptors,
    pub arm_parameters: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialArmsConfig {
    pub arms: Vec<TrialArmConfig>,
    pub assignment_mode: AssignmentMode,
    pub stratify: bool,
    pub block_size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedTrialConfig {
    pub config: TrialArmsConfig,
    pub config_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterventionActionConfig {
    ScaleAlphaPpm { ppm: u32 },
    ScaleAccessCreditPpm { ppm: u32 },
    ScaleKBitsBudgetPpm { ppm: u32 },
    ResetLedgerTotals,
    SetFrozenState { frozen: bool },
}

impl InterventionActionConfig {
    fn into_action(self) -> InterventionAction {
        match self {
            Self::ScaleAlphaPpm { ppm } => InterventionAction::ScaleAlphaPpm(ppm),
            Self::ScaleAccessCreditPpm { ppm } => InterventionAction::ScaleAccessCreditPpm(ppm),
            Self::ScaleKBitsBudgetPpm { ppm } => InterventionAction::ScaleKBitsBudgetPpm(ppm),
            Self::ResetLedgerTotals => InterventionAction::ResetLedgerTotals,
            Self::SetFrozenState { frozen } => InterventionAction::SetFrozenState(frozen),
        }
    }
}

pub fn load_trial_arms_config(path: &Path) -> Result<LoadedTrialConfig, Status> {
    let raw =
        std::fs::read(path).map_err(|_| Status::failed_precondition("trial config read failed"))?;
    let parsed = serde_json::from_slice::<TrialArmsConfig>(&raw)
        .map_err(|_| Status::invalid_argument("invalid trial_arms.json schema"))?;
    validate_trial_arms_config(&parsed)?;
    let canonical = evidenceos_core::capsule::canonical_json(&parsed)
        .map_err(|_| Status::invalid_argument("trial config canonicalization failed"))?;
    let mut h = Sha256::new();
    h.update(canonical);
    let digest = h.finalize();
    let mut config_hash = [0u8; 32];
    config_hash.copy_from_slice(&digest);
    Ok(LoadedTrialConfig {
        config: parsed,
        config_hash,
    })
}

fn validate_trial_arms_config(config: &TrialArmsConfig) -> Result<(), Status> {
    if config.arms.is_empty() {
        return Err(Status::invalid_argument(
            "trial config requires at least one arm",
        ));
    }
    let mut by_arm = HashMap::new();
    for arm in &config.arms {
        if arm.intervention_id.trim().is_empty() || arm.intervention_version.trim().is_empty() {
            return Err(Status::invalid_argument(
                "intervention_id and intervention_version are required",
            ));
        }
        if by_arm.insert(arm.arm_id, ()).is_some() {
            return Err(Status::invalid_argument("duplicate arm_id in trial config"));
        }
        let actions = arm
            .actions
            .clone()
            .into_iter()
            .map(InterventionActionConfig::into_action)
            .collect::<Vec<_>>();
        let _ = validate_and_build_delta(&actions)?;
        let _ = hash_arm_parameters(&arm.arm_parameters)?;
    }
    if matches!(config.assignment_mode, AssignmentMode::Blocked) {
        let block_size = config
            .block_size
            .ok_or_else(|| Status::invalid_argument("block_size is required in blocked mode"))?;
        if block_size == 0 || block_size % config.arms.len() != 0 {
            return Err(Status::invalid_argument(
                "block_size must be > 0 and divisible by number of arms",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ConfigurableIntervention {
    intervention_id: String,
    intervention_version: String,
    actions: Vec<InterventionAction>,
    descriptors: InterventionDescriptors,
    arm_parameters: Value,
}

impl ConfigurableIntervention {
    pub fn from_arm_config(arm: &TrialArmConfig) -> Self {
        Self {
            intervention_id: arm.intervention_id.clone(),
            intervention_version: arm.intervention_version.clone(),
            actions: arm
                .actions
                .clone()
                .into_iter()
                .map(InterventionActionConfig::into_action)
                .collect(),
            descriptors: arm.descriptors.clone(),
            arm_parameters: arm.arm_parameters.clone(),
        }
    }
}

impl EpistemicIntervention for ConfigurableIntervention {
    fn id(&self) -> &str {
        &self.intervention_id
    }

    fn version(&self) -> &str {
        &self.intervention_version
    }

    fn arm_parameters(&self) -> Value {
        self.arm_parameters.clone()
    }

    fn oracle_policy(&self) -> OraclePolicyDescriptor {
        self.descriptors.oracle_policy.clone()
    }

    fn dependence_policy(&self) -> DependencePolicyDescriptor {
        self.descriptors.dependence_policy.clone()
    }

    fn nullspec_policy(&self) -> NullSpecPolicyDescriptor {
        self.descriptors.nullspec_policy.clone()
    }

    fn output_policy(&self) -> OutputPolicyDescriptor {
        self.descriptors.output_policy.clone()
    }

    fn actions(&self) -> Vec<InterventionAction> {
        self.actions.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StratumKey {
    lane: String,
    holdout_family: String,
    oracle_id: String,
    nullspec_id: String,
}

impl StratumKey {
    pub fn from_baseline(covariates: BaselineCovariates) -> Self {
        Self {
            lane: covariates.lane,
            holdout_family: holdout_family(&covariates.holdout_ref),
            oracle_id: covariates.oracle_id,
            nullspec_id: covariates.nullspec_id,
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_tagged(&mut out, self.lane.as_bytes());
        append_tagged(&mut out, self.holdout_family.as_bytes());
        append_tagged(&mut out, self.oracle_id.as_bytes());
        append_tagged(&mut out, self.nullspec_id.as_bytes());
        out
    }
}

impl Default for StratumKey {
    fn default() -> Self {
        Self {
            lane: "unstratified".to_string(),
            holdout_family: "global".to_string(),
            oracle_id: "global".to_string(),
            nullspec_id: "global".to_string(),
        }
    }
}

fn holdout_family(holdout_ref: &str) -> String {
    holdout_ref
        .split(['/', ':'])
        .next()
        .map(str::to_string)
        .unwrap_or_default()
}

fn append_tagged(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub trait EpistemicIntervention: Send + Sync {
    fn id(&self) -> &str;
    fn version(&self) -> &str;
    fn arm_parameters(&self) -> Value;
    fn oracle_policy(&self) -> OraclePolicyDescriptor;
    fn dependence_policy(&self) -> DependencePolicyDescriptor;
    fn nullspec_policy(&self) -> NullSpecPolicyDescriptor;
    fn output_policy(&self) -> OutputPolicyDescriptor;
    fn actions(&self) -> Vec<InterventionAction>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterventionAction {
    ScaleAlphaPpm(u32),
    ScaleAccessCreditPpm(u32),
    ScaleKBitsBudgetPpm(u32),
    ResetLedgerTotals,
    SetFrozenState(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterventionDelta {
    pub alpha_scale_ppm: u32,
    pub access_credit_scale_ppm: u32,
    pub k_bits_scale_ppm: u32,
}

impl Default for InterventionDelta {
    fn default() -> Self {
        Self {
            alpha_scale_ppm: 1_000_000,
            access_credit_scale_ppm: 1_000_000,
            k_bits_scale_ppm: 1_000_000,
        }
    }
}

pub fn validate_and_build_delta(
    actions: &[InterventionAction],
) -> Result<InterventionDelta, Status> {
    let mut delta = InterventionDelta::default();
    for action in actions {
        match action {
            InterventionAction::ScaleAlphaPpm(ppm) => {
                validate_scale_ppm(*ppm, "ScaleAlphaPpm")?;
                delta.alpha_scale_ppm = *ppm;
            }
            InterventionAction::ScaleAccessCreditPpm(ppm) => {
                validate_scale_ppm(*ppm, "ScaleAccessCreditPpm")?;
                delta.access_credit_scale_ppm = *ppm;
            }
            InterventionAction::ScaleKBitsBudgetPpm(ppm) => {
                validate_scale_ppm(*ppm, "ScaleKBitsBudgetPpm")?;
                delta.k_bits_scale_ppm = *ppm;
            }
            InterventionAction::ResetLedgerTotals => {
                return Err(Status::invalid_argument(
                    "interventions may not reset ledger totals",
                ));
            }
            InterventionAction::SetFrozenState(_) => {
                return Err(Status::invalid_argument(
                    "interventions may not mutate frozen state",
                ));
            }
        }
    }
    Ok(delta)
}

fn validate_scale_ppm(ppm: u32, field: &str) -> Result<(), Status> {
    if !(SCALE_PPM_MIN..=SCALE_PPM_MAX).contains(&ppm) {
        return Err(Status::invalid_argument(format!(
            "{field} must be in [{SCALE_PPM_MIN}, {SCALE_PPM_MAX}] ppm"
        )));
    }
    Ok(())
}

trait RandomSource: Send {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Status>;
}

struct OsRandomSource;

impl RandomSource for OsRandomSource {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Status> {
        getrandom(dest).map_err(|_| Status::internal("random source unavailable"))
    }
}

#[derive(Debug)]
struct BlockedAllocator {
    block_size: usize,
    cursor: usize,
    bag: Vec<ArmId>,
    arm_counts: Vec<u64>,
}

impl BlockedAllocator {
    fn new(arm_count: ArmId, block_size: usize) -> Result<Self, Status> {
        let arm_count_usize = usize::from(arm_count);
        if block_size == 0 || block_size % arm_count_usize != 0 {
            return Err(Status::invalid_argument(
                "block_size must be > 0 and divisible by arm_count",
            ));
        }
        Ok(Self {
            block_size,
            cursor: 0,
            bag: Vec::new(),
            arm_counts: vec![0_u64; arm_count_usize],
        })
    }

    fn next<R: RandomSource + ?Sized>(
        &mut self,
        arm_count: ArmId,
        rng: &mut R,
    ) -> Result<ArmId, Status> {
        if self.cursor >= self.bag.len() {
            self.refill(arm_count, rng)?;
        }
        let arm = self
            .bag
            .get(self.cursor)
            .copied()
            .ok_or_else(|| Status::internal("blocked allocator cursor out of bounds"))?;
        self.cursor += 1;
        self.arm_counts[usize::from(arm)] += 1;
        Ok(arm)
    }

    fn refill<R: RandomSource + ?Sized>(
        &mut self,
        arm_count: ArmId,
        rng: &mut R,
    ) -> Result<(), Status> {
        self.bag.clear();
        self.cursor = 0;
        let repeats = self.block_size / usize::from(arm_count);
        for arm in 0..arm_count {
            for _ in 0..repeats {
                self.bag.push(arm);
            }
        }
        shuffle_in_place(&mut self.bag, rng)
    }
}

fn shuffle_in_place<R: RandomSource + ?Sized>(
    bag: &mut [ArmId],
    rng: &mut R,
) -> Result<(), Status> {
    if bag.len() <= 1 {
        return Ok(());
    }
    for i in (1..bag.len()).rev() {
        let mut bytes = [0_u8; 8];
        rng.fill_bytes(&mut bytes)?;
        let j = (u64::from_le_bytes(bytes) % ((i + 1) as u64)) as usize;
        bag.swap(i, j);
    }
    Ok(())
}

struct AllocationState {
    rng: Box<dyn RandomSource>,
    stratified_allocators: HashMap<StratumKey, BlockedAllocator>,
    global_allocator: Option<BlockedAllocator>,
}

pub struct TrialRouter {
    arm_count: u16,
    block_size: usize,
    interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
    blocked: bool,
    stratified: bool,
    allocator: Mutex<AllocationState>,
}

impl TrialRouter {
    pub fn new(
        arm_count: u16,
        blocked: bool,
        interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
    ) -> Result<Self, Status> {
        Self::with_options(
            arm_count,
            blocked,
            true,
            usize::from(arm_count),
            interventions,
        )
    }

    pub fn with_options(
        arm_count: u16,
        blocked: bool,
        stratified: bool,
        block_size: usize,
        interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
    ) -> Result<Self, Status> {
        Self::new_with_rng(
            arm_count,
            blocked,
            stratified,
            block_size,
            interventions,
            OsRandomSource,
        )
    }
}

impl TrialRouter {
    fn new_with_rng(
        arm_count: u16,
        blocked: bool,
        stratified: bool,
        block_size: usize,
        interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
        rng: impl RandomSource + 'static,
    ) -> Result<Self, Status> {
        if arm_count == 0 {
            return Err(Status::invalid_argument("trial arm_count must be > 0"));
        }
        let global_allocator = BlockedAllocator::new(arm_count, block_size)?;
        Ok(Self {
            arm_count,
            block_size,
            interventions,
            blocked,
            stratified,
            allocator: Mutex::new(AllocationState {
                rng: Box::new(rng),
                stratified_allocators: HashMap::new(),
                global_allocator: Some(global_allocator),
            }),
        })
    }

    #[cfg(test)]
    fn with_rng(
        arm_count: u16,
        blocked: bool,
        stratified: bool,
        block_size: usize,
        interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
        rng: impl RandomSource + 'static,
    ) -> Result<Self, Status> {
        Self::new_with_rng(
            arm_count,
            blocked,
            stratified,
            block_size,
            interventions,
            rng,
        )
    }

    pub fn assign(
        &self,
        trial_nonce: [u8; 16],
        stratum: &StratumKey,
    ) -> Result<TrialAssignment, Status> {
        let arm_id = if self.blocked {
            self.assign_blocked(trial_nonce, stratum)?
        } else {
            self.assign_hashed(trial_nonce, stratum)
        };
        let (intervention_id, intervention_version, arm_parameters_hash, descriptors) = self
            .interventions
            .get(&arm_id)
            .map(|i| {
                let arm_parameters = i.arm_parameters();
                let hash = hash_arm_parameters(&arm_parameters)?;
                Ok::<_, Status>((
                    i.id().to_string(),
                    i.version().to_string(),
                    hash,
                    InterventionDescriptors {
                        oracle_policy: i.oracle_policy(),
                        dependence_policy: i.dependence_policy(),
                        nullspec_policy: i.nullspec_policy(),
                        output_policy: i.output_policy(),
                    },
                ))
            })
            .transpose()?
            .unwrap_or_else(|| {
                (
                    "noop".to_string(),
                    "v1".to_string(),
                    [0u8; 32],
                    InterventionDescriptors {
                        oracle_policy: OraclePolicyDescriptor {
                            policy_id: "oracle.default.v1".to_string(),
                            params: serde_json::json!({}),
                        },
                        dependence_policy: DependencePolicyDescriptor {
                            policy_id: "dependence.default.v1".to_string(),
                            params: serde_json::json!({}),
                        },
                        nullspec_policy: NullSpecPolicyDescriptor {
                            policy_id: "nullspec.default.v1".to_string(),
                            params: serde_json::json!({}),
                        },
                        output_policy: OutputPolicyDescriptor {
                            policy_id: "output.default.v1".to_string(),
                            params: serde_json::json!({}),
                        },
                    },
                )
            });
        Ok(TrialAssignment {
            trial_nonce,
            arm_id,
            intervention_id,
            intervention_version,
            arm_parameters_hash,
            descriptors,
            schema_version: DEFAULT_SCHEMA_VERSION,
        })
    }

    pub fn intervention_actions(
        &self,
        assignment: &TrialAssignment,
    ) -> Result<Vec<InterventionAction>, Status> {
        let Some(intervention) = self.interventions.get(&assignment.arm_id) else {
            return Ok(Vec::new());
        };
        let actions = intervention.actions();
        let _ = validate_and_build_delta(&actions)?;
        Ok(actions)
    }

    fn assign_hashed(&self, trial_nonce: [u8; 16], stratum: &StratumKey) -> ArmId {
        let mut h = Sha256::new();
        h.update(b"evidenceos:trial_assignment:v1");
        h.update(trial_nonce);
        h.update(stratum.as_bytes());
        let digest = h.finalize();
        u16::from_be_bytes([digest[0], digest[1]]) % self.arm_count
    }

    fn assign_blocked(
        &self,
        _trial_nonce: [u8; 16],
        stratum: &StratumKey,
    ) -> Result<ArmId, Status> {
        let mut guard = self.allocator.lock();
        if self.stratified {
            if !guard.stratified_allocators.contains_key(stratum) {
                let allocator = BlockedAllocator::new(self.arm_count, self.block_size)?;
                guard
                    .stratified_allocators
                    .insert(stratum.clone(), allocator);
            }
            let mut allocator = guard
                .stratified_allocators
                .remove(stratum)
                .ok_or_else(|| Status::internal("missing stratum allocator"))?;
            let arm = allocator.next(self.arm_count, guard.rng.as_mut())?;
            guard
                .stratified_allocators
                .insert(stratum.clone(), allocator);
            Ok(arm)
        } else {
            let mut allocator = guard
                .global_allocator
                .take()
                .ok_or_else(|| Status::internal("missing global allocator"))?;
            let arm = allocator.next(self.arm_count, guard.rng.as_mut())?;
            guard.global_allocator = Some(allocator);
            Ok(arm)
        }
    }
}

pub fn default_trial_arms_config() -> TrialArmsConfig {
    TrialArmsConfig {
        arms: vec![
            TrialArmConfig {
                arm_id: 0,
                intervention_id: "control.identity_scaling".to_string(),
                intervention_version: "v1".to_string(),
                actions: vec![
                    InterventionActionConfig::ScaleAlphaPpm { ppm: 1_000_000 },
                    InterventionActionConfig::ScaleAccessCreditPpm { ppm: 1_000_000 },
                    InterventionActionConfig::ScaleKBitsBudgetPpm { ppm: 1_000_000 },
                ],
                descriptors: InterventionDescriptors {
                    oracle_policy: OraclePolicyDescriptor {
                        policy_id: "oracle.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                    dependence_policy: DependencePolicyDescriptor {
                        policy_id: "dependence.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                    nullspec_policy: NullSpecPolicyDescriptor {
                        policy_id: "nullspec.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                    output_policy: OutputPolicyDescriptor {
                        policy_id: "output.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                },
                arm_parameters: serde_json::json!({"alpha_scale_ppm":1_000_000,"access_credit_scale_ppm":1_000_000,"k_bits_scale_ppm":1_000_000}),
            },
            TrialArmConfig {
                arm_id: 1,
                intervention_id: "treatment.tighten_k_budget".to_string(),
                intervention_version: "v1".to_string(),
                actions: vec![
                    InterventionActionConfig::ScaleAlphaPpm { ppm: 1_000_000 },
                    InterventionActionConfig::ScaleAccessCreditPpm { ppm: 1_000_000 },
                    InterventionActionConfig::ScaleKBitsBudgetPpm { ppm: 750_000 },
                ],
                descriptors: InterventionDescriptors {
                    oracle_policy: OraclePolicyDescriptor {
                        policy_id: "oracle.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                    dependence_policy: DependencePolicyDescriptor {
                        policy_id: "dependence.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                    nullspec_policy: NullSpecPolicyDescriptor {
                        policy_id: "nullspec.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                    output_policy: OutputPolicyDescriptor {
                        policy_id: "output.default.v1".to_string(),
                        params: serde_json::json!({}),
                    },
                },
                arm_parameters: serde_json::json!({"alpha_scale_ppm":1_000_000,"access_credit_scale_ppm":1_000_000,"k_bits_scale_ppm":750_000}),
            },
        ],
        assignment_mode: AssignmentMode::Blocked,
        stratify: true,
        block_size: Some(2),
    }
}

pub fn interventions_from_trial_config(
    config: &TrialArmsConfig,
) -> HashMap<u16, Arc<dyn EpistemicIntervention>> {
    config
        .arms
        .iter()
        .map(|arm| {
            (
                arm.arm_id,
                Arc::new(ConfigurableIntervention::from_arm_config(arm))
                    as Arc<dyn EpistemicIntervention>,
            )
        })
        .collect()
}

pub struct NoopIntervention;

impl EpistemicIntervention for NoopIntervention {
    fn id(&self) -> &str {
        "noop"
    }

    fn version(&self) -> &str {
        "v1"
    }

    fn arm_parameters(&self) -> Value {
        serde_json::json!({})
    }

    fn oracle_policy(&self) -> OraclePolicyDescriptor {
        OraclePolicyDescriptor {
            policy_id: "oracle.default.v1".to_string(),
            params: serde_json::json!({}),
        }
    }

    fn dependence_policy(&self) -> DependencePolicyDescriptor {
        DependencePolicyDescriptor {
            policy_id: "dependence.default.v1".to_string(),
            params: serde_json::json!({}),
        }
    }

    fn nullspec_policy(&self) -> NullSpecPolicyDescriptor {
        NullSpecPolicyDescriptor {
            policy_id: "nullspec.default.v1".to_string(),
            params: serde_json::json!({}),
        }
    }

    fn output_policy(&self) -> OutputPolicyDescriptor {
        OutputPolicyDescriptor {
            policy_id: "output.default.v1".to_string(),
            params: serde_json::json!({}),
        }
    }

    fn actions(&self) -> Vec<InterventionAction> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trial_arms_config_and_build_interventions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trial_arms.json");
        let json = serde_json::json!({
            "arms": [
                {
                    "arm_id": 0,
                    "intervention_id": "control.identity_scaling",
                    "intervention_version": "v1",
                    "actions": [
                        {"type": "scale_alpha_ppm", "ppm": 1000000},
                        {"type": "scale_access_credit_ppm", "ppm": 1000000},
                        {"type": "scale_k_bits_budget_ppm", "ppm": 1000000}
                    ],
                    "descriptors": {
                        "oracle_policy": {"policy_id": "oracle.default.v1", "params": {}},
                        "dependence_policy": {"policy_id": "dependence.default.v1", "params": {}},
                        "nullspec_policy": {"policy_id": "nullspec.default.v1", "params": {}},
                        "output_policy": {"policy_id": "output.default.v1", "params": {}}
                    },
                    "arm_parameters": {"k_bits_scale_ppm": 1000000}
                },
                {
                    "arm_id": 1,
                    "intervention_id": "treatment.tighten_k_budget",
                    "intervention_version": "v1",
                    "actions": [
                        {"type": "scale_alpha_ppm", "ppm": 1000000},
                        {"type": "scale_access_credit_ppm", "ppm": 1000000},
                        {"type": "scale_k_bits_budget_ppm", "ppm": 750000}
                    ],
                    "descriptors": {
                        "oracle_policy": {"policy_id": "oracle.default.v1", "params": {}},
                        "dependence_policy": {"policy_id": "dependence.default.v1", "params": {}},
                        "nullspec_policy": {"policy_id": "nullspec.default.v1", "params": {}},
                        "output_policy": {"policy_id": "output.default.v1", "params": {}}
                    },
                    "arm_parameters": {"k_bits_scale_ppm": 750000}
                }
            ],
            "assignment_mode": "blocked",
            "stratify": true,
            "block_size": 2
        });
        std::fs::write(&path, serde_json::to_vec(&json).expect("json")).expect("write");
        let loaded = load_trial_arms_config(&path).expect("load");
        assert_eq!(loaded.config.arms.len(), 2);
        assert_ne!(loaded.config_hash, [0u8; 32]);

        let interventions = interventions_from_trial_config(&loaded.config);
        let control = interventions.get(&0).expect("control").actions();
        let treatment = interventions.get(&1).expect("treatment").actions();
        let control_delta = validate_and_build_delta(&control).expect("control delta");
        let treatment_delta = validate_and_build_delta(&treatment).expect("treatment delta");
        assert_eq!(control_delta.k_bits_scale_ppm, 1_000_000);
        assert_eq!(treatment_delta.k_bits_scale_ppm, 750_000);
    }

    #[test]
    fn default_trial_config_has_non_noop_arm() {
        let config = default_trial_arms_config();
        let interventions = interventions_from_trial_config(&config);
        let treatment = interventions.get(&1).expect("arm 1").actions();
        let delta = validate_and_build_delta(&treatment).expect("delta");
        assert_eq!(delta.k_bits_scale_ppm, 750_000);
    }

    #[test]
    fn assignment_is_deterministic_for_same_nonce_and_stratum() {
        let router = TrialRouter::new(4, false, HashMap::new()).expect("router");
        let key = StratumKey::from_baseline(BaselineCovariates {
            lane: "fast".to_string(),
            holdout_ref: "family/a".to_string(),
            oracle_id: "oracle".to_string(),
            nullspec_id: String::new(),
        });
        let nonce = [7u8; 16];
        let a = router.assign(nonce, &key).expect("assignment");
        let b = router.assign(nonce, &key).expect("assignment");
        assert_eq!(a.arm_id, b.arm_id);
        assert_eq!(a.intervention_id, b.intervention_id);
    }

    #[test]
    fn range_validation_rejects_unsafe_actions() {
        let err = validate_and_build_delta(&[InterventionAction::ScaleAlphaPpm(99_999)]);
        assert!(err.is_err());
        let err = validate_and_build_delta(&[InterventionAction::ResetLedgerTotals]);
        assert!(err.is_err());
        let err = validate_and_build_delta(&[InterventionAction::SetFrozenState(true)]);
        assert!(err.is_err());
    }

    #[test]
    fn blocked_allocator_stays_balanced_per_stratum() {
        let router = TrialRouter::new(3, true, HashMap::new()).expect("router");
        let key = StratumKey::from_baseline(BaselineCovariates {
            lane: "heavy".to_string(),
            holdout_ref: "holdout/fam".to_string(),
            oracle_id: "oracle".to_string(),
            nullspec_id: String::new(),
        });

        for i in 0..60_u8 {
            let mut nonce = [0u8; 16];
            nonce[0] = i;
            let _ = router.assign(nonce, &key).expect("assignment");
        }

        let guard = router.allocator.lock();
        let counts = &guard
            .stratified_allocators
            .get(&key)
            .expect("counts")
            .arm_counts;
        let max = counts.iter().copied().max().expect("max");
        let min = counts.iter().copied().min().expect("min");
        assert!(max - min <= 1, "counts not balanced: {counts:?}");
    }

    #[test]
    fn blocked_allocator_balances_each_stratum() {
        let router = TrialRouter::with_rng(2, true, true, 4, HashMap::new(), DeterministicRng(42))
            .expect("router");
        let a = StratumKey::from_baseline(BaselineCovariates {
            lane: "fast".to_string(),
            holdout_ref: "fam/a".to_string(),
            oracle_id: "oracle".to_string(),
            nullspec_id: String::new(),
        });
        let b = StratumKey::from_baseline(BaselineCovariates {
            lane: "heavy".to_string(),
            holdout_ref: "fam/b".to_string(),
            oracle_id: "oracle".to_string(),
            nullspec_id: String::new(),
        });

        for i in 0..8_u8 {
            let mut nonce = [0_u8; 16];
            nonce[0] = i;
            let _ = router.assign(nonce, &a).expect("assignment a");
            let _ = router.assign(nonce, &b).expect("assignment b");
        }

        let guard = router.allocator.lock();
        let a_counts = &guard
            .stratified_allocators
            .get(&a)
            .expect("a counts")
            .arm_counts;
        let b_counts = &guard
            .stratified_allocators
            .get(&b)
            .expect("b counts")
            .arm_counts;
        assert_eq!(a_counts, &vec![4, 4]);
        assert_eq!(b_counts, &vec![4, 4]);
    }

    struct DeterministicRng(u64);

    impl RandomSource for DeterministicRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Status> {
            let mut s = self.0;
            for byte in dest {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *byte = (s & 0xff) as u8;
            }
            self.0 = s;
            Ok(())
        }
    }

    #[test]
    fn blocked_allocator_balances_each_block() {
        let router = TrialRouter::with_rng(2, true, true, 4, HashMap::new(), DeterministicRng(123))
            .expect("router");
        let key = StratumKey::default();

        for i in 0..8_u8 {
            let mut nonce = [0_u8; 16];
            nonce[0] = i;
            let _ = router.assign(nonce, &key).expect("assignment");
        }

        let guard = router.allocator.lock();
        let allocator = guard.stratified_allocators.get(&key).expect("allocator");
        assert_eq!(allocator.arm_counts, vec![4, 4]);
    }

    #[test]
    fn deterministic_rng_yields_reproducible_blocked_assignments() {
        let mk_router = || {
            TrialRouter::with_rng(3, true, true, 6, HashMap::new(), DeterministicRng(7))
                .expect("router")
        };

        let a = mk_router();
        let b = mk_router();
        let key = StratumKey::default();
        for i in 0..18_u8 {
            let mut nonce = [0_u8; 16];
            nonce[0] = i;
            let aa = a.assign(nonce, &key).expect("assignment");
            let bb = b.assign(nonce, &key).expect("assignment");
            assert_eq!(aa.arm_id, bb.arm_id);
        }
    }
}
