use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::Status;

const DEFAULT_SCHEMA_VERSION: u32 = 1;
const SCALE_PPM_MIN: u32 = 100_000;
const SCALE_PPM_MAX: u32 = 2_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialAssignment {
    pub trial_nonce: [u8; 16],
    pub arm_id: u16,
    pub intervention_id: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StratumKey {
    lane: String,
    claim_name: String,
    holdout_family: String,
    oracle_id: String,
    nullspec_id: String,
}

impl StratumKey {
    pub fn new(
        lane: String,
        claim_name: impl Into<String>,
        holdout_ref: &str,
        oracle_id: impl Into<String>,
        nullspec_id: impl Into<String>,
    ) -> Self {
        Self {
            lane: lane.into(),
            claim_name: claim_name.into(),
            holdout_family: holdout_family(holdout_ref),
            oracle_id: oracle_id.into(),
            nullspec_id: nullspec_id.into(),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_tagged(&mut out, self.lane.as_bytes());
        append_tagged(&mut out, self.claim_name.as_bytes());
        append_tagged(&mut out, self.holdout_family.as_bytes());
        append_tagged(&mut out, self.oracle_id.as_bytes());
        append_tagged(&mut out, self.nullspec_id.as_bytes());
        out
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
    fn intervention_id(&self) -> &'static str;
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

#[derive(Default)]
struct BlockAllocator {
    arm_counts: HashMap<StratumKey, Vec<u64>>,
}

pub struct TrialRouter {
    arm_count: u16,
    interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
    blocked: bool,
    allocator: Mutex<BlockAllocator>,
}

impl TrialRouter {
    pub fn new(
        arm_count: u16,
        blocked: bool,
        interventions: HashMap<u16, Arc<dyn EpistemicIntervention>>,
    ) -> Result<Self, Status> {
        if arm_count == 0 {
            return Err(Status::invalid_argument("trial arm_count must be > 0"));
        }
        Ok(Self {
            arm_count,
            interventions,
            blocked,
            allocator: Mutex::new(BlockAllocator::default()),
        })
    }

    pub fn assign(
        &self,
        trial_nonce: [u8; 16],
        stratum: &StratumKey,
    ) -> Result<TrialAssignment, Status> {
        let arm_id = if self.blocked {
            self.assign_blocked(trial_nonce, stratum)
        } else {
            self.assign_hashed(trial_nonce, stratum)
        };
        let intervention_id = self
            .interventions
            .get(&arm_id)
            .map(|i| i.intervention_id().to_string())
            .unwrap_or_else(|| "noop.v1".to_string());
        Ok(TrialAssignment {
            trial_nonce,
            arm_id,
            intervention_id,
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

    fn assign_hashed(&self, trial_nonce: [u8; 16], stratum: &StratumKey) -> u16 {
        let mut h = Sha256::new();
        h.update(b"evidenceos:trial_assignment:v1");
        h.update(trial_nonce);
        h.update(stratum.as_bytes());
        let digest = h.finalize();
        u16::from_be_bytes([digest[0], digest[1]]) % self.arm_count
    }

    fn assign_blocked(&self, trial_nonce: [u8; 16], stratum: &StratumKey) -> u16 {
        let base_arm = self.assign_hashed(trial_nonce, stratum);
        let mut guard = self.allocator.lock();
        let counts = guard
            .arm_counts
            .entry(stratum.clone())
            .or_insert_with(|| vec![0_u64; usize::from(self.arm_count)]);

        let min = counts.iter().copied().min().unwrap_or(0);
        let mut best = base_arm;
        for offset in 0..self.arm_count {
            let idx = usize::from((base_arm + offset) % self.arm_count);
            if counts[idx] == min {
                best = idx as u16;
                break;
            }
        }
        counts[usize::from(best)] += 1;
        best
    }
}

pub struct NoopIntervention;

impl EpistemicIntervention for NoopIntervention {
    fn intervention_id(&self) -> &'static str {
        "noop.v1"
    }

    fn actions(&self) -> Vec<InterventionAction> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_is_deterministic_for_same_nonce_and_stratum() {
        let router = TrialRouter::new(4, false, HashMap::new()).expect("router");
        let key = StratumKey::new("fast", "c1", "family/a", "oracle", "");
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
        let key = StratumKey::new("heavy", "c2", "holdout/fam", "oracle", "");

        for i in 0..60_u8 {
            let mut nonce = [0u8; 16];
            nonce[0] = i;
            let _ = router.assign(nonce, &key).expect("assignment");
        }

        let guard = router.allocator.lock();
        let counts = guard.arm_counts.get(&key).expect("counts");
        let max = counts.iter().copied().max().expect("max");
        let min = counts.iter().copied().min().expect("min");
        assert!(max - min <= 1, "counts not balanced: {counts:?}");
    }
}
