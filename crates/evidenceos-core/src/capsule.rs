// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::etl::leaf_hash;
use crate::ledger::ConservationLedger;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimState {
    Uncommitted,
    Sealed,
    Executing,
    Settled,
    Certified,
    Revoked,
    Tainted,
    Stale,
}

impl ClaimState {
    pub fn transition(&self, to: ClaimState) -> Result<ClaimState, String> {
        let valid = matches!(
            (self, to),
            (ClaimState::Uncommitted, ClaimState::Sealed)
                | (ClaimState::Sealed, ClaimState::Executing)
                | (ClaimState::Executing, ClaimState::Settled)
                | (ClaimState::Settled, ClaimState::Certified)
                | (ClaimState::Settled, ClaimState::Revoked)
                | (ClaimState::Certified, ClaimState::Revoked)
                | (ClaimState::Revoked, ClaimState::Tainted)
                | (ClaimState::Sealed, ClaimState::Stale)
                | (ClaimState::Executing, ClaimState::Stale)
                | (ClaimState::Stale, ClaimState::Sealed)
        );
        if valid {
            Ok(to)
        } else {
            Err(format!("invalid transition: {:?} -> {:?}", self, to))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerSnapshot {
    pub alpha: f64,
    pub alpha_prime: f64,
    pub k_bits_total: f64,
    pub barrier: f64,
    pub wealth: f64,
    pub w_max: f64,
    pub epsilon_total: f64,
    pub delta_total: f64,
    pub access_credit_spent: f64,
}

impl LedgerSnapshot {
    pub fn from_ledger(l: &ConservationLedger) -> Self {
        Self {
            alpha: l.alpha,
            alpha_prime: l.alpha_prime(),
            k_bits_total: l.k_bits_total,
            barrier: l.barrier(),
            wealth: l.wealth,
            w_max: l.w_max,
            epsilon_total: 0.0,
            delta_total: 0.0,
            access_credit_spent: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimCapsule {
    pub schema: String,
    pub session_id: String,
    pub holdout_id: String,
    pub claim_name: String,
    pub predictions_hash_hex: String,
    pub holdout_commitment_hex: String,
    pub ledger: LedgerSnapshot,
    pub e_value: f64,
    pub certified: bool,
    pub aspec_version: String,
    pub runtime_version: String,
    pub wasm_hash_hex: String,
    pub dependency_hashes: Vec<String>,
    pub judge_trace_hash_hex: String,
    pub state: ClaimState,
}

pub fn canonical_json(v: &impl Serialize) -> EvidenceOSResult<Vec<u8>> {
    let value = serde_json::to_value(v).map_err(|_| EvidenceOSError::Internal)?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).map_err(|_| EvidenceOSError::Internal)
}

fn sort_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = Map::new();
            for (k, val) in entries {
                sorted.insert(k, sort_json(val));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

impl ClaimCapsule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        holdout_id: String,
        claim_name: String,
        predictions: &[u8],
        holdout_commitment_preimage: &[u8],
        ledger: &ConservationLedger,
        e_value: f64,
        certified: bool,
    ) -> Self {
        Self {
            schema: "evidenceos.v1.claim_capsule".to_string(),
            session_id,
            holdout_id,
            claim_name,
            predictions_hash_hex: sha256_hex(predictions),
            holdout_commitment_hex: sha256_hex(holdout_commitment_preimage),
            ledger: LedgerSnapshot::from_ledger(ledger),
            e_value,
            certified,
            aspec_version: "aspec.v1".into(),
            runtime_version: "unknown".into(),
            wasm_hash_hex: sha256_hex(&[]),
            dependency_hashes: Vec::new(),
            judge_trace_hash_hex: sha256_hex(&[]),
            state: ClaimState::Uncommitted,
        }
    }

    pub fn to_json_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        canonical_json(self)
    }
    pub fn capsule_hash_hex(&self) -> EvidenceOSResult<String> {
        Ok(sha256_hex(&self.to_json_bytes()?))
    }
    pub fn etl_leaf_hash(&self) -> EvidenceOSResult<[u8; 32]> {
        Ok(leaf_hash(&self.to_json_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ConservationLedger;

    #[test]
    fn claim_state_valid_transitions() {
        let s = ClaimState::Uncommitted
            .transition(ClaimState::Sealed)
            .expect("u->s");
        let s = s.transition(ClaimState::Executing).expect("s->e");
        let s = s.transition(ClaimState::Settled).expect("e->set");
        s.transition(ClaimState::Certified).expect("set->cert");
    }

    #[test]
    fn canonical_json_stable_regardless_of_insertion_order() {
        let a: Value = serde_json::json!({"z":1,"a":2,"b":3,"c":4,"d":5,"e":6,"f":7,"g":8,"h":9,"i":10,"j":11});
        let b: Value = serde_json::json!({"a":2,"b":3,"c":4,"d":5,"e":6,"f":7,"g":8,"h":9,"i":10,"j":11,"z":1});
        assert_eq!(
            canonical_json(&a).expect("json a"),
            canonical_json(&b).expect("json b")
        );
    }

    #[test]
    fn capsule_hash_changes_when_state_changes() {
        let l = ConservationLedger::new(0.05).expect("ledger");
        let mut c = ClaimCapsule::new(
            "s".into(),
            "h".into(),
            "c".into(),
            b"pred",
            b"hold",
            &l,
            1.0,
            false,
        );
        c.state = ClaimState::Sealed;
        let h1 = c.capsule_hash_hex().expect("hash1");
        c.state = ClaimState::Certified;
        let h2 = c.capsule_hash_hex().expect("hash2");
        assert_ne!(h1, h2);
    }
}
