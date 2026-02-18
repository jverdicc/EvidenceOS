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
            epsilon_total: l.epsilon_total,
            delta_total: l.delta_total,
            access_credit_spent: l.access_credit_spent,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimCapsule {
    pub schema: String,
    pub claim_id_hex: String,
    pub topic_id_hex: String,
    pub output_schema_id: String,
    pub structured_output_hash_hex: String,
    pub wasm_hash_hex: String,
    pub judge_trace_hash_hex: String,
    pub holdout_ref: String,
    pub holdout_commitment_hex: String,
    pub ledger: LedgerSnapshot,
    pub e_value: f64,
    pub certified: bool,
    pub decision: i32,
    pub reason_codes: Vec<u32>,
    pub aspec_version: String,
    pub runtime_version: String,
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
        claim_id_hex: String,
        topic_id_hex: String,
        output_schema_id: String,
        structured_output: &[u8],
        wasm_bytes: &[u8],
        holdout_commitment_preimage: &[u8],
        ledger: &ConservationLedger,
        e_value: f64,
        certified: bool,
        decision: i32,
        reason_codes: Vec<u32>,
        judge_trace_hash_hex: String,
        holdout_ref: String,
    ) -> Self {
        Self {
            schema: "evidenceos.v2.claim_capsule".to_string(),
            claim_id_hex,
            topic_id_hex,
            output_schema_id,
            structured_output_hash_hex: sha256_hex(structured_output),
            wasm_hash_hex: sha256_hex(wasm_bytes),
            judge_trace_hash_hex,
            holdout_ref,
            holdout_commitment_hex: sha256_hex(holdout_commitment_preimage),
            ledger: LedgerSnapshot::from_ledger(ledger),
            e_value,
            certified,
            decision,
            reason_codes,
            aspec_version: "aspec.v1".into(),
            runtime_version: "unknown".into(),
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
    fn capsule_hash_changes_when_state_changes() {
        let l = ConservationLedger::new(0.05).expect("ledger");
        let mut c = ClaimCapsule::new(
            "c".into(),
            "t".into(),
            "schema".into(),
            b"out",
            b"wasm",
            b"hold",
            &l,
            1.0,
            false,
            1,
            vec![7],
            "trace".into(),
            "holdout".into(),
        );
        c.state = ClaimState::Sealed;
        let h1 = c.capsule_hash_hex().expect("hash1");
        c.state = ClaimState::Certified;
        let h2 = c.capsule_hash_hex().expect("hash2");
        assert_ne!(h1, h2);
    }
}
