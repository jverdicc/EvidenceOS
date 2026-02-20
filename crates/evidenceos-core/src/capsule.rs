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

use crate::crypto_transcripts::etl_leaf_hash;
use crate::error::{EvidenceOSError, EvidenceOSResult};
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
    Frozen,
}

impl ClaimState {
    pub fn transition(&self, to: ClaimState) -> Result<ClaimState, String> {
        if to == ClaimState::Frozen {
            return Ok(ClaimState::Frozen);
        }
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
    pub compute_fuel_spent: f64,
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
            compute_fuel_spent: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub kind: String,
    pub hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerReceipt {
    pub lane: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentAttestations {
    pub runtime_version: String,
    pub aspec_version: String,
    pub protocol_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyOracleReceiptLike {
    pub oracle_id: String,
    pub manifest_hash_hex: String,
    pub wasm_hash_hex: String,
    pub decision: String,
    pub reason_code: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimCapsule {
    pub schema: String,
    pub claim_id_hex: String,
    pub topic_id_hex: String,
    pub output_schema_id: String,
    pub code_ir_manifests: Vec<ManifestEntry>,
    pub dependency_capsule_hashes: Vec<String>,
    pub structured_output_hash_hex: String,
    pub canonical_output_hash_hex: String,
    pub kout_bits_upper_bound: u64,
    pub wasm_hash_hex: String,
    pub judge_trace_hash_hex: String,
    pub holdout_ref: String,
    pub holdout_commitment_hex: String,
    pub ledger: LedgerSnapshot,
    pub ledger_receipts: Vec<LedgerReceipt>,
    pub e_value: f64,
    pub certified: bool,
    pub decision: i32,
    pub reason_codes: Vec<u32>,
    #[serde(default)]
    pub semantic_hash_hex: Option<String>,
    #[serde(default)]
    pub physhir_hash_hex: Option<String>,
    #[serde(default)]
    pub lineage_root_hash_hex: Option<String>,
    #[serde(default)]
    pub output_schema_id_hash_hex: Option<String>,
    #[serde(default)]
    pub holdout_handle_hash_hex: Option<String>,
    #[serde(default)]
    pub disagreement_score: Option<u32>,
    #[serde(default)]
    pub semantic_physhir_distance_bits: Option<u32>,
    #[serde(default)]
    pub escalate_to_heavy: Option<bool>,
    #[serde(default)]
    pub policy_oracle_receipts: Vec<PolicyOracleReceiptLike>,
    #[serde(default)]
    pub nullspec_id_hex: Option<String>,
    #[serde(default)]
    pub oracle_resolution_hash_hex: Option<String>,
    #[serde(default)]
    pub eprocess_kind: Option<String>,
    #[serde(default)]
    pub nullspec_contract_hash_hex: Option<String>,
    pub environment_attestations: EnvironmentAttestations,
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
        code_ir_manifests: Vec<ManifestEntry>,
        dependency_capsule_hashes: Vec<String>,
        structured_output: &[u8],
        wasm_bytes: &[u8],
        holdout_commitment_preimage: &[u8],
        ledger: &ConservationLedger,
        e_value: f64,
        certified: bool,
        decision: i32,
        reason_codes: Vec<u32>,
        policy_oracle_receipts: Vec<PolicyOracleReceiptLike>,
        judge_trace: &[u8],
        holdout_ref: String,
        runtime_version: String,
        aspec_version: String,
        protocol_version: String,
        compute_fuel_spent: f64,
    ) -> Self {
        Self::new_with_state(
            claim_id_hex,
            topic_id_hex,
            output_schema_id,
            code_ir_manifests,
            dependency_capsule_hashes,
            structured_output,
            wasm_bytes,
            holdout_commitment_preimage,
            ledger,
            e_value,
            certified,
            decision,
            reason_codes,
            policy_oracle_receipts,
            judge_trace,
            holdout_ref,
            runtime_version,
            aspec_version,
            protocol_version,
            compute_fuel_spent,
            ClaimState::Uncommitted,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_state(
        claim_id_hex: String,
        topic_id_hex: String,
        output_schema_id: String,
        mut code_ir_manifests: Vec<ManifestEntry>,
        mut dependency_capsule_hashes: Vec<String>,
        structured_output: &[u8],
        wasm_bytes: &[u8],
        holdout_commitment_preimage: &[u8],
        ledger: &ConservationLedger,
        e_value: f64,
        certified: bool,
        decision: i32,
        reason_codes: Vec<u32>,
        policy_oracle_receipts: Vec<PolicyOracleReceiptLike>,
        judge_trace: &[u8],
        holdout_ref: String,
        runtime_version: String,
        aspec_version: String,
        protocol_version: String,
        compute_fuel_spent: f64,
        state: ClaimState,
    ) -> Self {
        code_ir_manifests.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| a.hash_hex.cmp(&b.hash_hex))
        });
        dependency_capsule_hashes.sort();
        let mut ledger_snapshot = LedgerSnapshot::from_ledger(ledger);
        ledger_snapshot.compute_fuel_spent = compute_fuel_spent;
        Self {
            schema: "evidenceos.v2.claim_capsule".to_string(),
            claim_id_hex,
            topic_id_hex,
            output_schema_id,
            code_ir_manifests,
            dependency_capsule_hashes,
            structured_output_hash_hex: sha256_hex(structured_output),
            canonical_output_hash_hex: sha256_hex(structured_output),
            kout_bits_upper_bound: (structured_output.len() as u64).saturating_mul(8),
            wasm_hash_hex: sha256_hex(wasm_bytes),
            judge_trace_hash_hex: sha256_hex(judge_trace),
            holdout_ref,
            holdout_commitment_hex: sha256_hex(holdout_commitment_preimage),
            ledger: ledger_snapshot.clone(),
            ledger_receipts: vec![
                LedgerReceipt {
                    lane: "wealth_w".to_string(),
                    value: ledger_snapshot.wealth,
                    unit: "e_value_product".to_string(),
                },
                LedgerReceipt {
                    lane: "information_k".to_string(),
                    value: ledger_snapshot.k_bits_total,
                    unit: "bits".to_string(),
                },
                LedgerReceipt {
                    lane: "privacy_epsilon_delta".to_string(),
                    value: ledger_snapshot.epsilon_total + ledger_snapshot.delta_total,
                    unit: "epsilon_plus_delta".to_string(),
                },
                LedgerReceipt {
                    lane: "access_credit".to_string(),
                    value: ledger_snapshot.access_credit_spent,
                    unit: "credits".to_string(),
                },
                LedgerReceipt {
                    lane: "compute_fuel".to_string(),
                    value: ledger_snapshot.compute_fuel_spent,
                    unit: "fuel".to_string(),
                },
            ],
            e_value,
            certified,
            decision,
            reason_codes,
            semantic_hash_hex: None,
            physhir_hash_hex: None,
            lineage_root_hash_hex: None,
            output_schema_id_hash_hex: None,
            holdout_handle_hash_hex: None,
            disagreement_score: None,
            semantic_physhir_distance_bits: None,
            escalate_to_heavy: None,
            policy_oracle_receipts,
            nullspec_id_hex: None,
            oracle_resolution_hash_hex: None,
            eprocess_kind: None,
            nullspec_contract_hash_hex: None,
            environment_attestations: EnvironmentAttestations {
                runtime_version,
                aspec_version,
                protocol_version,
            },
            state,
        }
    }

    pub fn to_json_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        canonical_json(self)
    }
    pub fn capsule_hash_hex(&self) -> EvidenceOSResult<String> {
        Ok(sha256_hex(&self.to_json_bytes()?))
    }
    pub fn etl_leaf_hash(&self) -> EvidenceOSResult<[u8; 32]> {
        Ok(etl_leaf_hash(&self.to_json_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ConservationLedger;

    #[test]
    fn capsule_hash_changes_on_any_field_change() {
        let l = ConservationLedger::new(0.05).expect("ledger");
        let mut c = ClaimCapsule::new(
            "c".into(),
            "t".into(),
            "schema".into(),
            vec![ManifestEntry {
                kind: "ir".into(),
                hash_hex: "aa".into(),
            }],
            vec!["11".into()],
            b"out",
            b"wasm",
            b"hold",
            &l,
            1.0,
            false,
            1,
            vec![7],
            Vec::new(),
            b"trace",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            123.0,
        );
        let h1 = c.capsule_hash_hex().expect("hash1");
        c.environment_attestations.protocol_version = "evidenceos.v2".to_string();
        let h2 = c.capsule_hash_hex().expect("hash2");
        assert_ne!(h1, h2);
    }
}
