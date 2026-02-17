use crate::etl::leaf_hash;
use crate::ledger::ConservationLedger;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimCapsule {
    pub schema: String,

    pub session_id: String,
    pub holdout_id: String,

    pub claim_name: String,

    /// SHA256 of the submitted predictions bytes.
    pub predictions_hash_hex: String,

    /// SHA256 of the holdout commitment preimage.
    pub holdout_commitment_hex: String,

    pub ledger: LedgerSnapshot,

    pub e_value: f64,
    pub certified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub alpha: f64,
    pub alpha_prime: f64,
    pub k_bits_total: f64,
    pub barrier: f64,
    pub wealth: f64,
}

impl LedgerSnapshot {
    pub fn from_ledger(l: &ConservationLedger) -> Self {
        Self {
            alpha: l.alpha,
            alpha_prime: l.alpha_prime(),
            k_bits_total: l.k_bits_total,
            barrier: l.barrier(),
            wealth: l.wealth,
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

impl ClaimCapsule {
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
        }
    }

    /// Deterministic JSON encoding.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("capsule JSON serialization should not fail")
    }

    pub fn capsule_hash_hex(&self) -> String {
        sha256_hex(&self.to_json_bytes())
    }

    pub fn etl_leaf_hash(&self) -> [u8; 32] {
        leaf_hash(&self.to_json_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ConservationLedger;

    #[test]
    fn capsule_hash_is_deterministic() {
        let l = ConservationLedger::new(0.05).unwrap();
        let c1 = ClaimCapsule::new(
            "s".to_string(),
            "h".to_string(),
            "claim".to_string(),
            b"preds",
            b"holdout",
            &l,
            1.0,
            false,
        );
        let c2 = c1.clone();
        assert_eq!(c1.to_json_bytes(), c2.to_json_bytes());
        assert_eq!(c1.capsule_hash_hex(), c2.capsule_hash_hex());
    }
}
