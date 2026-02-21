use crate::capsule::canonical_json;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedSettlementProposal {
    pub schema_version: u32,
    pub claim_id_hex: String,
    pub claim_state: String,
    pub epoch: u64,
    pub etl_index: u64,
    pub sth_hash_hex: String,
    pub decision: i32,
    pub reason_codes: Vec<u32>,
    pub capsule_hash_hex: String,
}

impl UnsignedSettlementProposal {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("unsupported schema_version");
        }
        if self.claim_id_hex.len() != 64
            || self.capsule_hash_hex.len() != 64
            || self.sth_hash_hex.len() != 64
        {
            return Err("hash fields must be 32-byte hex");
        }
        if self.claim_state.is_empty() {
            return Err("claim_state must be non-empty");
        }
        if self.reason_codes.len() > 64 {
            return Err("reason_codes exceeds maximum");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedSettlementRecord {
    pub proposal: UnsignedSettlementProposal,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

fn signing_payload(proposal: &UnsignedSettlementProposal) -> Result<Vec<u8>, &'static str> {
    canonical_json(proposal).map_err(|_| "proposal serialization failed")
}

pub fn sign_settlement_proposal(
    proposal: UnsignedSettlementProposal,
    signing_key: &SigningKey,
) -> Result<SignedSettlementRecord, &'static str> {
    proposal.validate()?;
    let payload = signing_payload(&proposal)?;
    let signature = signing_key.sign(&payload);
    Ok(SignedSettlementRecord {
        proposal,
        signer_public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_signed_settlement(
    record: &SignedSettlementRecord,
    expected_verifying_key: &VerifyingKey,
) -> Result<(), &'static str> {
    record.proposal.validate()?;
    if hex::encode(expected_verifying_key.to_bytes()) != record.signer_public_key_hex {
        return Err("unexpected signer key");
    }
    let sig_bytes = hex::decode(&record.signature_hex).map_err(|_| "invalid signature hex")?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "invalid signature bytes")?;
    let payload = signing_payload(&record.proposal)?;
    expected_verifying_key
        .verify(&payload, &sig)
        .map_err(|_| "signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn roundtrip_signed_settlement() {
        let proposal = UnsignedSettlementProposal {
            schema_version: 1,
            claim_id_hex: "ab".repeat(32),
            claim_state: "CERTIFIED".to_string(),
            epoch: 12,
            etl_index: 99,
            sth_hash_hex: "12".repeat(32),
            decision: 1,
            reason_codes: vec![7, 9],
            capsule_hash_hex: "34".repeat(32),
        };
        let key = signing_key();
        let record = sign_settlement_proposal(proposal, &key).expect("sign");
        verify_signed_settlement(&record, &key.verifying_key()).expect("verify");
    }

    #[test]
    fn tamper_fails_closed() {
        let proposal = UnsignedSettlementProposal {
            schema_version: 1,
            claim_id_hex: "cd".repeat(32),
            claim_state: "SETTLED".to_string(),
            epoch: 2,
            etl_index: 2,
            sth_hash_hex: "ef".repeat(32),
            decision: 2,
            reason_codes: vec![4],
            capsule_hash_hex: "ab".repeat(32),
        };
        let key = signing_key();
        let mut record = sign_settlement_proposal(proposal, &key).expect("sign");
        record.proposal.claim_state = "REVOKED".to_string();
        assert!(verify_signed_settlement(&record, &key.verifying_key()).is_err());
    }

    #[test]
    fn canonical_payload_stable_across_json_key_order() {
        let ordered = json!({
            "schema_version": 1,
            "claim_id_hex": "ef".repeat(32),
            "claim_state": "SETTLED",
            "epoch": 99,
            "etl_index": 12,
            "sth_hash_hex": "aa".repeat(32),
            "decision": 1,
            "reason_codes": [9202, 9203],
            "capsule_hash_hex": "bb".repeat(32)
        });
        let reordered = json!({
            "capsule_hash_hex": ordered["capsule_hash_hex"],
            "reason_codes": ordered["reason_codes"],
            "decision": ordered["decision"],
            "sth_hash_hex": ordered["sth_hash_hex"],
            "etl_index": ordered["etl_index"],
            "epoch": ordered["epoch"],
            "claim_state": ordered["claim_state"],
            "schema_version": ordered["schema_version"],
            "claim_id_hex": ordered["claim_id_hex"]
        });

        let ordered_proposal: UnsignedSettlementProposal =
            serde_json::from_value(ordered).expect("ordered parse");
        let reordered_proposal: UnsignedSettlementProposal =
            serde_json::from_value(reordered).expect("reordered parse");

        let ordered_payload = signing_payload(&ordered_proposal).expect("ordered payload");
        let reordered_payload = signing_payload(&reordered_proposal).expect("reordered payload");
        assert_eq!(ordered_payload, reordered_payload);
    }
}
