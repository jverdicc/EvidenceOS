use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedSettlementProposal {
    pub schema_version: u32,
    pub claim_id_hex: String,
    pub claim_state: String,
    pub epoch: u64,
    pub capsule_bytes: Vec<u8>,
    pub capsule_hash_hex: String,
}

impl UnsignedSettlementProposal {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("unsupported schema_version");
        }
        if self.claim_id_hex.len() != 64 || self.capsule_hash_hex.len() != 64 {
            return Err("hash fields must be 32-byte hex");
        }
        if self.claim_state.is_empty() {
            return Err("claim_state must be non-empty");
        }
        let hash = Sha256::digest(&self.capsule_bytes);
        if hex::encode(hash) != self.capsule_hash_hex {
            return Err("capsule_hash_hex does not match capsule_bytes");
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
    serde_json::to_vec(proposal).map_err(|_| "proposal serialization failed")
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
            capsule_bytes: b"capsule".to_vec(),
            capsule_hash_hex: hex::encode(Sha256::digest(b"capsule")),
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
            capsule_bytes: b"capsule".to_vec(),
            capsule_hash_hex: hex::encode(Sha256::digest(b"capsule")),
        };
        let key = signing_key();
        let mut record = sign_settlement_proposal(proposal, &key).expect("sign");
        record.proposal.claim_state = "REVOKED".to_string();
        assert!(verify_signed_settlement(&record, &key.verifying_key()).is_err());
    }
}
