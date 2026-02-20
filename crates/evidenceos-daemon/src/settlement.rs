use ed25519_dalek::VerifyingKey;
use evidenceos_core::settlement::{
    verify_signed_settlement, SignedSettlementRecord, UnsignedSettlementProposal,
};
use std::fs;
use std::path::{Path, PathBuf};

pub fn write_unsigned_proposal(
    data_dir: &Path,
    proposal: &UnsignedSettlementProposal,
) -> Result<PathBuf, String> {
    proposal.validate().map_err(|e| e.to_string())?;
    let claim_id = proposal.claim_id_hex.clone();
    let dir = data_dir
        .join("settlement_spool")
        .join(proposal.epoch.to_string());
    fs::create_dir_all(&dir).map_err(|_| "failed to create settlement spool dir".to_string())?;
    let path = dir.join(format!("{claim_id}.json"));
    let payload = serde_json::to_vec_pretty(proposal)
        .map_err(|_| "failed to serialize settlement proposal".to_string())?;
    fs::write(&path, payload).map_err(|_| "failed to write settlement proposal".to_string())?;
    Ok(path)
}

pub fn import_signed_settlements(
    import_dir: &Path,
    verify_key: &VerifyingKey,
) -> Result<Vec<SignedSettlementRecord>, String> {
    let mut records = Vec::new();
    if !import_dir.exists() {
        return Ok(records);
    }
    let entries = fs::read_dir(import_dir).map_err(|_| "failed to read import dir".to_string())?;
    for entry in entries {
        let path = entry
            .map_err(|_| "failed to read import entry".to_string())?
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|_| "failed to read signed settlement".to_string())?;
        let record: SignedSettlementRecord = serde_json::from_slice(&bytes)
            .map_err(|_| "failed to decode signed settlement".to_string())?;
        verify_signed_settlement(&record, verify_key).map_err(|e| e.to_string())?;
        records.push(record);
    }
    Ok(records)
}
