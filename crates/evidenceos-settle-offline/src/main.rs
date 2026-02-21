#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use ed25519_dalek::SigningKey;
use evidenceos_core::settlement::{sign_settlement_proposal, UnsignedSettlementProposal};
use std::fs;
use std::path::Path;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    spool_dir: String,
    #[arg(long)]
    out_dir: String,
    #[arg(long)]
    signer_key_hex: String,
}

fn load_proposals(
    dir: &Path,
) -> Result<Vec<UnsignedSettlementProposal>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for epoch_entry in fs::read_dir(dir)? {
        let epoch_path = epoch_entry?.path();
        if !epoch_path.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&epoch_path)? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)?;
            let proposal: UnsignedSettlementProposal = serde_json::from_slice(&bytes)?;
            proposal.validate().map_err(std::io::Error::other)?;
            out.push(proposal);
        }
    }
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)?;
    let key_bytes = hex::decode(args.signer_key_hex)?;
    let key_arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signer key must be 32 bytes",
        )
    })?;
    let key = SigningKey::from_bytes(&key_arr);
    let proposals = load_proposals(Path::new(&args.spool_dir))?;
    for proposal in proposals {
        let claim_id = proposal.claim_id_hex.clone();
        let signed = sign_settlement_proposal(proposal, &key).map_err(std::io::Error::other)?;
        let path = Path::new(&args.out_dir).join(format!("{claim_id}.json"));
        fs::write(path, serde_json::to_vec_pretty(&signed)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_roundtrip() {
        let proposal = UnsignedSettlementProposal {
            schema_version: 1,
            claim_id_hex: "01".repeat(32),
            claim_state: "SETTLED".into(),
            epoch: 1,
            etl_index: 9,
            sth_hash_hex: "ab".repeat(32),
            decision: 1,
            reason_codes: vec![9202],
            capsule_hash_hex: "cd".repeat(32),
        };
        let payload = serde_json::to_vec(&proposal).expect("serialize");
        let parsed: UnsignedSettlementProposal = serde_json::from_slice(&payload).expect("parse");
        assert_eq!(proposal, parsed);
    }
}
