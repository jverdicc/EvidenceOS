use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::capsule::canonical_json;
use evidenceos_protocol::{
    sha256_domain, DOMAIN_EPOCH_CONTROL_V1, DOMAIN_ORACLE_OPERATOR_RECORD_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const ORACLE_OPERATOR_PATH: &str = "oracle_operator_config.json";
const EPOCH_CONTROL_PATH: &str = "epoch_control.json";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    SignOracleRecord {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        oracle_id: String,
        #[arg(long)]
        ttl_epochs: u64,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        key_id: String,
    },
    SignEpochControl {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        forced_epoch: u64,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        key_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorRecord {
    ttl_epochs: u64,
    calibration_hash: Option<String>,
    calibration_epoch: Option<u64>,
    updated_at_epoch: u64,
    key_id: String,
    signature_ed25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorConfig {
    oracles: HashMap<String, OracleOperatorRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct OracleOperatorRecordSigningPayload<'a> {
    oracle_id: &'a str,
    ttl_epochs: u64,
    calibration_hash: Option<&'a str>,
    calibration_epoch: Option<u64>,
    updated_at_epoch: u64,
    key_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct EpochControlSigningPayload<'a> {
    forced_epoch: u64,
    updated_at_epoch: u64,
    key_id: &'a str,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::SignOracleRecord {
            data_dir,
            oracle_id,
            ttl_epochs,
            signing_key,
            key_id,
        } => {
            if ttl_epochs == 0 {
                return Err("ttl_epochs must be > 0".to_string());
            }
            let signing_key = read_signing_key(&signing_key)?;
            let cfg_path = data_dir.join(ORACLE_OPERATOR_PATH);
            let mut cfg = if cfg_path.exists() {
                let bytes = fs::read(&cfg_path).map_err(|e| e.to_string())?;
                serde_json::from_slice::<OracleOperatorConfig>(&bytes).map_err(|e| e.to_string())?
            } else {
                OracleOperatorConfig::default()
            };

            let now_epoch = unix_epoch_now()?;
            let mut entry = cfg.oracles.remove(&oracle_id).unwrap_or_default();
            entry.ttl_epochs = ttl_epochs;
            entry.updated_at_epoch = now_epoch;
            entry.key_id = key_id.clone();

            let payload = OracleOperatorRecordSigningPayload {
                oracle_id: &oracle_id,
                ttl_epochs: entry.ttl_epochs,
                calibration_hash: entry.calibration_hash.as_deref(),
                calibration_epoch: entry.calibration_epoch,
                updated_at_epoch: entry.updated_at_epoch,
                key_id: &entry.key_id,
            };
            entry.signature_ed25519 = sign_oracle_record_payload(&signing_key, &payload)?;
            cfg.oracles.insert(oracle_id, entry);

            fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
            fs::write(
                cfg_path,
                serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            Ok(())
        }
        Command::SignEpochControl {
            data_dir,
            forced_epoch,
            signing_key,
            key_id,
        } => {
            let signing_key = read_signing_key(&signing_key)?;
            let updated_at_epoch = unix_epoch_now()?;
            let payload = EpochControlSigningPayload {
                forced_epoch,
                updated_at_epoch,
                key_id: &key_id,
            };
            let signature_ed25519 = sign_epoch_control_payload(&signing_key, &payload)?;

            fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
            fs::write(
                data_dir.join(EPOCH_CONTROL_PATH),
                serde_json::to_vec_pretty(&json!({
                    "forced_epoch": forced_epoch,
                    "updated_at_epoch": updated_at_epoch,
                    "key_id": key_id,
                    "signature_ed25519": signature_ed25519,
                }))
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

fn unix_epoch_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())
}

fn read_signing_key(path: &PathBuf) -> Result<SigningKey, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("signing key must be 32-byte seed".to_string());
    }
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing key must be 32-byte seed".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

fn sign_oracle_record_payload(
    sk: &SigningKey,
    payload: &OracleOperatorRecordSigningPayload<'_>,
) -> Result<String, String> {
    let canonical = canonical_json(payload).map_err(|e| e.to_string())?;
    let digest = sha256_domain(DOMAIN_ORACLE_OPERATOR_RECORD_V1, &canonical);
    Ok(hex::encode(sk.sign(&digest).to_bytes()))
}

fn sign_epoch_control_payload(
    sk: &SigningKey,
    payload: &EpochControlSigningPayload<'_>,
) -> Result<String, String> {
    let canonical = canonical_json(payload).map_err(|e| e.to_string())?;
    let digest = sha256_domain(DOMAIN_EPOCH_CONTROL_V1, &canonical);
    Ok(hex::encode(sk.sign(&digest).to_bytes()))
}
