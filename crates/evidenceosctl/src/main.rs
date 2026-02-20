use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::canary::CanaryState;
use evidenceos_core::nullspec::{
    EProcessKind, NullSpecContractV1, NullSpecKind, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_store::NullSpecStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Nullspec {
        #[command(subcommand)]
        cmd: NullspecCmd,
    },
    Canary {
        #[command(subcommand)]
        cmd: CanaryCmd,
    },
}

#[derive(Subcommand)]
enum NullspecCmd {
    Create {
        #[arg(long)]
        oracle_id: String,
        #[arg(long)]
        holdout: String,
        #[arg(long)]
        resolution_hash: String,
        #[arg(long)]
        from_calibration_buckets: PathBuf,
        #[arg(long)]
        ttl_epochs: u64,
        #[arg(long)]
        alpha: f64,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        created_by: String,
    },
    Install {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        contract: PathBuf,
    },
    Activate {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        oracle_id: String,
        #[arg(long)]
        holdout: String,
        #[arg(long)]
        nullspec_id: String,
    },
    List {
        #[arg(long)]
        data_dir: PathBuf,
    },
    Show {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        nullspec_id: String,
    },
}

#[derive(Subcommand)]
enum CanaryCmd {
    Status {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        claim_name: String,
        #[arg(long)]
        holdout: String,
    },
    Reset {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        claim_name: String,
        #[arg(long)]
        holdout: String,
        #[arg(long)]
        governance_event: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct CalibrationBuckets {
    counts: Vec<u64>,
    calibration_manifest_hash: Option<String>,
    epoch_created: u64,
}

#[derive(Debug, Serialize)]
struct GovernanceEvent<'a> {
    event_type: &'a str,
    nullspec_id: String,
    oracle_id: String,
    resolution_hash: String,
    epoch: u64,
    key_id: String,
    signature_ed25519: String,
}

fn main() {
    let cli = Cli::parse();
    let out = match cli.cmd {
        Command::Nullspec { cmd } => run_nullspec(cmd),
        Command::Canary { cmd } => run_canary(cmd),
    };
    match out {
        Ok(v) => println!("{}", v),
        Err(msg) => {
            println!("{}", json!({"error": msg}));
            std::process::exit(1);
        }
    }
}

fn run_canary(cmd: CanaryCmd) -> Result<serde_json::Value, String> {
    match cmd {
        CanaryCmd::Status {
            data_dir,
            claim_name,
            holdout,
        } => {
            let state_path = data_dir.join("state.json");
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(state_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let key = format!("{claim_name}::{holdout}");
            let states = state
                .get("canary_states")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "canary_states missing".to_string())?;
            let found = states.iter().find(|entry| {
                entry
                    .get(0)
                    .and_then(|k| k.as_str())
                    .map(|k| k == key)
                    .unwrap_or(false)
            });
            if let Some(v) = found {
                Ok(v.get(1).cloned().unwrap_or_else(|| json!({})))
            } else {
                Err("canary state not found".to_string())
            }
        }
        CanaryCmd::Reset {
            data_dir,
            claim_name,
            holdout,
            governance_event,
        } => {
            let gov: serde_json::Value =
                serde_json::from_slice(&fs::read(&governance_event).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let event_type = gov
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if event_type != "canary_reset" {
                return Err("governance event_type must be canary_reset".to_string());
            }
            if gov
                .get("signature_ed25519")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .is_empty()
            {
                return Err("signed governance event required".to_string());
            }
            let state_path = data_dir.join("state.json");
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&state_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let key = format!("{claim_name}::{holdout}");
            let states = state
                .get_mut("canary_states")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| "canary_states missing".to_string())?;
            for entry in states.iter_mut() {
                let is_target = entry
                    .get(0)
                    .and_then(|k| k.as_str())
                    .map(|k| k == key)
                    .unwrap_or(false);
                if is_target {
                    let mut canary: CanaryState = serde_json::from_value(
                        entry
                            .get(1)
                            .cloned()
                            .ok_or_else(|| "invalid canary entry".to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    canary.reset();
                    if let Some(slot) = entry.get_mut(1) {
                        *slot = serde_json::to_value(canary).map_err(|e| e.to_string())?;
                    }
                    fs::write(
                        &state_path,
                        serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    append_governance_event(
                        &data_dir,
                        GovernanceEvent {
                            event_type: "canary_reset",
                            nullspec_id: String::new(),
                            oracle_id: claim_name,
                            resolution_hash: holdout,
                            epoch: 0,
                            key_id: gov
                                .get("key_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string(),
                            signature_ed25519: gov
                                .get("signature_ed25519")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string(),
                        },
                    )?;
                    return Ok(json!({"status":"ok"}));
                }
            }
            Err("canary state not found".to_string())
        }
    }
}

fn run_nullspec(cmd: NullspecCmd) -> Result<serde_json::Value, String> {
    match cmd {
        NullspecCmd::Create {
            oracle_id,
            holdout,
            resolution_hash,
            from_calibration_buckets,
            ttl_epochs,
            alpha,
            signing_key,
            created_by,
        } => {
            let cal: CalibrationBuckets = serde_json::from_slice(
                &fs::read(from_calibration_buckets).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            if cal.counts.is_empty() {
                return Err("counts must be non-empty".to_string());
            }
            let smooth = 1.0_f64;
            let denom = cal.counts.iter().map(|c| *c as f64 + smooth).sum::<f64>();
            let p0: Vec<f64> = cal
                .counts
                .iter()
                .map(|c| (*c as f64 + smooth) / denom)
                .collect();
            let alpha_vec = vec![alpha; p0.len()];
            let mut contract = NullSpecContractV1 {
                schema: NULLSPEC_SCHEMA_V1.to_string(),
                nullspec_id: [0_u8; 32],
                oracle_id,
                oracle_resolution_hash: parse_hex32(&resolution_hash)?,
                holdout_handle: holdout,
                epoch_created: cal.epoch_created,
                ttl_epochs,
                kind: NullSpecKind::DiscreteBuckets { p0 },
                eprocess: EProcessKind::DirichletMultinomialMixture { alpha: alpha_vec },
                calibration_manifest_hash: cal
                    .calibration_manifest_hash
                    .as_deref()
                    .map(parse_hex32)
                    .transpose()?,
                created_by,
                signature_ed25519: Vec::new(),
            };
            let key_bytes = fs::read(signing_key).map_err(|e| e.to_string())?;
            let sk_arr: [u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "signing key must be raw 32-byte seed".to_string())?;
            let sk = SigningKey::from_bytes(&sk_arr);
            let payload = contract
                .signing_payload_bytes()
                .map_err(|_| "signing payload encode failed".to_string())?;
            contract.signature_ed25519 = sk.sign(&payload).to_bytes().to_vec();
            contract.nullspec_id = contract.compute_id();
            Ok(json!(contract))
        }
        NullspecCmd::Install { data_dir, contract } => {
            let bytes = fs::read(contract).map_err(|e| e.to_string())?;
            let contract: NullSpecContractV1 =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let store =
                NullSpecStore::open(&data_dir).map_err(|_| "open store failed".to_string())?;
            store
                .install(&contract)
                .map_err(|_| "install failed".to_string())?;
            append_governance_event(
                &data_dir,
                GovernanceEvent {
                    event_type: "nullspec_install",
                    nullspec_id: hex::encode(contract.nullspec_id),
                    oracle_id: contract.oracle_id,
                    resolution_hash: hex::encode(contract.oracle_resolution_hash),
                    epoch: contract.epoch_created,
                    key_id: contract.created_by,
                    signature_ed25519: hex::encode(contract.signature_ed25519),
                },
            )?;
            Ok(json!({"status":"ok"}))
        }
        NullspecCmd::Activate {
            data_dir,
            oracle_id,
            holdout,
            nullspec_id,
        } => {
            let store =
                NullSpecStore::open(&data_dir).map_err(|_| "open store failed".to_string())?;
            let id = parse_hex32(&nullspec_id)?;
            let contract = store
                .get(&id)
                .map_err(|_| "nullspec not found".to_string())?;
            store
                .rotate_active(&oracle_id, &holdout, id)
                .map_err(|_| "activate failed".to_string())?;
            append_governance_event(
                &data_dir,
                GovernanceEvent {
                    event_type: "nullspec_activate",
                    nullspec_id,
                    oracle_id,
                    resolution_hash: hex::encode(contract.oracle_resolution_hash),
                    epoch: contract.epoch_created,
                    key_id: contract.created_by,
                    signature_ed25519: hex::encode(contract.signature_ed25519),
                },
            )?;
            Ok(json!({"status":"ok"}))
        }
        NullspecCmd::List { data_dir } => {
            let store =
                NullSpecStore::open(&data_dir).map_err(|_| "open store failed".to_string())?;
            let list = store.list().map_err(|_| "list failed".to_string())?;
            Ok(json!(list))
        }
        NullspecCmd::Show {
            data_dir,
            nullspec_id,
        } => {
            let store =
                NullSpecStore::open(&data_dir).map_err(|_| "open store failed".to_string())?;
            let id = parse_hex32(&nullspec_id)?;
            let c = store.get(&id).map_err(|_| "show failed".to_string())?;
            Ok(json!(c))
        }
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "expected 32-byte hex".to_string())
}

fn append_governance_event(data_dir: &Path, event: GovernanceEvent<'_>) -> Result<(), String> {
    let path = data_dir.join("etl_governance_events.log");
    let payload = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
    let mut line = payload;
    line.push(b'\n');
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(&line).map_err(|e| e.to_string())?;
    Ok(())
}
