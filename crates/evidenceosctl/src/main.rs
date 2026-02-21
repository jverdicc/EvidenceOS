use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::canary::CanaryState;
use evidenceos_core::capsule::canonical_json;
use evidenceos_core::nullspec::{
    EProcessKind, NullSpecContractV1, NullSpecKind, NULLSPEC_SCHEMA_V1,
};
use evidenceos_core::nullspec_store::NullSpecStore;
use evidenceos_protocol::{
    sha256_domain, DOMAIN_EPOCH_CONTROL_V1, DOMAIN_ORACLE_OPERATOR_RECORD_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ORACLE_OPERATOR_PATH: &str = "oracle_operator_config.json";
const EPOCH_CONTROL_PATH: &str = "epoch_control.json";
const GOVERNANCE_LOG_PATH: &str = "etl_governance_events.log";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(alias = "operator")]
    Oracle {
        #[command(subcommand)]
        cmd: OracleCmd,
    },
    #[command(alias = "operator-epoch")]
    Epoch {
        #[command(subcommand)]
        cmd: EpochCmd,
    },
    Nullspec {
        #[command(subcommand)]
        cmd: NullspecCmd,
    },
    Canary {
        #[command(subcommand)]
        cmd: CanaryCmd,
    },
    Governance {
        #[command(subcommand)]
        cmd: GovernanceCmd,
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

#[derive(Subcommand)]
enum OracleCmd {
    List {
        #[arg(long)]
        data_dir: PathBuf,
    },
    Show {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        oracle_id: String,
    },
    #[command(name = "sign-oracle-record", alias = "set-ttl")]
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
    #[command(name = "sign-oracle-calibration", alias = "rotate-calibration")]
    SignOracleCalibration {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        oracle_id: String,
        #[arg(long)]
        calib_hash: String,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        key_id: String,
    },
}
#[derive(Subcommand)]
enum EpochCmd {
    #[command(name = "sign-epoch-control", alias = "advance")]
    SignEpochControl {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        to: u64,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        key_id: String,
    },
}

#[derive(Subcommand)]
enum GovernanceCmd {
    Events {
        #[command(subcommand)]
        cmd: GovernanceEventsCmd,
    },
}

#[derive(Subcommand)]
enum GovernanceEventsCmd {
    List {
        #[arg(long)]
        data_dir: PathBuf,
    },
    Show {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        event_id: String,
    },
}

#[derive(Debug, Deserialize)]
struct CalibrationBuckets {
    counts: Vec<u64>,
    calibration_manifest_hash: Option<String>,
    epoch_created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorRecord {
    schema_version: u32,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: Option<String>,
    calibration_epoch: Option<u64>,
    disjointness_attestation: Option<String>,
    nonoverlap_proof_uri: Option<String>,
    updated_at_epoch: u64,
    key_id: String,
    signature_ed25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OracleOperatorConfig {
    oracles: BTreeMap<String, OracleOperatorRecord>,
}
#[derive(Debug, Clone, Serialize)]
struct OracleOperatorSigningPayload<'a> {
    oracle_id: &'a str,
    schema_version: u32,
    ttl_epochs: u64,
    calibration_manifest_hash_hex: &'a str,
    calibration_epoch: Option<u64>,
    disjointness_attestation: &'a str,
    nonoverlap_proof_uri: Option<&'a str>,
    updated_at_epoch: u64,
    key_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct EpochControlSigningPayload<'a> {
    forced_epoch: u64,
    updated_at_epoch: u64,
    key_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedGovernanceEvent {
    event_id: String,
    event_type: String,
    epoch: u64,
    key_id: String,
    payload: serde_json::Value,
    signature_ed25519: String,
}

#[derive(Debug, Clone, Serialize)]
struct GovernanceEventPayload<'a> {
    event_type: &'a str,
    epoch: u64,
    key_id: &'a str,
    payload: serde_json::Value,
}

fn main() {
    let cli = Cli::parse();
    let out = match cli.cmd {
        Command::Nullspec { cmd } => run_nullspec(cmd),
        Command::Canary { cmd } => run_canary(cmd),
        Command::Oracle { cmd } => run_oracle(cmd),
        Command::Epoch { cmd } => run_epoch(cmd),
        Command::Governance { cmd } => run_governance(cmd),
    };
    match out {
        Ok(v) => println!("{}", v),
        Err(msg) => {
            println!("{}", json!({"error": msg}));
            std::process::exit(1);
        }
    }
}

fn run_oracle(cmd: OracleCmd) -> Result<serde_json::Value, String> {
    match cmd {
        OracleCmd::List { data_dir } => {
            let cfg = read_oracle_config(&data_dir)?;
            Ok(json!(cfg.oracles))
        }
        OracleCmd::Show {
            data_dir,
            oracle_id,
        } => {
            let cfg = read_oracle_config(&data_dir)?;
            let record = cfg
                .oracles
                .get(&oracle_id)
                .ok_or_else(|| "oracle not found".to_string())?;
            Ok(json!(record))
        }
        OracleCmd::SignOracleRecord {
            data_dir,
            oracle_id,
            ttl_epochs,
            signing_key,
            key_id,
        } => {
            if ttl_epochs == 0 {
                return Err("ttl_epochs must be > 0".to_string());
            }
            let mut cfg = read_oracle_config(&data_dir)?;
            let epoch = unix_epoch_now()?;
            let payload = json!({"oracle_id": oracle_id, "ttl_epochs": ttl_epochs});
            let event =
                sign_governance_event("oracle_ttl_set", epoch, &key_id, payload, &signing_key)?;

            let entry = cfg.oracles.entry(oracle_id.clone()).or_default();
            entry.schema_version = 1;
            entry.ttl_epochs = ttl_epochs;
            entry.updated_at_epoch = epoch;
            entry.key_id = key_id;
            entry
                .calibration_manifest_hash_hex
                .get_or_insert_with(|| "00".repeat(32));
            entry
                .disjointness_attestation
                .get_or_insert_with(|| "operator-attested-disjoint".to_string());
            let record_payload = OracleOperatorSigningPayload {
                oracle_id: &oracle_id,
                schema_version: entry.schema_version,
                ttl_epochs: entry.ttl_epochs,
                calibration_manifest_hash_hex: entry
                    .calibration_manifest_hash_hex
                    .as_deref()
                    .unwrap_or(""),
                calibration_epoch: entry.calibration_epoch,
                disjointness_attestation: entry.disjointness_attestation.as_deref().unwrap_or(""),
                nonoverlap_proof_uri: entry.nonoverlap_proof_uri.as_deref(),
                updated_at_epoch: entry.updated_at_epoch,
                key_id: &entry.key_id,
            };
            entry.signature_ed25519 = sign_oracle_record_payload(&signing_key, &record_payload)?;

            write_json_atomic(
                data_dir.join(ORACLE_OPERATOR_PATH),
                &cfg,
                "write oracle config failed",
            )?;
            append_governance_event(&data_dir, &event)?;
            Ok(json!({"status":"ok", "event_id": event.event_id}))
        }
        OracleCmd::SignOracleCalibration {
            data_dir,
            oracle_id,
            calib_hash,
            signing_key,
            key_id,
        } => {
            let _ = parse_hex32(&calib_hash)?;
            let mut cfg = read_oracle_config(&data_dir)?;
            let epoch = unix_epoch_now()?;
            let payload = json!({"oracle_id": oracle_id, "calibration_hash": calib_hash});
            let event = sign_governance_event(
                "oracle_calibration_rotated",
                epoch,
                &key_id,
                payload,
                &signing_key,
            )?;

            let entry = cfg.oracles.entry(oracle_id.clone()).or_default();
            if entry.ttl_epochs == 0 {
                entry.ttl_epochs = 1;
            }
            entry.calibration_manifest_hash_hex = Some(calib_hash.clone());
            entry.calibration_epoch = Some(epoch);
            entry.updated_at_epoch = epoch;
            entry.key_id = key_id;
            entry.schema_version = 1;
            entry
                .disjointness_attestation
                .get_or_insert_with(|| "operator-attested-disjoint".to_string());
            let record_payload = OracleOperatorSigningPayload {
                oracle_id: &oracle_id,
                schema_version: entry.schema_version,
                ttl_epochs: entry.ttl_epochs,
                calibration_manifest_hash_hex: entry
                    .calibration_manifest_hash_hex
                    .as_deref()
                    .unwrap_or(""),
                calibration_epoch: entry.calibration_epoch,
                disjointness_attestation: entry.disjointness_attestation.as_deref().unwrap_or(""),
                nonoverlap_proof_uri: entry.nonoverlap_proof_uri.as_deref(),
                updated_at_epoch: entry.updated_at_epoch,
                key_id: &entry.key_id,
            };
            entry.signature_ed25519 = sign_oracle_record_payload(&signing_key, &record_payload)?;

            write_json_atomic(
                data_dir.join(ORACLE_OPERATOR_PATH),
                &cfg,
                "write oracle config failed",
            )?;
            append_governance_event(&data_dir, &event)?;
            Ok(json!({"status":"ok", "event_id": event.event_id}))
        }
    }
}

fn run_epoch(cmd: EpochCmd) -> Result<serde_json::Value, String> {
    match cmd {
        EpochCmd::SignEpochControl {
            data_dir,
            to,
            signing_key,
            key_id,
        } => {
            let epoch = unix_epoch_now()?;
            let event = sign_governance_event(
                "epoch_advanced",
                epoch,
                &key_id,
                json!({"to": to}),
                &signing_key,
            )?;
            let control_payload = EpochControlSigningPayload {
                forced_epoch: to,
                updated_at_epoch: epoch,
                key_id: &key_id,
            };
            let signature_ed25519 = sign_epoch_control_payload(&signing_key, &control_payload)?;
            let control = json!({
                "forced_epoch": to,
                "updated_at_epoch": epoch,
                "key_id": key_id,
                "signature_ed25519": signature_ed25519,
                "event_id": event.event_id,
            });
            write_json_atomic(
                data_dir.join(EPOCH_CONTROL_PATH),
                &control,
                "write epoch control failed",
            )?;
            append_governance_event(&data_dir, &event)?;
            Ok(json!({"status":"ok"}))
        }
    }
}

fn run_governance(cmd: GovernanceCmd) -> Result<serde_json::Value, String> {
    match cmd {
        GovernanceCmd::Events { cmd } => match cmd {
            GovernanceEventsCmd::List { data_dir } => Ok(json!(read_governance_events(&data_dir)?)),
            GovernanceEventsCmd::Show { data_dir, event_id } => {
                let events = read_governance_events(&data_dir)?;
                let event = events
                    .into_iter()
                    .find(|ev| ev.event_id == event_id)
                    .ok_or_else(|| "governance event not found".to_string())?;
                Ok(json!(event))
            }
        },
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
                        &SignedGovernanceEvent {
                            event_id: sha256_hex(
                                serde_json::to_string(&gov)
                                    .map_err(|e| e.to_string())?
                                    .as_bytes(),
                            ),
                            event_type: "canary_reset".to_string(),
                            epoch: 0,
                            key_id: gov
                                .get("key_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string(),
                            payload: json!({"claim_name": claim_name, "holdout": holdout}),
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
            let sk = read_signing_key(&signing_key)?;
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
                &SignedGovernanceEvent {
                    event_id: sha256_hex(&contract.nullspec_id),
                    event_type: "nullspec_install".to_string(),
                    epoch: contract.epoch_created,
                    key_id: contract.created_by,
                    payload: json!({
                        "nullspec_id": hex::encode(contract.nullspec_id),
                        "oracle_id": contract.oracle_id,
                        "resolution_hash": hex::encode(contract.oracle_resolution_hash),
                    }),
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
                &SignedGovernanceEvent {
                    event_id: sha256_hex(&id),
                    event_type: "nullspec_activate".to_string(),
                    epoch: contract.epoch_created,
                    key_id: contract.created_by,
                    payload: json!({
                        "nullspec_id": nullspec_id,
                        "oracle_id": oracle_id,
                        "holdout": holdout,
                        "resolution_hash": hex::encode(contract.oracle_resolution_hash),
                    }),
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

fn sign_governance_event(
    event_type: &str,
    epoch: u64,
    key_id: &str,
    payload: serde_json::Value,
    signing_key: &Path,
) -> Result<SignedGovernanceEvent, String> {
    let signing = read_signing_key(signing_key)?;
    let to_sign = GovernanceEventPayload {
        event_type,
        epoch,
        key_id,
        payload: payload.clone(),
    };
    let signing_payload = canonical_json(&to_sign).map_err(|e| e.to_string())?;
    let sig = signing.sign(&signing_payload).to_bytes();
    Ok(SignedGovernanceEvent {
        event_id: sha256_hex(&signing_payload),
        event_type: event_type.to_string(),
        epoch,
        key_id: key_id.to_string(),
        payload,
        signature_ed25519: hex::encode(sig),
    })
}

fn sign_oracle_record_payload(
    signing_key: &Path,
    payload: &OracleOperatorSigningPayload<'_>,
) -> Result<String, String> {
    let signing = read_signing_key(signing_key)?;
    let canonical = canonical_json(payload).map_err(|e| e.to_string())?;
    let digest = sha256_domain(DOMAIN_ORACLE_OPERATOR_RECORD_V1, &canonical);
    Ok(hex::encode(signing.sign(&digest).to_bytes()))
}

fn sign_epoch_control_payload(
    signing_key: &Path,
    payload: &EpochControlSigningPayload<'_>,
) -> Result<String, String> {
    let signing = read_signing_key(signing_key)?;
    let canonical = canonical_json(payload).map_err(|e| e.to_string())?;
    let digest = sha256_domain(DOMAIN_EPOCH_CONTROL_V1, &canonical);
    Ok(hex::encode(signing.sign(&digest).to_bytes()))
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let key_bytes = fs::read(path).map_err(|e| e.to_string())?;
    let sk_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing key must be raw 32-byte seed".to_string())?;
    Ok(SigningKey::from_bytes(&sk_arr))
}

fn read_oracle_config(data_dir: &Path) -> Result<OracleOperatorConfig, String> {
    let path = data_dir.join(ORACLE_OPERATOR_PATH);
    if !path.exists() {
        return Ok(OracleOperatorConfig::default());
    }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn read_governance_events(data_dir: &Path) -> Result<Vec<SignedGovernanceEvent>, String> {
    let path = data_dir.join(GOVERNANCE_LOG_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str::<SignedGovernanceEvent>(line).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "expected 32-byte hex".to_string())
}

fn append_governance_event(data_dir: &Path, event: &SignedGovernanceEvent) -> Result<(), String> {
    let path = data_dir.join(GOVERNANCE_LOG_PATH);
    let payload = serde_json::to_vec(event).map_err(|e| e.to_string())?;
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

fn write_json_atomic(
    path: PathBuf,
    value: &impl Serialize,
    err_prefix: &str,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{err_prefix}: {e}"))?;
    }
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("{err_prefix}: {e}"))?;
    fs::write(&tmp, bytes).map_err(|e| format!("{err_prefix}: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("{err_prefix}: {e}"))?;
    Ok(())
}

fn unix_epoch_now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
