// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use evidenceos_core::capsule::{ClaimCapsule, ClaimState};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const INDEX_SCHEMA_VERSION: i64 = 2;
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const CLAIM_CAPSULE_SCHEMA: &str = "evidenceos.v2.claim_capsule";

#[derive(Debug, Parser)]
#[command(name = "evidenceos-etl-indexer")]
#[command(about = "Build deterministic SQLite indexes from ETL files")]
struct Cli {
    #[arg(long)]
    etl: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Error)]
enum IndexerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json parse error at ETL index {index}: {source}")]
    Json {
        index: u64,
        #[source]
        source: serde_json::Error,
    },
    #[error("claim capsule decode failed at ETL index {index}: {source}")]
    ClaimCapsule {
        index: u64,
        #[source]
        source: serde_json::Error,
    },
    #[error("crc mismatch at ETL index {index}")]
    CrcMismatch { index: u64 },
    #[error("truncated ETL entry at ETL index {index}")]
    TruncatedEntry { index: u64 },
    #[error("unknown schema `{schema}` at ETL index {index}")]
    UnknownSchema { index: u64, schema: String },
    #[error("unknown event kind `{kind}` at ETL index {index}")]
    UnknownKind { index: u64, kind: String },
}

#[derive(Debug, Deserialize)]
struct ProbeEvent {
    action: String,
}

#[derive(Debug, Deserialize)]
struct CanaryIncident {
    claim_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RevocationEntry {
    capsule_hash_hex: String,
    reason: String,
    revoked_at_index: u64,
}

#[derive(Debug)]
struct SettlementRow {
    etl_index: u64,
    capsule_hash: Option<String>,
    claim_id: String,
    claim_name: Option<String>,
    arm_id: Option<u32>,
    intervention_id: Option<String>,
    intervention_version: Option<String>,
    outcome: String,
    k_bits_total: f64,
    ended_at: u64,
    topic_id: String,
    holdout_ref: String,
    nullspec_id: Option<String>,
    trial_nonce_b64: Option<String>,
    decision: i32,
}

#[derive(Debug)]
struct CapsuleRow {
    etl_index: u64,
    capsule_hash: Option<String>,
    claim_id: String,
    arm_id: Option<u32>,
    intervention_id: Option<String>,
    intervention_version: Option<String>,
    outcome: Option<String>,
    k_bits_total: f64,
}

#[derive(Debug)]
struct IndexedRows {
    settlements: Vec<SettlementRow>,
    capsules: Vec<CapsuleRow>,
}

fn record_checksum(len_bytes: [u8; 4], payload: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&len_bytes);
    hasher.update(payload);
    hasher.finalize()
}

fn etl_digest(path: &Path) -> Result<String, IndexerError> {
    let mut hasher = Sha256::new();
    let mut f = File::open(path)?;
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn trial_nonce_to_b64(capsule: &ClaimCapsule) -> Option<String> {
    let nonce_hex = capsule.trial_nonce_hex.as_ref()?;
    let raw = hex::decode(nonce_hex).ok()?;
    Some(STANDARD.encode(raw))
}

fn outcome_from_claim_state(state: ClaimState) -> Option<&'static str> {
    match state {
        ClaimState::Settled => Some("SETTLED"),
        ClaimState::Certified => Some("CERTIFIED"),
        ClaimState::Revoked => Some("REVOKED"),
        ClaimState::Tainted => Some("TAINTED"),
        ClaimState::Frozen => Some("FROZEN"),
        ClaimState::Stale => Some("STALE"),
        ClaimState::Uncommitted | ClaimState::Sealed | ClaimState::Executing => None,
    }
}

fn index_etl(etl_path: &Path) -> Result<IndexedRows, IndexerError> {
    let file = File::open(etl_path)?;
    let mut reader = BufReader::new(file);
    let mut etl_index = 0u64;
    let mut settlements = Vec::new();
    let mut capsules = Vec::new();

    loop {
        let mut len_bytes = [0u8; 4];
        match reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(IndexerError::Io(e)),
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut payload = vec![0u8; len];
        if reader.read_exact(&mut payload).is_err() {
            return Err(IndexerError::TruncatedEntry { index: etl_index });
        }
        let mut checksum_bytes = [0u8; 4];
        if reader.read_exact(&mut checksum_bytes).is_err() {
            return Err(IndexerError::TruncatedEntry { index: etl_index });
        }
        let expected = u32::from_le_bytes(checksum_bytes);
        let actual = record_checksum(len_bytes, &payload);
        if expected != actual {
            return Err(IndexerError::CrcMismatch { index: etl_index });
        }

        let value: Value =
            serde_json::from_slice(&payload).map_err(|source| IndexerError::Json {
                index: etl_index,
                source,
            })?;

        if let Some(schema) = value.get("schema").and_then(Value::as_str) {
            if schema != CLAIM_CAPSULE_SCHEMA {
                return Err(IndexerError::UnknownSchema {
                    index: etl_index,
                    schema: schema.to_string(),
                });
            }
            let capsule: ClaimCapsule =
                serde_json::from_value(value).map_err(|source| IndexerError::ClaimCapsule {
                    index: etl_index,
                    source,
                })?;

            let outcome = outcome_from_claim_state(capsule.state).map(ToOwned::to_owned);
            capsules.push(CapsuleRow {
                etl_index,
                capsule_hash: capsule.capsule_hash_hex().ok(),
                claim_id: capsule.claim_id_hex.clone(),
                arm_id: capsule.trial_arm_id,
                intervention_id: capsule.trial_intervention_id.clone(),
                intervention_version: capsule.trial_intervention_version.clone(),
                outcome: outcome.clone(),
                k_bits_total: capsule.ledger.k_bits_total,
            });

            if let Some(outcome) = outcome {
                settlements.push(SettlementRow {
                    etl_index,
                    capsule_hash: capsule.capsule_hash_hex().ok(),
                    claim_id: capsule.claim_id_hex,
                    claim_name: None,
                    arm_id: capsule.trial_arm_id,
                    intervention_id: capsule.trial_intervention_id,
                    intervention_version: capsule.trial_intervention_version,
                    outcome,
                    k_bits_total: capsule.ledger.k_bits_total,
                    ended_at: etl_index,
                    topic_id: capsule.topic_id_hex,
                    holdout_ref: capsule.holdout_ref,
                    nullspec_id: capsule.nullspec_id_hex,
                    trial_nonce_b64: trial_nonce_to_b64(&capsule),
                    decision: capsule.decision,
                });
            }
            etl_index = etl_index.saturating_add(1);
            continue;
        }

        if let Some(kind) = value.get("kind").and_then(Value::as_str) {
            match kind {
                "probe_event" => {
                    let probe: ProbeEvent =
                        serde_json::from_value(value).map_err(|source| IndexerError::Json {
                            index: etl_index,
                            source,
                        })?;
                    if !matches!(probe.action.as_str(), "ESCALATE" | "FREEZE") {
                        return Err(IndexerError::UnknownKind {
                            index: etl_index,
                            kind: format!("probe_event:{}", probe.action),
                        });
                    }
                }
                "canary_incident" => {
                    let canary: CanaryIncident =
                        serde_json::from_value(value).map_err(|source| IndexerError::Json {
                            index: etl_index,
                            source,
                        })?;
                    let _ = canary.claim_name;
                }
                _ => {
                    return Err(IndexerError::UnknownKind {
                        index: etl_index,
                        kind: kind.to_string(),
                    });
                }
            }
            etl_index = etl_index.saturating_add(1);
            continue;
        }

        let revocation: RevocationEntry =
            serde_json::from_value(value).map_err(|source| IndexerError::Json {
                index: etl_index,
                source,
            })?;
        let _ = (
            revocation.capsule_hash_hex,
            revocation.reason,
            revocation.revoked_at_index,
        );
        etl_index = etl_index.saturating_add(1);
    }

    Ok(IndexedRows {
        settlements,
        capsules,
    })
}

fn apply_schema(conn: &Connection) -> Result<(), IndexerError> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS claim_capsules(
            etl_index INTEGER PRIMARY KEY NOT NULL,
            capsule_hash TEXT,
            claim_id TEXT,
            arm_id INTEGER,
            intervention_id TEXT,
            intervention_version TEXT,
            outcome TEXT,
            k_bits_total REAL
         );
         CREATE TABLE IF NOT EXISTS claim_settlements(
            etl_index INTEGER PRIMARY KEY NOT NULL,
            capsule_hash TEXT,
            claim_id TEXT,
            claim_name TEXT,
            arm_id INTEGER,
            intervention_id TEXT,
            intervention_version TEXT,
            outcome TEXT NOT NULL,
            k_bits_total REAL,
            ended_at INTEGER NOT NULL,
            topic_id TEXT,
            holdout_ref TEXT,
            nullspec_id TEXT,
            trial_nonce_b64 TEXT,
            decision INTEGER
         );
         CREATE VIEW IF NOT EXISTS settlements AS
            SELECT etl_index,capsule_hash,claim_id,claim_name,arm_id,intervention_id,outcome,k_bits_total,ended_at,topic_id,holdout_ref,decision
            FROM claim_settlements;
         CREATE TABLE IF NOT EXISTS index_manifest(
            id INTEGER PRIMARY KEY CHECK(id = 1),
            etl_file_digest TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            tool_version TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS schema_version(id INTEGER PRIMARY KEY CHECK(id = 1), version INTEGER NOT NULL);
         INSERT INTO schema_version(id, version) VALUES(1, 2)
           ON CONFLICT(id) DO UPDATE SET version=excluded.version;
         CREATE INDEX IF NOT EXISTS settlements_arm_id_idx ON claim_settlements(arm_id);
         CREATE INDEX IF NOT EXISTS settlements_intervention_id_idx ON claim_settlements(intervention_id);
         CREATE INDEX IF NOT EXISTS settlements_intervention_version_idx ON claim_settlements(intervention_version);
         CREATE INDEX IF NOT EXISTS settlements_outcome_idx ON claim_settlements(outcome);
         CREATE INDEX IF NOT EXISTS settlements_k_bits_total_idx ON claim_settlements(k_bits_total);
         CREATE INDEX IF NOT EXISTS settlements_arm_outcome_idx ON claim_settlements(arm_id, outcome);
         CREATE INDEX IF NOT EXISTS settlements_intervention_outcome_idx ON claim_settlements(intervention_id, outcome);
         CREATE INDEX IF NOT EXISTS settlements_claim_name_idx ON claim_settlements(claim_name);
         CREATE INDEX IF NOT EXISTS settlements_ended_at_idx ON claim_settlements(ended_at);",
    )?;
    Ok(())
}

fn migrate_schema(db_path: &Path) -> Result<(), IndexerError> {
    let mut conn = Connection::open(db_path)?;
    let tx = conn.transaction()?;
    apply_schema(&tx)?;

    let legacy_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='settlements')",
        [],
        |r| r.get(0),
    )?;
    let claim_settlements_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='claim_settlements')",
        [],
        |r| r.get(0),
    )?;

    if legacy_exists && claim_settlements_exists {
        tx.execute_batch(
            "INSERT OR IGNORE INTO claim_settlements(
                etl_index,capsule_hash,claim_id,claim_name,arm_id,intervention_id,intervention_version,outcome,k_bits_total,ended_at,topic_id,holdout_ref,nullspec_id,trial_nonce_b64,decision
             )
             SELECT etl_index,capsule_hash,claim_id,claim_name,arm_id,intervention_id,NULL,outcome,k_bits_total,ended_at,topic_id,holdout_ref,NULL,NULL,decision
             FROM settlements;",
        )?;
    }

    tx.commit()?;
    Ok(())
}

fn build_index(etl_path: &Path, out_path: &Path) -> Result<(), IndexerError> {
    if out_path.exists() {
        migrate_schema(out_path)?;
    }
    let digest = etl_digest(etl_path)?;
    let rows = index_etl(etl_path)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = out_path.with_extension("tmp");
    if tmp_path.exists() {
        fs::remove_file(&tmp_path)?;
    }

    let mut conn = Connection::open(&tmp_path)?;
    let tx = conn.transaction()?;
    apply_schema(&tx)?;

    {
        let mut stmt = tx.prepare(
            "INSERT INTO claim_capsules(etl_index,capsule_hash,claim_id,arm_id,intervention_id,intervention_version,outcome,k_bits_total)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        )?;
        for row in &rows.capsules {
            stmt.execute(params![
                row.etl_index,
                row.capsule_hash,
                row.claim_id,
                row.arm_id,
                row.intervention_id,
                row.intervention_version,
                row.outcome,
                row.k_bits_total
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare(
            "INSERT INTO claim_settlements(etl_index,capsule_hash,claim_id,claim_name,arm_id,intervention_id,intervention_version,outcome,k_bits_total,ended_at,topic_id,holdout_ref,nullspec_id,trial_nonce_b64,decision)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        )?;
        for row in &rows.settlements {
            stmt.execute(params![
                row.etl_index,
                row.capsule_hash,
                row.claim_id,
                row.claim_name,
                row.arm_id,
                row.intervention_id,
                row.intervention_version,
                row.outcome,
                row.k_bits_total,
                row.ended_at,
                row.topic_id,
                row.holdout_ref,
                row.nullspec_id,
                row.trial_nonce_b64,
                row.decision
            ])?;
        }
    }

    tx.execute(
        "INSERT INTO index_manifest(id,etl_file_digest,schema_version,tool_version)
         VALUES(1,?1,?2,?3)
         ON CONFLICT(id) DO UPDATE SET etl_file_digest=excluded.etl_file_digest, schema_version=excluded.schema_version, tool_version=excluded.tool_version",
        params![digest, INDEX_SCHEMA_VERSION, TOOL_VERSION],
    )?;
    tx.commit()?;

    if out_path.exists() {
        fs::remove_file(out_path)?;
    }
    fs::rename(tmp_path, out_path)?;
    Ok(())
}

fn main() -> Result<(), IndexerError> {
    let cli = Cli::parse();
    build_index(&cli.etl, &cli.output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn append_record(f: &mut File, payload: &[u8]) {
        let len = (payload.len() as u32).to_le_bytes();
        let crc = record_checksum(len, payload).to_le_bytes();
        f.write_all(&len).expect("len");
        f.write_all(payload).expect("payload");
        f.write_all(&crc).expect("crc");
    }

    #[test]
    fn rejects_crc_corruption() {
        let temp = TempDir::new().expect("temp");
        let etl = temp.path().join("etl.log");
        let mut f = File::create(&etl).expect("etl");
        let payload =
            serde_json::to_vec(&serde_json::json!({"kind":"probe_event","action":"FREEZE"}))
                .expect("json");
        let len = (payload.len() as u32).to_le_bytes();
        f.write_all(&len).expect("len");
        f.write_all(&payload).expect("payload");
        f.write_all(&0u32.to_le_bytes()).expect("bad crc");
        drop(f);

        let db = temp.path().join("index.sqlite");
        let err = build_index(&etl, &db).expect_err("crc must fail");
        assert!(matches!(err, IndexerError::CrcMismatch { .. }));
    }

    #[test]
    fn creates_expected_indexes_and_query_results() {
        let temp = TempDir::new().expect("temp");
        let etl = temp.path().join("etl.log");
        let mut f = File::create(&etl).expect("etl");

        for (arm, iid, iver, outcome) in [
            (7, "int-7", "v1", "Frozen"),
            (8, "int-8", "v2", "Certified"),
            (7, "int-7", "v1", "Stale"),
        ] {
            let capsule = serde_json::json!({
                "schema": CLAIM_CAPSULE_SCHEMA,
                "claim_id_hex": format!("11{}", arm),
                "topic_id_hex": "22",
                "output_schema_id": "legacy/v1",
                "code_ir_manifests": [],
                "dependency_capsule_hashes": [],
                "structured_output_hash_hex": "aa",
                "canonical_output_hash_hex": "bb",
                "kout_bits_upper_bound": 0,
                "wasm_hash_hex": "cc",
                "judge_trace_hash_hex": "dd",
                "holdout_ref": "h",
                "holdout_commitment_hex": "ee",
                "ledger": {
                    "alpha": 0.1,"log_alpha_target": 0.0,"alpha_prime": 0.1,"log_alpha_prime": 0.0,
                    "k_bits_total": 2.0,"barrier_threshold": 0.0,"barrier": 0.0,"wealth": 0.0,
                    "w_max": 0.0,"epsilon_total": 0.0,"delta_total": 0.0,"access_credit_spent": 0.0,"compute_fuel_spent": 0.0
                },
                "ledger_receipts": [],
                "e_value": 1.0,
                "certified": false,
                "decision": 1,
                "reason_codes": [],
                "environment_attestations": {"runtime_version": "r","aspec_version": "a","protocol_version": "p"},
                "state": outcome,
                "trial_arm_id": arm,
                "trial_intervention_id": iid,
                "trial_intervention_version": iver
            });
            append_record(&mut f, &serde_json::to_vec(&capsule).expect("capsule"));
        }
        drop(f);

        let db = temp.path().join("index.sqlite");
        build_index(&etl, &db).expect("index build");

        let conn = Connection::open(&db).expect("open db");

        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (
                    'settlements_arm_id_idx','settlements_intervention_id_idx','settlements_intervention_version_idx',
                    'settlements_outcome_idx','settlements_k_bits_total_idx','settlements_arm_outcome_idx','settlements_intervention_outcome_idx'
                )",
                [],
                |r| r.get(0),
            )
            .expect("index count");
        assert_eq!(idx_count, 7);

        let arm_outcome_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM settlements WHERE arm_id = 7 AND outcome = 'FROZEN'",
                [],
                |r| r.get(0),
            )
            .expect("query rows");
        assert_eq!(arm_outcome_rows, 1);

        let intervention_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM settlements WHERE intervention_id = 'int-7' AND outcome = 'STALE'",
                [],
                |r| r.get(0),
            )
            .expect("query rows");
        assert_eq!(intervention_rows, 1);

        let plan: Option<String> = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT * FROM claim_settlements WHERE arm_id=7 AND outcome='FROZEN'",
                [],
                |r| r.get(3),
            )
            .optional()
            .expect("explain");
        assert!(plan.is_some());
    }
}
