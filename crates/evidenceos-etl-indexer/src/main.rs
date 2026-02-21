// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use evidenceos_core::capsule::{ClaimCapsule, ClaimState};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

const INDEX_SCHEMA_VERSION: i64 = 1;
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
    #[error("sqlite3 execution failed: {0}")]
    SqliteExec(String),
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
    outcome: String,
    k_bits_total: f64,
    ended_at: u64,
    topic_id: String,
    holdout_ref: String,
    decision: i32,
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

fn sql_text(value: Option<&str>) -> String {
    match value {
        Some(v) => format!("'{}'", v.replace('\'', "''")),
        None => "NULL".to_string(),
    }
}

fn sql_i64(value: Option<i64>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "NULL".to_string(),
    }
}

fn build_sql(rows: &[SettlementRow], digest: &str) -> String {
    let mut sql = String::new();
    sql.push_str(
        "PRAGMA journal_mode=WAL;\nPRAGMA synchronous=FULL;\nPRAGMA foreign_keys=ON;\nBEGIN IMMEDIATE;\n",
    );
    sql.push_str(
        "CREATE TABLE settlements(\
            etl_index INTEGER PRIMARY KEY NOT NULL,\
            capsule_hash TEXT,\
            claim_id TEXT,\
            claim_name TEXT,\
            arm_id INTEGER,\
            intervention_id TEXT,\
            outcome TEXT NOT NULL,\
            k_bits_total REAL,\
            ended_at INTEGER NOT NULL,\
            topic_id TEXT,\
            holdout_ref TEXT,\
            decision INTEGER\
        );\n",
    );
    sql.push_str(
        "CREATE TABLE index_manifest(\
            id INTEGER PRIMARY KEY CHECK(id = 1),\
            etl_file_digest TEXT NOT NULL,\
            schema_version INTEGER NOT NULL,\
            tool_version TEXT NOT NULL\
        );\n",
    );
    sql.push_str("CREATE INDEX settlements_arm_outcome_idx ON settlements(arm_id, outcome);\n");
    sql.push_str("CREATE INDEX settlements_intervention_outcome_idx ON settlements(intervention_id, outcome);\n");
    sql.push_str("CREATE INDEX settlements_claim_name_idx ON settlements(claim_name);\n");
    sql.push_str("CREATE INDEX settlements_ended_at_idx ON settlements(ended_at);\n");

    for row in rows {
        let _ = writeln!(
            sql,
            "INSERT INTO settlements(etl_index,capsule_hash,claim_id,claim_name,arm_id,intervention_id,outcome,k_bits_total,ended_at,topic_id,holdout_ref,decision) VALUES({},{},{},{},{},{},{},{},{},{},{},{});",
            row.etl_index,
            sql_text(row.capsule_hash.as_deref()),
            sql_text(Some(&row.claim_id)),
            sql_text(row.claim_name.as_deref()),
            sql_i64(row.arm_id.map(i64::from)),
            sql_text(row.intervention_id.as_deref()),
            sql_text(Some(&row.outcome)),
            row.k_bits_total,
            row.ended_at,
            sql_text(Some(&row.topic_id)),
            sql_text(Some(&row.holdout_ref)),
            row.decision,
        );
    }

    let _ = writeln!(
        sql,
        "INSERT INTO index_manifest(id,etl_file_digest,schema_version,tool_version) VALUES(1,{}, {}, {});",
        sql_text(Some(digest)),
        INDEX_SCHEMA_VERSION,
        sql_text(Some(TOOL_VERSION))
    );
    sql.push_str("COMMIT;\nVACUUM;\n");
    sql
}

fn outcome_from_claim_state(state: ClaimState) -> Option<&'static str> {
    match state {
        ClaimState::Settled => Some("SETTLED"),
        ClaimState::Certified => Some("CERTIFIED"),
        ClaimState::Revoked => Some("REVOKED"),
        ClaimState::Tainted => Some("TAINTED"),
        ClaimState::Frozen => Some("FREEZE"),
        ClaimState::Stale => Some("STALE"),
        ClaimState::Uncommitted | ClaimState::Sealed | ClaimState::Executing => None,
    }
}

fn index_etl(etl_path: &Path) -> Result<Vec<SettlementRow>, IndexerError> {
    let file = File::open(etl_path)?;
    let mut reader = BufReader::new(file);
    let mut etl_index = 0u64;
    let mut rows = Vec::new();

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
            if let Some(outcome) = outcome_from_claim_state(capsule.state) {
                rows.push(SettlementRow {
                    etl_index,
                    capsule_hash: capsule.capsule_hash_hex().ok(),
                    claim_id: capsule.claim_id_hex,
                    claim_name: None,
                    arm_id: capsule.trial_arm_id,
                    intervention_id: capsule.trial_intervention_id,
                    outcome: outcome.to_string(),
                    k_bits_total: capsule.ledger.k_bits_total,
                    ended_at: etl_index,
                    topic_id: capsule.topic_id_hex,
                    holdout_ref: capsule.holdout_ref,
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
                    })
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

    Ok(rows)
}

fn build_index(etl_path: &Path, out_path: &Path) -> Result<(), IndexerError> {
    let digest = etl_digest(etl_path)?;
    let rows = index_etl(etl_path)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = out_path.with_extension("tmp");
    let sql_path = out_path.with_extension("sql");
    if tmp_path.exists() {
        fs::remove_file(&tmp_path)?;
    }

    let sql = build_sql(&rows, &digest);
    let mut sql_file = File::create(&sql_path)?;
    sql_file.write_all(sql.as_bytes())?;
    drop(sql_file);

    let output = Command::new("sqlite3")
        .arg(&tmp_path)
        .arg(format!(".read {}", sql_path.display()))
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        return Err(IndexerError::SqliteExec(format!(
            "stdout={stdout}; stderr={stderr}"
        )));
    }

    fs::remove_file(&sql_path)?;
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
    use std::process::Command;
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
    fn writes_manifest_and_settlement_rows() {
        let temp = TempDir::new().expect("temp");
        let etl = temp.path().join("etl.log");
        let mut f = File::create(&etl).expect("etl");

        let capsule = serde_json::json!({
            "schema": CLAIM_CAPSULE_SCHEMA,
            "claim_id_hex": "11",
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
                "alpha": 0.1,
                "log_alpha_target": 0.0,
                "alpha_prime": 0.1,
                "log_alpha_prime": 0.0,
                "k_bits_total": 2.0,
                "barrier_threshold": 0.0,
                "barrier": 0.0,
                "wealth": 0.0,
                "w_max": 0.0,
                "epsilon_total": 0.0,
                "delta_total": 0.0,
                "access_credit_spent": 0.0,
                "compute_fuel_spent": 0.0
            },
            "ledger_receipts": [],
            "e_value": 1.0,
            "certified": false,
            "decision": 1,
            "reason_codes": [],
            "environment_attestations": {
                "runtime_version": "r",
                "aspec_version": "a",
                "protocol_version": "p"
            },
            "state": "Frozen",
            "trial_arm_id": 7,
            "trial_intervention_id": "int-7"
        });

        append_record(
            &mut f,
            &serde_json::to_vec(&serde_json::json!({"kind":"probe_event","action":"FREEZE"}))
                .expect("probe"),
        );
        append_record(&mut f, &serde_json::to_vec(&capsule).expect("capsule"));
        drop(f);

        let db = temp.path().join("index.sqlite");
        build_index(&etl, &db).expect("index build");

        let query = "SELECT COUNT(*) FROM settlements WHERE arm_id = 7 AND outcome = 'FREEZE';";
        let out = Command::new("sqlite3")
            .arg(&db)
            .arg(query)
            .output()
            .expect("sqlite3 query");
        assert!(out.status.success());
        let rows = String::from_utf8(out.stdout).expect("utf8");
        assert_eq!(rows.trim(), "1");
    }
}
