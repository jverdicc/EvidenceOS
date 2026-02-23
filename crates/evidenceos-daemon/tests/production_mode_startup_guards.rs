use std::process::Command;

use tempfile::TempDir;

fn run_daemon(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_evidenceos-daemon"));
    cmd.args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("daemon process should launch")
}

#[test]
fn production_mode_rejects_plaintext_holdouts_flag() {
    let temp = TempDir::new().expect("tmp");
    let output = run_daemon(
        &[
            "--data-dir",
            temp.path().to_str().expect("utf8"),
            "--allow-plaintext-holdouts",
        ],
        &[("EVIDENCEOS_PRODUCTION_MODE", "1")],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("forbids plaintext holdouts"));
}

#[test]
fn production_mode_rejects_insecure_synthetic_holdout_flag() {
    let temp = TempDir::new().expect("tmp");
    let output = run_daemon(
        &[
            "--data-dir",
            temp.path().to_str().expect("utf8"),
            "--insecure-synthetic-holdout",
        ],
        &[("EVIDENCEOS_PRODUCTION_MODE", "1")],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("forbids insecure synthetic holdouts"));
}

#[test]
fn production_mode_rejects_offline_ingest_without_operator_ack() {
    let temp = TempDir::new().expect("tmp");
    let output = run_daemon(
        &[
            "--data-dir",
            temp.path().to_str().expect("utf8"),
            "--offline-settlement-ingest",
        ],
        &[("EVIDENCEOS_PRODUCTION_MODE", "1")],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("offline settlement ingest bypass requires"));
}

#[test]
fn production_mode_offline_ingest_with_operator_ack_passes_startup_guard() {
    let temp = TempDir::new().expect("tmp");
    let output = run_daemon(
        &[
            "--data-dir",
            temp.path().to_str().expect("utf8"),
            "--offline-settlement-ingest",
            "--offline-settlement-ingest-operator-ack",
            "--auth-token",
            "token",
            "--auth-hmac-key",
            "hmac",
        ],
        &[("EVIDENCEOS_PRODUCTION_MODE", "1")],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--auth-token and --auth-hmac-key are mutually exclusive"));
    assert!(!stderr.contains("offline settlement ingest bypass requires"));
}
