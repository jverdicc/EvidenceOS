use evidenceos_daemon::server::{CreditBackend, CreditError};
use serde_json::json;
use tempfile::tempdir;

fn write_balances(path: &std::path::Path, balance: f64) {
    let payload = json!({
        "principals": {
            "p1": {
                "balance": balance,
                "epoch_id": "epoch-1"
            }
        }
    });
    std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
}

#[test]
fn test_config_file_backend_deducts_correctly() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("credit_balances.json");
    write_balances(&path, 100.0);

    let backend = CreditBackend::ConfigFile(path.clone());
    let remaining = backend.check_and_deduct("p1", "claim-a", 10.0).unwrap();
    assert_eq!(remaining, 90.0);

    let err = backend.check_and_deduct("p1", "claim-b", 95.0).unwrap_err();
    match err {
        CreditError::Insufficient {
            principal_id,
            requested,
            available,
        } => {
            assert_eq!(principal_id, "p1");
            assert_eq!(requested, 95.0);
            assert_eq!(available, 90.0);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn test_config_file_backend_atomic_write() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("credit_balances.json");
    write_balances(&path, 42.0);

    let backend = CreditBackend::ConfigFile(path.clone());
    let remaining = backend.check_and_deduct("p1", "claim-atomic", 2.0).unwrap();
    assert_eq!(remaining, 40.0);

    let raw = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed["principals"]["p1"]["balance"], json!(40.0));
    assert!(!dir.path().join("credit_balances.tmp").exists());
}

#[test]
fn test_none_backend_always_permits() {
    let backend = CreditBackend::None;
    let remaining = backend.check_and_deduct("p1", "claim-none", 1.0).unwrap();
    assert_eq!(remaining, f64::MAX);
}
