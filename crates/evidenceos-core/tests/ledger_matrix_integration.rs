use evidenceos_core::ledger::{e_merge, e_product, CanaryPulse, ConservationLedger};
use serde_json::Value;

#[test]
fn epsilon_delta_accounting_integration() {
    let mut l = ConservationLedger::new(0.05).expect("ledger");
    l.charge_all(1.0, 0.5, 0.2, 1.0, "x", Value::Null)
        .expect("charge");
    assert!((l.epsilon_total - 0.5).abs() < 1e-12);
    assert!((l.delta_total - 0.2).abs() < 1e-12);
}

#[test]
fn canary_pulse_integration() {
    let mut c = CanaryPulse::new(0.05).expect("canary");
    assert!(c.update(1.0).is_ok());
}

#[test]
fn e_merge_integration_matrix() {
    let m = e_merge(&[1.0, 3.0], &[0.25, 0.75]).expect("merge");
    assert!((m - 2.5).abs() < 1e-12);
}

#[test]
fn e_product_integration_matrix() {
    let p = e_product(&[2.0, 0.5, 3.0]).expect("product");
    assert!((p - 3.0).abs() < 1e-12);
}
