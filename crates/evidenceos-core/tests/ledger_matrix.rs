use evidenceos_core::error::EvidenceOSError;
use evidenceos_core::ledger::{
    alpha_prime, certification_barrier, e_merge, e_merge_equal, e_product, CanaryPulse,
    ConservationLedger, JointLeakagePool, TopicBudgetPool,
};
use serde_json::Value;

#[test]
fn ledger_public_api_matrix() {
    assert!(alpha_prime(0.1, 3.0) < 0.1);
    assert!(certification_barrier(0.1, 3.0) > 0.0);
    assert!(e_merge(&[1.0, 2.0], &[0.5, 0.5]).is_ok());
    assert!(e_merge_equal(&[1.0, 2.0]).is_ok());
    assert!(e_product(&[1.5, 2.0]).is_ok());

    assert!(JointLeakagePool::new("h".into(), f64::NAN).is_err());
    assert!(TopicBudgetPool::new("topic".into(), 2.0, 2.0).is_ok());

    let mut canary = CanaryPulse::new(0.1).expect("canary");
    assert!(canary.update(1.5).is_ok());

    let mut ledger = ConservationLedger::new(0.1)
        .expect("ledger")
        .with_budgets(Some(1.0), Some(1.0));
    ledger
        .charge_all(0.5, 0.0, 0.0, 0.5, "matrix", Value::Null)
        .expect("charge");
    assert!(matches!(
        ledger.charge_all(1.0, 0.0, 0.0, 0.0, "matrix", Value::Null),
        Err(EvidenceOSError::Frozen)
    ));
}
