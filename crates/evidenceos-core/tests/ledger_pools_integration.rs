use evidenceos_core::error::EvidenceOSError;
use evidenceos_core::ledger::{JointLeakagePool, TopicBudgetPool};

#[test]
fn joint_leakage_pool_budget_boundary_matrix() {
    for (budget, fit, exceed) in [
        (0.0, 0.0, 0.1),
        (0.5, 0.5, 0.500_000_1),
        (100.0, 99.0, 101.0),
    ] {
        let mut pool = JointLeakagePool::new("h".into(), budget).expect("pool");
        assert!(pool.charge(fit).is_ok());
        assert!(matches!(pool.charge(exceed), Err(EvidenceOSError::Frozen)));
        assert!(matches!(pool.charge(0.0), Err(EvidenceOSError::Frozen)));
    }
}

#[test]
fn topic_budget_pool_boundary_matrix_with_covariance() {
    for (k_budget, access_budget, k_fit, cov_fit) in [
        (0.0, 0.0, 0.0, 0.0),
        (1.0, 1.0, 0.5, 0.5),
        (50.0, 50.0, 20.0, 30.0),
    ] {
        let mut pool = TopicBudgetPool::new("topic".into(), k_budget, access_budget).expect("pool");
        assert!(pool.charge(k_fit, k_fit, cov_fit).is_ok());
        let before_cov = pool.covariance_charge_total;
        assert!(before_cov >= cov_fit);

        let exceed_delta = (k_budget - k_fit).max(0.0) + 0.000_001;
        assert!(matches!(
            pool.charge(exceed_delta, exceed_delta, 0.1),
            Err(EvidenceOSError::Frozen)
        ));
    }
}
