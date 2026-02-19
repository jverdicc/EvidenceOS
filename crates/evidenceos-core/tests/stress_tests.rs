use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use evidenceos_core::error::EvidenceOSError;
use evidenceos_core::ledger::{e_product, JointLeakagePool, TopicBudgetPool};

const STORM_CLAIMS: usize = 50_000;
const STORM_E_VALUE: f64 = 1.000_001;

fn is_graceful_error(err: &EvidenceOSError) -> bool {
    matches!(
        err,
        EvidenceOSError::Frozen | EvidenceOSError::InvalidArgument
    )
}

#[test]
fn storm_of_claims_handles_wealth_and_leakage_without_overflow_or_panic() {
    let mut leakage_pool = match JointLeakagePool::new("storm-holdout".to_string(), 250.0) {
        Ok(pool) => pool,
        Err(err) => panic!("failed to construct leakage pool: {err:?}"),
    };

    let mut accepted = 0usize;
    for _ in 0..STORM_CLAIMS {
        match leakage_pool.charge(0.005) {
            Ok(_) => accepted += 1,
            Err(err) => {
                assert!(
                    is_graceful_error(&err),
                    "storm charge should fail gracefully, got {err:?}"
                );
                break;
            }
        }
    }

    assert!(accepted > 10_000, "storm should process >=10k claims");
    assert!(leakage_pool.k_bits_spent().is_finite());

    let wealth_inputs = vec![STORM_E_VALUE; accepted.max(10_001)];
    let wealth = e_product(&wealth_inputs);
    assert!(wealth.is_ok(), "wealth accumulation should remain finite");

    let wealth_value = match wealth {
        Ok(value) => value,
        Err(err) => panic!("wealth should be available: {err:?}"),
    };
    assert!(wealth_value.is_finite());
    assert!(wealth_value > 1.0);
}

#[test]
fn boundary_transition_from_active_to_frozen_has_no_off_by_one_leakage() {
    let budget = 64.0;
    let mut pool = match JointLeakagePool::new("boundary".to_string(), budget) {
        Ok(pool) => pool,
        Err(err) => panic!("failed to construct pool: {err:?}"),
    };

    let near_boundary = budget - 1.0;
    let near_result = pool.charge(near_boundary);
    assert!(
        near_result.is_ok(),
        "pool should remain active before boundary"
    );

    let exact_result = pool.charge(1.0);
    assert!(
        exact_result.is_ok(),
        "exact boundary charge should be accepted"
    );

    let overflow_result = pool.charge(f64::EPSILON * 2.0);
    assert!(matches!(overflow_result, Err(EvidenceOSError::Frozen)));
    assert!(pool.frozen);

    let spent = pool.k_bits_spent();
    assert!(
        (spent - budget).abs() <= f64::EPSILON,
        "spent={spent}, budget={budget}"
    );
    assert!(pool.k_bits_remaining() <= f64::EPSILON);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_discos_probes_preserve_consistent_ledger_state() {
    let ledger = match TopicBudgetPool::new("kernel".to_string(), 100.0, 100.0) {
        Ok(pool) => Arc::new(Mutex::new(pool)),
        Err(err) => panic!("failed to construct topic pool: {err:?}"),
    };
    let success_counter = Arc::new(AtomicUsize::new(0));

    let probes = 64usize;
    let attempts_per_probe = 64usize;
    let k_charge = 0.05;

    let mut handles = Vec::with_capacity(probes);
    for _ in 0..probes {
        let ledger = Arc::clone(&ledger);
        let success_counter = Arc::clone(&success_counter);
        handles.push(tokio::spawn(async move {
            for _ in 0..attempts_per_probe {
                let mut guard = match ledger.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match guard.charge(k_charge, k_charge, 0.001) {
                    Ok(()) => {
                        success_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        assert!(
                            is_graceful_error(&err),
                            "concurrent charge should fail gracefully, got {err:?}"
                        );
                    }
                }
            }
        }));
    }

    for handle in handles {
        let joined = handle.await;
        assert!(joined.is_ok(), "probe task should not panic");
    }

    let guard = match ledger.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let expected_spent = success_counter.load(Ordering::Relaxed) as f64 * k_charge;
    let spent = guard.k_bits_spent();

    assert!((spent - expected_spent).abs() <= 1e-9);
    assert!(spent <= guard.k_bits_budget + f64::EPSILON);
    assert!(guard.access_credit_spent() <= guard.access_credit_budget + f64::EPSILON);
}

#[test]
fn invalid_inputs_return_graceful_errors_instead_of_panics() {
    let mut leakage_pool = match JointLeakagePool::new("graceful".to_string(), 1.0) {
        Ok(pool) => pool,
        Err(err) => panic!("failed to construct leakage pool: {err:?}"),
    };

    let negative_charge = leakage_pool.charge(-0.1);
    assert!(matches!(
        negative_charge,
        Err(EvidenceOSError::InvalidArgument)
    ));

    let mut topic_pool = match TopicBudgetPool::new("graceful-topic".to_string(), 1.0, 1.0) {
        Ok(pool) => pool,
        Err(err) => panic!("failed to construct topic pool: {err:?}"),
    };

    let invalid_topic_charge = topic_pool.charge(f64::INFINITY, 0.1, 0.1);
    assert!(matches!(
        invalid_topic_charge,
        Err(EvidenceOSError::InvalidArgument)
    ));

    let wealth_failure = e_product(&[1.0, 0.0]);
    assert!(matches!(
        wealth_failure,
        Err(EvidenceOSError::InvalidArgument)
    ));
}
