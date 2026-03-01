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

    // At a magnitude of 64.0, tiny sub-ULP additions can round away; use a
    // representable excess that is strictly greater than the EPSILON tolerance.
    let overflow_result = pool.charge(1e-12);
    assert!(matches!(overflow_result, Err(EvidenceOSError::Frozen)));
    assert!(pool.frozen);

    let post_frozen_result = pool.charge(1.0);
    assert!(matches!(post_frozen_result, Err(EvidenceOSError::Frozen)));

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

#[test]
fn etl_million_append_memory_bound_and_proof_validation() {
    use evidenceos_core::etl::{verify_consistency_proof, verify_inclusion_proof, Etl};

    const ENTRIES: usize = 1_000_000;
    const MEM_CAP_KB: u64 = 350_000;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("etl-million.log");
    let mut etl = Etl::open_or_create(&path).expect("etl");

    for i in 0..ENTRIES {
        let payload = format!("entry-{i:08}");
        etl.append(payload.as_bytes()).expect("append");
    }

    assert_eq!(etl.tree_size(), ENTRIES as u64);

    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let vmrss_line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .expect("VmRSS");
    let vmrss_kb: u64 = vmrss_line
        .split_whitespace()
        .nth(1)
        .expect("vmrss value")
        .parse()
        .expect("parse vmrss");
    assert!(
        vmrss_kb <= MEM_CAP_KB,
        "rss exceeded cap: {vmrss_kb}KB > {MEM_CAP_KB}KB"
    );

    let idx = 777_777u64;
    let leaf = etl.leaf_hash_at(idx).expect("leaf");
    let root = etl.root_hash();
    let inclusion = etl.inclusion_proof(idx).expect("inclusion");
    assert!(verify_inclusion_proof(
        &inclusion,
        &leaf,
        idx as usize,
        ENTRIES,
        &root
    ));

    let old_size = 500_000u64;
    let old_root = etl.root_at_size(old_size).expect("old root");
    let consistency = etl
        .consistency_proof(old_size, ENTRIES as u64)
        .expect("consistency");
    assert!(verify_consistency_proof(
        &old_root,
        &root,
        old_size as usize,
        ENTRIES,
        &consistency
    ));
}
