use std::collections::HashSet;
use std::sync::Arc;

use proptest::prelude::*;

use crate::etl::ClaimSettlementEvent;
use crate::ledger;

use super::router::TrialRouter;
use super::{ClassicalSupportBound, EpistemicIntervention};

#[derive(Clone)]
struct TestArm(&'static str);

impl EpistemicIntervention for TestArm {
    fn intervention_id(&self) -> &str {
        self.0
    }

    fn calculate_k_cost(&self, alphabet_size: u64, transcript_len: usize) -> f64 {
        ClassicalSupportBound.calculate_k_cost(alphabet_size, transcript_len)
    }

    fn certification_threshold(&self, alpha: f64, k_tot: f64) -> f64 {
        ClassicalSupportBound.certification_threshold(alpha, k_tot)
    }

    fn nullspec_id(&self) -> &str {
        "nullspec.test.v1"
    }
}

#[test]
fn threshold_matches_existing_kernel_to_6dp() {
    let threshold = ClassicalSupportBound.certification_threshold(0.05, 8.0);
    let expected = ledger::certification_barrier(0.05, 8.0);
    assert!((threshold - expected).abs() < 1e-6);
}

#[test]
fn k_cost_matches_log2_existing_charge() {
    let k = ClassicalSupportBound.calculate_k_cost(16, 1);
    assert!((k - 4.0).abs() < 1e-12);
}

#[test]
fn assign_balances_two_arms_approximately() {
    let arm_a: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("a"));
    let arm_b: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("b"));
    let router = TrialRouter::new(vec![arm_a, arm_b]);

    let mut counts = [0usize; 2];
    for _ in 0..10_000 {
        let (arm, _) = router.assign();
        if arm.intervention_id() == "a" {
            counts[0] += 1;
        } else {
            counts[1] += 1;
        }
    }
    let p_a = counts[0] as f64 / 10_000.0;
    let p_b = counts[1] as f64 / 10_000.0;
    assert!((0.45..=0.55).contains(&p_a), "p_a={p_a}");
    assert!((0.45..=0.55).contains(&p_b), "p_b={p_b}");
}

#[test]
fn assign_nonce_is_unique_across_two_calls() {
    let arm_a: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("a"));
    let arm_b: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("b"));
    let router = TrialRouter::new(vec![arm_a, arm_b]);

    let (_, n1) = router.assign();
    let (_, n2) = router.assign();
    assert_ne!(n1, n2);
}

#[test]
fn single_arm_router_always_returns_that_arm() {
    let only: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("only"));
    let router = TrialRouter::new(vec![Arc::clone(&only)]);

    for _ in 0..128 {
        let (arm, _) = router.assign();
        assert_eq!(arm.intervention_id(), "only");
    }
}

proptest! {
    #[test]
    fn prop_threshold_matches_kernel(alphabet_size in 2u64..=256, k_tot in 0.0f64..=64.0f64) {
        let alpha = 0.05;
        let threshold = ClassicalSupportBound.certification_threshold(alpha, k_tot);
        let expected = ledger::certification_barrier(alpha, k_tot);
        prop_assert!((threshold - expected).abs() < 1e-9);

        let k_cost = ClassicalSupportBound.calculate_k_cost(alphabet_size, 1);
        let expected_cost = (alphabet_size as f64).log2();
        prop_assert!((k_cost - expected_cost).abs() < 1e-12);
    }

    #[test]
    fn prop_claim_settlement_roundtrip_identity(
        claim_id in "[a-zA-Z0-9_-]{1,32}",
        outcome in "[A-Z_]{3,16}",
        k_bits_total in 0u64..=1_000_000,
        intervention_id in proptest::option::of("[a-zA-Z0-9_.-]{1,32}"),
        trial_nonce in proptest::option::of("[a-f0-9]{2,64}"),
        arm_assigned_at in proptest::option::of(0u64..=1_000_000),
    ) {
        let event = ClaimSettlementEvent {
            claim_id,
            outcome,
            k_bits_total,
            intervention_id,
            trial_nonce,
            arm_assigned_at,
        };
        let bytes = serde_json::to_vec(&event).unwrap();
        let decoded: ClaimSettlementEvent = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(decoded, event);
    }

    #[test]
    fn prop_legacy_events_deserialize(
        claim_id in "[a-zA-Z0-9_-]{1,32}",
        outcome in "[A-Z_]{3,16}",
        k_bits_total in 0u64..=1_000_000,
    ) {
        #[derive(serde::Serialize)]
        struct LegacyEvent {
            claim_id: String,
            outcome: String,
            k_bits_total: u64,
        }

        let legacy = LegacyEvent { claim_id, outcome, k_bits_total };
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let decoded: ClaimSettlementEvent = serde_json::from_slice(&bytes).unwrap();
        prop_assert!(decoded.intervention_id.is_none());
        prop_assert!(decoded.trial_nonce.is_none());
        prop_assert!(decoded.arm_assigned_at.is_none());
    }
}

#[test]
fn random_nonce_set_has_no_duplicates_for_small_sample() {
    let arm_a: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("a"));
    let arm_b: Arc<dyn EpistemicIntervention> = Arc::new(TestArm("b"));
    let router = TrialRouter::new(vec![arm_a, arm_b]);
    let mut seen = HashSet::new();
    for _ in 0..2048 {
        let (_, nonce) = router.assign();
        assert!(seen.insert(nonce));
    }
}
