// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Compute alpha' = alpha * 2^{-k_total}.
pub fn alpha_prime(alpha: f64, k_bits_total: f64) -> f64 {
    alpha * 2f64.powf(-k_bits_total)
}

/// Certification barrier: 1 / alpha' = 2^{k_total} / alpha.
pub fn certification_barrier(alpha: f64, k_bits_total: f64) -> f64 {
    let ap = alpha_prime(alpha, k_bits_total);
    if ap <= 0.0 {
        f64::INFINITY
    } else {
        1.0 / ap
    }
}

/// §19.4 weighted arithmetic e-merge.
pub fn e_merge(e_values: &[f64], weights: &[f64]) -> EvidenceOSResult<f64> {
    if e_values.is_empty() || e_values.len() != weights.len() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let mut numer = 0.0;
    let mut denom = 0.0;
    for (&e, &w) in e_values.iter().zip(weights.iter()) {
        if w < 0.0 || !e.is_finite() || e < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        numer += w * e;
        denom += w;
    }
    if denom <= 0.0 {
        return Err(EvidenceOSError::InvalidArgument);
    }
    Ok(numer / denom)
}

/// §19.4 equal-weight e-merge.
pub fn e_merge_equal(e_values: &[f64]) -> EvidenceOSResult<f64> {
    if e_values.is_empty() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let weights = vec![1.0; e_values.len()];
    e_merge(e_values, &weights)
}

/// Only valid when e-processes are adapted to disjoint filtrations.
/// Use e_merge_equal when dependence is possible. See §19.4.
pub fn e_product(e_values: &[f64]) -> EvidenceOSResult<f64> {
    if e_values.is_empty() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let mut out = 1.0;
    for &e in e_values {
        if e <= 0.0 || !e.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if out > f64::MAX / e {
            return Err(EvidenceOSError::InvalidArgument);
        }
        out *= e;
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEvent {
    pub kind: String,
    pub bits: f64,
    pub meta: Value,
}

impl LedgerEvent {
    pub fn leak(kind: impl Into<String>, bits: f64, meta: Value) -> Self {
        Self {
            kind: kind.into(),
            bits,
            meta,
        }
    }

    pub fn wealth(kind: impl Into<String>, e_value: f64, meta: Value) -> Self {
        let mut m = meta;
        if let Value::Object(ref mut map) = m {
            map.insert("e_value".to_string(), Value::from(e_value));
        }
        Self {
            kind: kind.into(),
            bits: 0.0,
            meta: m,
        }
    }
}

/// §5.4 joint holdout leakage pool keyed by holdout id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointLeakagePool {
    pub holdout_id: String,
    pub k_bits_budget: f64,
    k_bits_spent: f64,
    pub frozen: bool,
}

impl JointLeakagePool {
    pub fn new(holdout_id: String, k_bits_budget: f64) -> EvidenceOSResult<Self> {
        if k_bits_budget < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(Self {
            holdout_id,
            k_bits_budget,
            k_bits_spent: 0.0,
            frozen: false,
        })
    }

    pub fn charge(&mut self, k_bits: f64) -> EvidenceOSResult<f64> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if k_bits < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let next = self.k_bits_spent + k_bits;
        if next > self.k_bits_budget + f64::EPSILON {
            self.frozen = true;
            return Err(EvidenceOSError::Frozen);
        }
        self.k_bits_spent = next;
        Ok(self.k_bits_remaining())
    }

    pub fn k_bits_remaining(&self) -> f64 {
        (self.k_bits_budget - self.k_bits_spent).max(0.0)
    }
    pub fn k_bits_spent(&self) -> f64 {
        self.k_bits_spent
    }
}

/// §13 Canary Pulse drift circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryPulse {
    alpha_drift: f64,
    e_drift: f64,
    frozen: bool,
}

impl CanaryPulse {
    pub fn new(alpha_drift: f64) -> EvidenceOSResult<Self> {
        if !(alpha_drift > 0.0 && alpha_drift < 1.0) {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(Self {
            alpha_drift,
            e_drift: 1.0,
            frozen: false,
        })
    }

    pub fn update(&mut self, e_drift_increment: f64) -> EvidenceOSResult<bool> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if e_drift_increment <= 0.0 || !e_drift_increment.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if self.e_drift > f64::MAX / e_drift_increment {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.e_drift *= e_drift_increment;
        if self.e_drift >= 1.0 / self.alpha_drift {
            self.frozen = true;
            return Err(EvidenceOSError::Frozen);
        }
        Ok(false)
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
    pub fn e_drift(&self) -> f64 {
        self.e_drift
    }
}

/// The Conservation Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConservationLedger {
    pub alpha: f64,
    pub k_bits_total: f64,
    pub wealth: f64,
    pub w_max: f64,
    pub events: Vec<LedgerEvent>,
    pub k_bits_budget: Option<f64>,
    pub frozen: bool,
}

impl ConservationLedger {
    pub fn new(alpha: f64) -> EvidenceOSResult<Self> {
        if !(alpha > 0.0 && alpha < 1.0) {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(Self {
            alpha,
            k_bits_total: 0.0,
            wealth: 1.0,
            w_max: 1.0,
            events: Vec::new(),
            k_bits_budget: None,
            frozen: false,
        })
    }

    pub fn with_budget(mut self, k_bits_budget: Option<f64>) -> Self {
        self.k_bits_budget = k_bits_budget;
        self
    }
    pub fn alpha_prime(&self) -> f64 {
        alpha_prime(self.alpha, self.k_bits_total)
    }
    pub fn barrier(&self) -> f64 {
        certification_barrier(self.alpha, self.k_bits_total)
    }
    pub fn can_certify(&self) -> bool {
        self.w_max >= self.barrier()
    }
    pub fn w_max(&self) -> f64 {
        self.w_max
    }

    pub fn charge(&mut self, k_bits: f64, kind: &str, meta: Value) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if k_bits < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let new_total = self.k_bits_total + k_bits;
        if let Some(b) = self.k_bits_budget {
            if new_total > b + f64::EPSILON {
                self.frozen = true;
                self.events.push(LedgerEvent::leak(
                    "freeze_budget_exhausted",
                    0.0,
                    json!({"overrun_bits": new_total - b}),
                ));
                return Err(EvidenceOSError::Frozen);
            }
        }
        self.k_bits_total = new_total;
        self.events
            .push(LedgerEvent::leak(kind.to_string(), k_bits, meta));
        Ok(())
    }

    pub fn settle_e_value(
        &mut self,
        e_value: f64,
        kind: &str,
        meta: Value,
    ) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if e_value <= 0.0 || !e_value.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if self.wealth > f64::MAX / e_value.max(1.0) {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.wealth *= e_value;
        self.w_max = self.w_max.max(self.wealth);
        self.events
            .push(LedgerEvent::wealth(kind.to_string(), e_value, meta));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn alpha_prime_correctness() {
        assert!((alpha_prime(0.05, 8.0) - 0.0001953125).abs() < 1e-12);
    }

    #[test]
    fn barrier_correctness() {
        assert!((certification_barrier(0.05, 8.0) - 5120.0).abs() < 1e-12);
    }

    #[test]
    fn w_max_tracks_peak_wealth() {
        let mut l = ConservationLedger::new(0.05).expect("ledger");
        l.settle_e_value(3.0, "a", Value::Null).expect("settle");
        l.settle_e_value(0.5, "b", Value::Null).expect("settle");
        assert!((l.w_max() - 3.0).abs() < 1e-12);
    }

    #[test]
    fn settle_overflow_returns_err() {
        let mut l = ConservationLedger::new(0.05).expect("ledger");
        l.wealth = 2.0;
        assert!(matches!(
            l.settle_e_value(f64::MAX, "x", Value::Null),
            Err(EvidenceOSError::InvalidArgument)
        ));
    }

    #[test]
    fn e_merge_uniform_weights() {
        assert!((e_merge_equal(&[2.0, 4.0]).expect("merge") - 3.0).abs() < 1e-12);
    }

    #[test]
    fn joint_pool_charges_correctly() {
        let mut p = JointLeakagePool::new("h".into(), 10.0).expect("pool");
        p.charge(3.0).expect("charge");
        let rem = p.charge(3.0).expect("charge");
        assert!((rem - 4.0).abs() < 1e-12);
        assert!(matches!(p.charge(5.0), Err(EvidenceOSError::Frozen)));
    }

    #[test]
    fn canary_pulse_freezes_at_threshold() {
        let mut c = CanaryPulse::new(0.05).expect("canary");
        assert!(matches!(c.update(25.0), Err(EvidenceOSError::Frozen)));
    }

    proptest! {
        #[test]
        fn conservation_ledger_invariants_hold_under_random_sequences(
            alpha in 0.000_1_f64..0.999_9,
            budget in 0.0_f64..256.0,
            ops in prop::collection::vec(
                (
                    proptest::bool::ANY,
                    0.0_f64..8.0,
                    0.01_f64..4.0,
                ),
                1..128,
            ),
        ) {
            let mut ledger = ConservationLedger::new(alpha)
                .expect("alpha strategy must produce a valid ledger")
                .with_budget(Some(budget));

            let mut expected_spent = 0.0_f64;
            let mut expected_wealth = 1.0_f64;
            let mut expected_w_max = 1.0_f64;
            let mut expected_frozen = false;

            for (is_charge, charge_bits, e_value) in ops {
                if is_charge {
                    let result = ledger.charge(charge_bits, "prop_charge", Value::Null);
                    if expected_frozen {
                        prop_assert!(matches!(result, Err(EvidenceOSError::Frozen)));
                        continue;
                    }

                    if expected_spent + charge_bits > budget + f64::EPSILON {
                        expected_frozen = true;
                        prop_assert!(matches!(result, Err(EvidenceOSError::Frozen)));
                    } else {
                        expected_spent += charge_bits;
                        prop_assert!(result.is_ok());
                    }
                } else {
                    let result = ledger.settle_e_value(e_value, "prop_settle", Value::Null);
                    if expected_frozen {
                        prop_assert!(matches!(result, Err(EvidenceOSError::Frozen)));
                        continue;
                    }

                    prop_assert!(result.is_ok());
                    expected_wealth *= e_value;
                    expected_w_max = expected_w_max.max(expected_wealth);
                }

                prop_assert!(ledger.k_bits_total >= 0.0);
                prop_assert!(ledger.alpha_prime() >= 0.0);
                prop_assert!(ledger.barrier().is_finite());
                prop_assert!(ledger.wealth > 0.0);
                prop_assert!(ledger.w_max() + 1e-12 >= ledger.wealth);
                prop_assert!((ledger.k_bits_total - expected_spent).abs() < 1e-9);
                prop_assert!((ledger.wealth - expected_wealth).abs() < 1e-9);
                prop_assert!((ledger.w_max() - expected_w_max).abs() < 1e-9);
                prop_assert_eq!(ledger.frozen, expected_frozen);
            }
        }
    }
}
