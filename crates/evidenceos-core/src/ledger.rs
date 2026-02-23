// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Compute alpha' = alpha * 2^{-k_total}.
pub fn alpha_prime(alpha: f64, k_bits_total: f64) -> f64 {
    log_alpha_prime(alpha, k_bits_total).exp()
}

/// Certification barrier: 1 / alpha' = 2^{k_total} / alpha.
pub fn certification_barrier(alpha: f64, k_bits_total: f64) -> f64 {
    barrier_threshold(alpha, k_bits_total).exp()
}

/// log(alpha_target).
pub fn log_alpha_target(alpha: f64) -> f64 {
    alpha.ln()
}

/// log(alpha') = log(alpha_target) - k * ln(2).
pub fn log_alpha_prime(alpha: f64, k_bits_total: f64) -> f64 {
    log_alpha_target(alpha) - (k_bits_total * std::f64::consts::LN_2)
}

/// Barrier threshold B in log-space where certify iff ln(w_max) >= B.
pub fn barrier_threshold(alpha: f64, k_bits_total: f64) -> f64 {
    -log_alpha_prime(alpha, k_bits_total)
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
        if !k_bits_budget.is_finite() || k_bits_budget < 0.0 {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicBudgetPool {
    pub topic_id: String,
    pub k_bits_budget: f64,
    pub access_credit_budget: f64,
    pub covariance_charge_total: f64,
    k_bits_spent: f64,
    access_credit_spent: f64,
    #[serde(default)]
    reserved_k_bits: f64,
    #[serde(default)]
    reserved_access_credit: f64,
    pub frozen: bool,
}

impl TopicBudgetPool {
    pub fn new(
        topic_id: String,
        k_bits_budget: f64,
        access_credit_budget: f64,
    ) -> EvidenceOSResult<Self> {
        if !k_bits_budget.is_finite()
            || !access_credit_budget.is_finite()
            || k_bits_budget < 0.0
            || access_credit_budget < 0.0
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(Self {
            topic_id,
            k_bits_budget,
            access_credit_budget,
            covariance_charge_total: 0.0,
            k_bits_spent: 0.0,
            access_credit_spent: 0.0,
            reserved_k_bits: 0.0,
            reserved_access_credit: 0.0,
            frozen: false,
        })
    }

    pub fn reserve(&mut self, k_bits: f64, access_credit: f64) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if !k_bits.is_finite() || !access_credit.is_finite() || k_bits < 0.0 || access_credit < 0.0
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let next_reserved_k = self.reserved_k_bits + k_bits;
        let next_reserved_access = self.reserved_access_credit + access_credit;
        if !next_reserved_k.is_finite() || !next_reserved_access.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let total_k = self.k_bits_spent + next_reserved_k;
        let total_access = self.access_credit_spent + next_reserved_access;
        if !total_k.is_finite() || !total_access.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if total_k > self.k_bits_budget + f64::EPSILON
            || total_access > self.access_credit_budget + f64::EPSILON
        {
            self.frozen = true;
            return Err(EvidenceOSError::Frozen);
        }
        self.reserved_k_bits = next_reserved_k;
        self.reserved_access_credit = next_reserved_access;
        Ok(())
    }

    pub fn settle_reserved(
        &mut self,
        reserved_k_bits: f64,
        reserved_access_credit: f64,
        actual_k_bits: f64,
        actual_access_credit: f64,
        covariance_charge: f64,
    ) -> EvidenceOSResult<()> {
        if !reserved_k_bits.is_finite()
            || !reserved_access_credit.is_finite()
            || !actual_k_bits.is_finite()
            || !actual_access_credit.is_finite()
            || !covariance_charge.is_finite()
            || reserved_k_bits < 0.0
            || reserved_access_credit < 0.0
            || actual_k_bits < 0.0
            || actual_access_credit < 0.0
            || covariance_charge < 0.0
            || actual_k_bits > reserved_k_bits + f64::EPSILON
            || actual_access_credit > reserved_access_credit + f64::EPSILON
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if reserved_k_bits > self.reserved_k_bits + f64::EPSILON
            || reserved_access_credit > self.reserved_access_credit + f64::EPSILON
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.reserved_k_bits -= reserved_k_bits;
        self.reserved_access_credit -= reserved_access_credit;
        self.charge(actual_k_bits, actual_access_credit, covariance_charge)
    }

    pub fn release_reserved(&mut self, k_bits: f64, access_credit: f64) -> EvidenceOSResult<()> {
        if !k_bits.is_finite() || !access_credit.is_finite() || k_bits < 0.0 || access_credit < 0.0
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if k_bits > self.reserved_k_bits + f64::EPSILON
            || access_credit > self.reserved_access_credit + f64::EPSILON
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.reserved_k_bits -= k_bits;
        self.reserved_access_credit -= access_credit;
        Ok(())
    }

    pub fn k_bits_remaining(&self) -> f64 {
        (self.k_bits_budget - self.k_bits_spent - self.reserved_k_bits).max(0.0)
    }

    pub fn charge(
        &mut self,
        k_bits: f64,
        access_credit: f64,
        covariance_charge: f64,
    ) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if !k_bits.is_finite()
            || !access_credit.is_finite()
            || !covariance_charge.is_finite()
            || k_bits < 0.0
            || access_credit < 0.0
            || covariance_charge < 0.0
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let next_k = self.k_bits_spent + k_bits;
        let next_access = self.access_credit_spent + access_credit;
        let next_cov = self.covariance_charge_total + covariance_charge;
        if !next_k.is_finite() || !next_access.is_finite() || !next_cov.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if next_k > self.k_bits_budget + f64::EPSILON
            || next_access > self.access_credit_budget + f64::EPSILON
        {
            self.frozen = true;
            return Err(EvidenceOSError::Frozen);
        }
        self.k_bits_spent = next_k;
        self.access_credit_spent = next_access;
        self.covariance_charge_total = next_cov;
        Ok(())
    }

    pub fn k_bits_spent(&self) -> f64 {
        self.k_bits_spent
    }

    pub fn access_credit_spent(&self) -> f64 {
        self.access_credit_spent
    }

    pub fn reserved_k_bits(&self) -> f64 {
        self.reserved_k_bits
    }
}

/// The Conservation Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConservationLedger {
    alpha: f64,
    k_bits_total: f64,
    epsilon_total: f64,
    delta_total: f64,
    access_credit_spent: f64,
    wealth: f64,
    w_max: f64,
    events: Vec<LedgerEvent>,
    k_bits_budget: Option<f64>,
    access_credit_budget: Option<f64>,
    epsilon_budget: Option<f64>,
    delta_budget: Option<f64>,
    #[cfg(feature = "dp_lane")]
    pub epsilon_spent: f64,
    #[cfg(feature = "dp_lane")]
    pub delta_spent: f64,
    #[cfg(feature = "dp_lane")]
    pub epsilon_budget_dp_lane: f64,
    #[cfg(feature = "dp_lane")]
    pub delta_budget_dp_lane: f64,
    frozen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerSnapshot {
    pub alpha: f64,
    pub log_alpha_target: f64,
    pub alpha_prime: f64,
    pub log_alpha_prime: f64,
    pub k_bits_total: f64,
    pub barrier_threshold: f64,
    pub barrier: f64,
    pub wealth: f64,
    pub w_max: f64,
    pub epsilon_total: f64,
    pub delta_total: f64,
    pub access_credit_spent: f64,
    pub k_bits_budget: Option<f64>,
    pub access_credit_budget: Option<f64>,
    pub epsilon_budget: Option<f64>,
    pub delta_budget: Option<f64>,
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
            epsilon_total: 0.0,
            delta_total: 0.0,
            access_credit_spent: 0.0,
            wealth: 1.0,
            w_max: 1.0,
            events: Vec::new(),
            k_bits_budget: None,
            access_credit_budget: None,
            epsilon_budget: None,
            delta_budget: None,
            #[cfg(feature = "dp_lane")]
            epsilon_spent: 0.0,
            #[cfg(feature = "dp_lane")]
            delta_spent: 0.0,
            #[cfg(feature = "dp_lane")]
            epsilon_budget_dp_lane: f64::INFINITY,
            #[cfg(feature = "dp_lane")]
            delta_budget_dp_lane: f64::INFINITY,
            frozen: false,
        })
    }

    pub fn with_budget(mut self, k_bits_budget: Option<f64>) -> Self {
        let valid = k_bits_budget.filter(|b| b.is_finite() && *b >= 0.0);
        self.k_bits_budget = valid;
        self.access_credit_budget = valid;
        self
    }

    pub fn with_budgets(
        mut self,
        k_bits_budget: Option<f64>,
        access_credit_budget: Option<f64>,
    ) -> Self {
        self.k_bits_budget = k_bits_budget.filter(|b| b.is_finite() && *b >= 0.0);
        self.access_credit_budget = access_credit_budget.filter(|b| b.is_finite() && *b >= 0.0);
        self
    }

    pub fn with_dp_budgets(
        mut self,
        epsilon_budget: Option<f64>,
        delta_budget: Option<f64>,
    ) -> Self {
        self.epsilon_budget = epsilon_budget.filter(|b| b.is_finite() && *b >= 0.0);
        self.delta_budget = delta_budget.filter(|b| b.is_finite() && *b >= 0.0);
        #[cfg(feature = "dp_lane")]
        {
            self.epsilon_budget_dp_lane = self.epsilon_budget.unwrap_or(f64::INFINITY);
            self.delta_budget_dp_lane = self.delta_budget.unwrap_or(f64::INFINITY);
        }
        self
    }
    pub fn alpha_prime(&self) -> f64 {
        alpha_prime(self.alpha, self.k_bits_total)
    }
    pub fn log_alpha_target(&self) -> f64 {
        log_alpha_target(self.alpha)
    }
    pub fn log_alpha_prime(&self) -> f64 {
        log_alpha_prime(self.alpha, self.k_bits_total)
    }
    pub fn barrier_threshold(&self) -> f64 {
        barrier_threshold(self.alpha, self.k_bits_total)
    }
    pub fn barrier(&self) -> f64 {
        certification_barrier(self.alpha, self.k_bits_total)
    }
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
    pub fn k_bits_total(&self) -> f64 {
        self.k_bits_total
    }
    pub fn epsilon_total(&self) -> f64 {
        self.epsilon_total
    }
    pub fn delta_total(&self) -> f64 {
        self.delta_total
    }
    pub fn access_credit_spent(&self) -> f64 {
        self.access_credit_spent
    }
    pub fn wealth(&self) -> f64 {
        self.wealth
    }
    pub fn k_bits_budget(&self) -> Option<f64> {
        self.k_bits_budget
    }
    pub fn access_credit_budget(&self) -> Option<f64> {
        self.access_credit_budget
    }
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
    pub fn epsilon_budget(&self) -> Option<f64> {
        self.epsilon_budget
    }
    pub fn delta_budget(&self) -> Option<f64> {
        self.delta_budget
    }
    pub fn events(&self) -> &[LedgerEvent] {
        &self.events
    }
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            alpha: self.alpha,
            log_alpha_target: self.log_alpha_target(),
            alpha_prime: self.alpha_prime(),
            log_alpha_prime: self.log_alpha_prime(),
            k_bits_total: self.k_bits_total,
            barrier_threshold: self.barrier_threshold(),
            barrier: self.barrier(),
            wealth: self.wealth,
            w_max: self.w_max,
            epsilon_total: self.epsilon_total,
            delta_total: self.delta_total,
            access_credit_spent: self.access_credit_spent,
            k_bits_budget: self.k_bits_budget,
            access_credit_budget: self.access_credit_budget,
            epsilon_budget: self.epsilon_budget,
            delta_budget: self.delta_budget,
            frozen: self.frozen,
        }
    }
    pub fn certification_guard_failure(&self) -> Option<&'static str> {
        if !(self.alpha.is_finite() && self.alpha > 0.0 && self.alpha < 1.0) {
            return Some("invalid_alpha");
        }
        if !self.k_bits_total.is_finite() || self.k_bits_total < 0.0 {
            return Some("invalid_k_bits_total");
        }
        if !(self.w_max.is_finite() && self.w_max > 0.0) {
            return Some("invalid_w_max");
        }
        let threshold = self.barrier_threshold();
        if !threshold.is_finite() {
            return Some("invalid_barrier_threshold");
        }
        None
    }
    pub fn can_certify(&self) -> bool {
        if self.certification_guard_failure().is_some() {
            return false;
        }
        let log_w_max = self.w_max.ln();
        let threshold = self.barrier_threshold();
        if !log_w_max.is_finite() || threshold.is_nan() {
            return false;
        }
        log_w_max >= threshold
    }
    pub fn w_max(&self) -> f64 {
        self.w_max
    }

    pub fn charge(&mut self, k_bits: f64, kind: &str, meta: Value) -> EvidenceOSResult<()> {
        self.charge_all(k_bits, 0.0, 0.0, k_bits, kind, meta)
    }

    pub fn charge_all(
        &mut self,
        k_bits: f64,
        epsilon: f64,
        delta: f64,
        access_credit: f64,
        kind: &str,
        meta: Value,
    ) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if !k_bits.is_finite()
            || !epsilon.is_finite()
            || !delta.is_finite()
            || !access_credit.is_finite()
            || k_bits < 0.0
            || epsilon < 0.0
            || delta < 0.0
            || access_credit < 0.0
        {
            return Err(EvidenceOSError::InvalidArgument);
        }

        let new_total = self.k_bits_total + k_bits;
        let epsilon_next = self.epsilon_total + epsilon;
        let delta_next = self.delta_total + delta;
        let access_next = self.access_credit_spent + access_credit;

        if !new_total.is_finite()
            || !epsilon_next.is_finite()
            || !delta_next.is_finite()
            || !access_next.is_finite()
        {
            return Err(EvidenceOSError::InvalidArgument);
        }

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

        if let Some(b) = self.access_credit_budget {
            if access_next > b + f64::EPSILON {
                self.frozen = true;
                self.events.push(LedgerEvent::leak(
                    "freeze_access_credit_exhausted",
                    0.0,
                    json!({"overrun_credit": access_next - b}),
                ));
                return Err(EvidenceOSError::Frozen);
            }
        }

        if let Some(b) = self.epsilon_budget {
            if epsilon_next > b + f64::EPSILON {
                self.frozen = true;
                self.events.push(LedgerEvent::leak(
                    "freeze_epsilon_budget_exhausted",
                    0.0,
                    json!({"overrun_epsilon": epsilon_next - b}),
                ));
                return Err(EvidenceOSError::Frozen);
            }
        }

        if let Some(b) = self.delta_budget {
            if delta_next > b + f64::EPSILON {
                self.frozen = true;
                self.events.push(LedgerEvent::leak(
                    "freeze_delta_budget_exhausted",
                    0.0,
                    json!({"overrun_delta": delta_next - b}),
                ));
                return Err(EvidenceOSError::Frozen);
            }
        }

        self.k_bits_total = new_total;
        self.epsilon_total = epsilon_next;
        self.delta_total = delta_next;
        #[cfg(feature = "dp_lane")]
        {
            self.epsilon_spent = self.epsilon_total;
            self.delta_spent = self.delta_total;
        }
        self.access_credit_spent = access_next;
        self.events
            .push(LedgerEvent::leak(kind.to_string(), k_bits, meta));
        Ok(())
    }

    #[cfg(feature = "dp_lane")]
    pub fn charge_dp_basic(&mut self, epsilon: f64, delta: f64) -> EvidenceOSResult<()> {
        if !(epsilon.is_finite() && delta.is_finite()) || epsilon < 0.0 || delta < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.epsilon_spent += epsilon;
        self.delta_spent += delta;
        if self.epsilon_spent > self.epsilon_budget_dp_lane
            || self.delta_spent > self.delta_budget_dp_lane
        {
            self.frozen = true;
            return Err(EvidenceOSError::Frozen);
        }
        self.epsilon_total = self.epsilon_spent;
        self.delta_total = self.delta_spent;
        Ok(())
    }

    pub fn charge_dp(
        &mut self,
        epsilon: f64,
        delta: f64,
        kind: &str,
        meta: Value,
    ) -> EvidenceOSResult<()> {
        self.charge_all(0.0, epsilon, delta, 0.0, kind, meta)
    }

    pub fn charge_kout_bits(&mut self, kout_bits: f64) -> EvidenceOSResult<()> {
        self.charge_all(
            kout_bits,
            0.0,
            0.0,
            kout_bits,
            "structured_output_kout",
            json!({"kout_bits": kout_bits}),
        )
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
        if e_value < 0.0 || !e_value.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if e_value > 0.0 && self.wealth > f64::MAX / e_value {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.wealth *= e_value;
        if self.wealth.is_nan() || self.wealth.is_infinite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.w_max = self.w_max.max(self.wealth);
        self.events
            .push(LedgerEvent::wealth(kind.to_string(), e_value, meta));
        Ok(())
    }

    pub fn scale_wealth(&mut self, scale: f64) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if !scale.is_finite() || scale < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.wealth *= scale;
        if !self.wealth.is_finite() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(())
    }

    pub fn freeze(&mut self, kind: &str, meta: Value) {
        self.frozen = true;
        self.events
            .push(LedgerEvent::leak(kind.to_string(), 0.0, meta));
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
    fn barrier_log_space_extremes_stay_non_nan() {
        let alpha = 1e-30;
        for k in [0.0, 1.0, 1_000.0, 1_000_000.0] {
            let log_ap = log_alpha_prime(alpha, k);
            let threshold = barrier_threshold(alpha, k);
            let barrier = certification_barrier(alpha, k);
            let ap = alpha_prime(alpha, k);
            assert!(!log_ap.is_nan());
            assert!(!threshold.is_nan());
            assert!(!barrier.is_nan());
            assert!(!ap.is_nan());
        }
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

    #[test]
    fn barrier_increases_with_k() {
        let low = certification_barrier(0.05, 2.0);
        let high = certification_barrier(0.05, 6.0);
        assert!(high > low);
    }

    #[test]
    fn barrier_threshold_is_monotonic_in_k() {
        let alpha = 1e-30;
        let mut prev = barrier_threshold(alpha, 0.0);
        for k in [1.0, 10.0, 100.0, 10_000.0, 1_000_000.0] {
            let next = barrier_threshold(alpha, k);
            assert!(next.is_finite());
            assert!(next > prev);
            prev = next;
        }
    }

    #[test]
    fn can_certify_uses_log_space_for_extreme_thresholds() {
        let mut l = ConservationLedger::new(1e-30).expect("ledger");
        l.k_bits_total = 1_000_000.0;
        l.w_max = f64::MAX;
        assert!(!l.can_certify());
    }

    #[test]
    fn certification_guard_fails_closed_on_invalid_numeric_state() {
        let mut l = ConservationLedger::new(0.5).expect("ledger");
        l.w_max = f64::NAN;
        assert_eq!(l.certification_guard_failure(), Some("invalid_w_max"));
        assert!(!l.can_certify());
    }

    #[test]
    fn certify_uses_w_max_not_current() {
        let mut l = ConservationLedger::new(0.5).expect("ledger");
        l.settle_e_value(8.0, "rise", Value::Null).expect("settle");
        l.charge_all(2.0, 0.0, 0.0, 2.0, "leak", Value::Null)
            .expect("charge");
        l.settle_e_value(0.1, "drop", Value::Null).expect("settle");
        assert!(l.wealth < l.barrier());
        assert!(l.can_certify());
    }

    #[test]
    fn topic_budget_is_shared() {
        let mut pool = TopicBudgetPool::new("topic".into(), 10.0, 10.0).expect("pool");
        pool.charge(6.0, 6.0, 0.0).expect("first claim");
        assert!(matches!(
            pool.charge(5.0, 5.0, 0.0),
            Err(EvidenceOSError::Frozen)
        ));
    }

    #[test]
    fn dependence_tax_applies_when_shared_holdout() {
        let dependence_tax_multiplier = 2.0;
        let base_k = 4.0;
        let taxed_k = base_k * dependence_tax_multiplier;
        let mut pool = TopicBudgetPool::new("topic".into(), 10.0, 10.0).expect("pool");
        assert!(pool.charge(taxed_k, taxed_k, taxed_k - base_k).is_ok());
        assert!(matches!(
            pool.charge(taxed_k, taxed_k, taxed_k - base_k),
            Err(EvidenceOSError::Frozen)
        ));
    }

    proptest! {
        #[test]
        fn monotone_high_water_mark_never_decreases(e_values in prop::collection::vec(0.0001f64..10.0f64, 1..64)) {
            let mut ledger = ConservationLedger::new(0.05).expect("ledger");
            let mut prev = ledger.w_max();
            for e in e_values {
                ledger.settle_e_value(e, "prop", Value::Null).expect("settle");
                prop_assert!(ledger.w_max() + 1e-12 >= prev);
                prev = ledger.w_max();
            }
        }

        #[test]
        fn k_bits_total_never_decreases(charges in prop::collection::vec(0.0f64..10.0f64, 1..64)) {
            let mut ledger = ConservationLedger::new(0.05).expect("ledger");
            let mut prev = ledger.k_bits_total;
            for k in charges {
                ledger.charge_all(k, 0.0, 0.0, k, "prop", Value::Null).expect("charge");
                prop_assert!(ledger.k_bits_total + 1e-12 >= prev);
                prev = ledger.k_bits_total;
            }
        }
    }
}

#[cfg(test)]
mod matrix_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_invalid_alpha() {
        assert!(ConservationLedger::new(0.0).is_err());
        assert!(ConservationLedger::new(1.0).is_err());
    }
    #[test]
    fn rejects_invalid_budgets() {
        let mut l = ConservationLedger::new(0.5)
            .expect("l")
            .with_budget(Some(-1.0));
        assert!(l.charge(1.0, "x", Value::Null).is_ok());

        let mut l2 = ConservationLedger::new(0.5)
            .expect("l")
            .with_budgets(Some(f64::NAN), Some(f64::INFINITY));
        assert!(l2.charge_all(1.0, 0.0, 0.0, 1.0, "x", Value::Null).is_ok());
    }
    #[test]
    fn charge_all_rejects_negative_or_nonfinite() {
        let mut l = ConservationLedger::new(0.1).expect("l");
        assert!(l.charge_all(-1.0, 0.0, 0.0, 0.0, "x", Value::Null).is_err());
        assert!(l
            .charge_all(f64::INFINITY, 0.0, 0.0, 0.0, "x", Value::Null)
            .is_err());
    }
    #[test]
    fn settle_rejects_nonpositive_or_nonfinite() {
        let mut l = ConservationLedger::new(0.1).expect("l");
        assert!(l.settle_e_value(-1.0, "x", Value::Null).is_err());
        assert!(l.settle_e_value(f64::NAN, "x", Value::Null).is_err());
    }
    #[test]
    fn events_record_kind_and_meta() {
        let mut l = ConservationLedger::new(0.1).expect("l");
        l.charge(1.0, "kind", json!({"k":1})).expect("charge");
        assert!(l.events.last().expect("event").kind.contains("kind"));
    }
    #[test]
    fn epsilon_delta_accounting() {
        let mut l = ConservationLedger::new(0.1).expect("l");
        l.charge_all(1.0, 0.5, 0.25, 1.0, "x", Value::Null)
            .expect("charge");
        assert!((l.epsilon_total - 0.5).abs() < 1e-12);
        assert!((l.delta_total - 0.25).abs() < 1e-12);
    }
    #[test]
    fn access_credit_is_monotone() {
        let mut l = ConservationLedger::new(0.1).expect("l");
        l.charge_all(0.1, 0.0, 0.0, 0.1, "x", Value::Null)
            .expect("c");
        let a = l.access_credit_spent;
        l.charge_all(0.1, 0.0, 0.0, 0.2, "x", Value::Null)
            .expect("c");
        assert!(l.access_credit_spent >= a);
    }

    #[test]
    fn charge_all_tracks_epsilon_delta_without_dp_budget_lane() {
        let mut l = ConservationLedger::new(0.1)
            .expect("l")
            .with_budgets(Some(5.0), Some(5.0));
        l.charge_all(
            0.0,
            0.1,
            2e-7,
            0.0,
            "structured_output",
            json!({"kind":"laplace"}),
        )
        .expect("first epsilon/delta charge");
        l.charge_all(
            0.0,
            0.2,
            8e-7,
            0.0,
            "structured_output",
            json!({"kind":"gaussian"}),
        )
        .expect("second epsilon/delta charge");
        assert!((l.epsilon_total - 0.3).abs() < 1e-12);
        assert!((l.delta_total - 1e-6).abs() < 1e-12);
    }

    #[test]
    fn dp_charge_freezes_when_budget_exceeded() {
        let mut l = ConservationLedger::new(0.1)
            .expect("l")
            .with_dp_budgets(Some(0.5), Some(1e-6));
        l.charge_dp(0.2, 4e-7, "dp", Value::Null)
            .expect("within budget");
        assert!(matches!(
            l.charge_dp(0.31, 0.0, "dp", Value::Null),
            Err(EvidenceOSError::Frozen)
        ));
        assert!(l.is_frozen());
    }

    #[test]
    fn alpha_soundness_depends_on_k_bits_not_dp_totals() {
        let mut l = ConservationLedger::new(0.05).expect("l");
        l.charge(3.0, "k", Value::Null).expect("k charge");
        let before = l.alpha_prime();
        l.charge_dp(0.4, 1e-6, "dp", Value::Null)
            .expect("dp charge");
        assert!((l.alpha_prime() - before).abs() < 1e-12);
    }
    #[test]
    fn freeze_after_budget_exhaustion() {
        let mut l = ConservationLedger::new(0.1)
            .expect("l")
            .with_budget(Some(1.0));
        l.charge(1.0, "x", Value::Null).expect("c");
        assert!(matches!(
            l.charge(0.1, "x", Value::Null),
            Err(EvidenceOSError::Frozen)
        ));
    }
    #[test]
    fn joint_pool_rejects_invalid_budget() {
        assert!(JointLeakagePool::new("a".into(), -1.0).is_err());
        assert!(JointLeakagePool::new("a".into(), f64::NAN).is_err());
        assert!(JointLeakagePool::new("a".into(), f64::INFINITY).is_err());
    }
    #[test]
    fn topic_pool_rejects_invalid_budget() {
        assert!(TopicBudgetPool::new("a".into(), -1.0, 1.0).is_err());
    }
    #[test]
    fn e_merge_rejects_invalid_inputs() {
        assert!(e_merge(&[1.0], &[0.0]).is_err());
    }
    #[test]
    fn e_merge_equal_rejects_empty() {
        assert!(e_merge_equal(&[]).is_err());
    }
    #[test]
    fn e_product_rejects_invalid_or_empty() {
        assert!(e_product(&[]).is_err());
        assert!(e_product(&[-1.0]).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn e_merge_weights_invariants_proptest(
            e_values in prop::collection::vec(0.0f64..8.0f64, 2..16),
            raw_weights in prop::collection::vec(0.0001f64..8.0f64, 2..16),
            bump in 0.0f64..2.0f64,
        ) {
            prop_assume!(e_values.len() == raw_weights.len());
            let total_w: f64 = raw_weights.iter().sum();
            prop_assume!(total_w.is_finite() && total_w > 0.0);
            let weights: Vec<f64> = raw_weights.iter().map(|w| *w / total_w).collect();
            let merged = e_merge(&e_values, &weights).expect("merge");
            let min = e_values.iter().copied().fold(f64::INFINITY, f64::min);
            let max = e_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            prop_assert!(merged.is_finite());
            prop_assert!(merged + 1e-12 >= min);
            prop_assert!(merged <= max + 1e-12);

            let mut raised = e_values.clone();
            raised[0] += bump;
            let merged_raised = e_merge(&raised, &weights).expect("merge raised");
            prop_assert!(merged_raised + 1e-12 >= merged);
        }
        #[test] fn events_never_decrease_under_random_ops(ops in prop::collection::vec(0.0f64..3.0f64,1..64)) { let mut l=ConservationLedger::new(0.1).expect("l"); let mut prev=0usize; for v in ops { let _=l.charge(v,"x",Value::Null); prop_assert!(l.events.len()>=prev); prev=l.events.len(); } }
        #[test] fn random_meta_does_not_panic(v in any::<u64>()) { let mut l=ConservationLedger::new(0.1).expect("l"); let _=l.charge(0.1,"x",json!({"v":v})); prop_assert!(true); }
        #[test] fn joint_pool_invariants_proptest(a in 0.1f64..10.0f64, x in 0.0f64..5.0f64) { let mut p=JointLeakagePool::new("h".into(), a).expect("p"); let _=p.charge(x); prop_assert!(p.k_bits_remaining() <= a + 1e-12); }
        #[test] fn topic_pool_invariants_proptest(a in 0.1f64..10.0f64, b in 0.1f64..10.0f64, x in 0.0f64..5.0f64, covariance_charge in 0.0f64..8.0f64) {
            let mut p=TopicBudgetPool::new("t".into(), a,b).expect("p");
            let before_cov = p.covariance_charge_total;
            let expected_freeze = x > a + f64::EPSILON || x > b + f64::EPSILON;
            let result = p.charge(x,x,covariance_charge);
            if expected_freeze {
                prop_assert!(matches!(result, Err(EvidenceOSError::Frozen)));
                prop_assert!(p.frozen);
            } else {
                prop_assert!(result.is_ok());
                prop_assert!(p.covariance_charge_total + 1e-12 >= before_cov);
                prop_assert!((p.covariance_charge_total - (before_cov + covariance_charge)).abs() < 1e-9);
            }
            prop_assert_eq!(p.frozen, expected_freeze);
        }
        #[test] fn e_merge_proptest_invariants(xs in prop::collection::vec(0.1f64..10.0f64,1..8)) { let w=vec![1.0/xs.len() as f64; xs.len()]; let v=e_merge(&xs,&w).expect("m"); prop_assert!(v.is_finite() && v>=0.0); }
        #[test] fn e_product_proptest_invariants(xs in prop::collection::vec(0.1f64..10.0f64,1..8)) { let v=e_product(&xs).expect("m"); prop_assert!(v.is_finite() && v>=0.0); }
    }
}
