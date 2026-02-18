// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEvent {
    pub kind: String,
    /// Bits charged by this event (0 for wealth events).
    pub bits: f64,
    /// JSON metadata.
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

/// The Conservation Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConservationLedger {
    pub alpha: f64,
    pub k_bits_total: f64,
    pub wealth: f64,
    pub events: Vec<LedgerEvent>,

    /// If Some, the maximum allowed leakage budget in bits.
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
        self.wealth >= self.barrier()
    }

    /// Charge `k_bits` leakage.
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
                    Value::Null,
                ));
                return Err(EvidenceOSError::Frozen);
            }
        }
        self.k_bits_total = new_total;
        self.events
            .push(LedgerEvent::leak(kind.to_string(), k_bits, meta));
        Ok(())
    }

    /// Settle an e-value into wealth.
    pub fn settle_e_value(
        &mut self,
        e_value: f64,
        kind: &str,
        meta: Value,
    ) -> EvidenceOSResult<()> {
        if self.frozen {
            return Err(EvidenceOSError::Frozen);
        }
        if e_value <= 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        self.wealth *= e_value;
        self.events
            .push(LedgerEvent::wealth(kind.to_string(), e_value, meta));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_prime_matches_reference() {
        let alpha = 0.05;
        let k = 8.0;
        let ap = alpha_prime(alpha, k);
        // 0.05 / 256 = 0.0001953125
        let expected = 0.0001953125;
        assert!((ap - expected).abs() < 1e-12);

        let barrier = certification_barrier(alpha, k);
        assert!((barrier - (1.0 / expected)).abs() < 1e-9);
    }

    #[test]
    fn budget_freezes_fail_closed() {
        let mut l = ConservationLedger::new(0.05)
            .unwrap()
            .with_budget(Some(3.0));
        l.charge(2.0, "leak", Value::Null).unwrap();
        assert!(!l.frozen);
        let err = l.charge(2.0, "leak", Value::Null).unwrap_err();
        assert!(matches!(err, EvidenceOSError::Frozen));
        assert!(l.frozen);
        // Subsequent calls should also fail.
        assert!(matches!(
            l.charge(0.0, "leak", Value::Null).unwrap_err(),
            EvidenceOSError::Frozen
        ));
    }
}
