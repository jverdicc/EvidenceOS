// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OracleResolution {
    pub num_buckets: u32,
    pub delta_sigma: f64,
}

impl OracleResolution {
    pub fn new(num_buckets: u32, delta_sigma: f64) -> EvidenceOSResult<Self> {
        if num_buckets < 2 {
            return Err(EvidenceOSError::InvalidArgument(
                "num_buckets must be >= 2".to_string(),
            ));
        }
        if !(delta_sigma >= 0.0) {
            return Err(EvidenceOSError::InvalidArgument(
                "delta_sigma must be >= 0".to_string(),
            ));
        }
        Ok(Self {
            num_buckets,
            delta_sigma,
        })
    }

    pub fn bits_per_call(&self) -> f64 {
        (self.num_buckets as f64).log2()
    }

    pub fn quantize_unit_interval(&self, v: f64) -> u32 {
        let clamped = if v.is_nan() {
            0.0
        } else if v < 0.0 {
            0.0
        } else if v > 1.0 {
            1.0
        } else {
            v
        };
        let max_idx = (self.num_buckets - 1) as f64;
        let idx = (clamped * max_idx).round();
        let idx_i = idx as i64;
        idx_i.clamp(0, self.num_buckets as i64 - 1) as u32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HysteresisState<T> {
    pub last_input: Option<T>,
    pub last_raw: Option<f64>,
    pub last_bucket: Option<u32>,
}

impl<T: Clone> HysteresisState<T> {
    pub fn apply(&mut self, local: bool, delta_sigma: f64, raw: f64, bucket: u32, input: T) -> u32 {
        let out = match (local, self.last_raw, self.last_bucket) {
            (true, Some(prev_raw), Some(prev_bucket)) if (raw - prev_raw).abs() < delta_sigma => prev_bucket,
            _ => bucket,
        };
        self.last_input = Some(input);
        self.last_raw = Some(raw);
        self.last_bucket = Some(out);
        out
    }
}

/// A private holdout of binary labels.
#[derive(Debug, Clone)]
pub struct HoldoutLabels {
    labels: Vec<u8>,
}

impl HoldoutLabels {
    pub fn new(labels: Vec<u8>) -> EvidenceOSResult<Self> {
        if labels.is_empty() {
            return Err(EvidenceOSError::InvalidArgument(
                "labels must be non-empty".to_string(),
            ));
        }
        for &b in &labels {
            if b != 0 && b != 1 {
                return Err(EvidenceOSError::InvalidArgument(
                    "labels must be binary (0/1)".to_string(),
                ));
            }
        }
        Ok(Self { labels })
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Expose raw bytes for kernel-internal commitments.
    ///
    /// WARNING: do not expose this outside the kernel TCB.
    pub fn labels_bytes(&self) -> &[u8] {
        &self.labels
    }

    pub fn accuracy(&self, predictions: &[u8]) -> EvidenceOSResult<f64> {
        if predictions.len() != self.labels.len() {
            return Err(EvidenceOSError::InvalidArgument(format!(
                "predictions length {} != labels length {}",
                predictions.len(),
                self.labels.len()
            )));
        }
        let mut correct = 0u64;
        for (p, y) in predictions.iter().zip(self.labels.iter()) {
            let pb = *p;
            if pb != 0 && pb != 1 {
                return Err(EvidenceOSError::InvalidArgument(
                    "predictions must be bytes of 0/1".to_string(),
                ));
            }
            if pb == *y {
                correct += 1;
            }
        }
        Ok(correct as f64 / self.labels.len() as f64)
    }

    pub fn hamming_distance(a: &[u8], b: &[u8]) -> EvidenceOSResult<u64> {
        if a.len() != b.len() {
            return Err(EvidenceOSError::InvalidArgument(
                "hamming_distance: length mismatch".to_string(),
            ));
        }
        let mut d = 0u64;
        for (x, y) in a.iter().zip(b.iter()) {
            if x != y {
                d += 1;
            }
        }
        Ok(d)
    }
}

/// A private scalar boundary b in [0,1].
#[derive(Debug, Clone, Copy)]
pub struct HoldoutBoundary {
    pub b: f64,
}

impl HoldoutBoundary {
    pub fn new(b: f64) -> EvidenceOSResult<Self> {
        if !(b >= 0.0 && b <= 1.0) {
            return Err(EvidenceOSError::InvalidArgument(
                "boundary b must be in [0,1]".to_string(),
            ));
        }
        Ok(Self { b })
    }

    pub fn accuracy_det(&self, x: f64) -> f64 {
        let v = 1.0 - (x - self.b).abs();
        v.clamp(0.0, 1.0)
    }

    pub fn safety_det(&self, x: f64) -> bool {
        x <= self.b
    }

    /// Commitment preimage (fixed-endian encoding) for ETL capsules.
    pub fn commitment_preimage(&self) -> [u8; 8] {
        self.b.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantization_matches_rounding() {
        let r = OracleResolution::new(256, 0.0).unwrap();
        assert_eq!(r.quantize_unit_interval(0.0), 0);
        assert_eq!(r.quantize_unit_interval(1.0), 255);
        assert_eq!(r.quantize_unit_interval(0.5), 128);
    }

    #[test]
    fn labels_accuracy_and_hamming() {
        let h = HoldoutLabels::new(vec![0, 1, 1, 0]).unwrap();
        let acc = h.accuracy(&[0, 1, 0, 0]).unwrap();
        assert!((acc - 0.75).abs() < 1e-12);
        let d = HoldoutLabels::hamming_distance(&[0, 1, 0, 0], &[0, 1, 1, 0]).unwrap();
        assert_eq!(d, 1);
    }

    #[test]
    fn hysteresis_stalls_small_delta_on_local() {
        let mut h: HysteresisState<Vec<u8>> = HysteresisState::default();
        let out1 = h.apply(true, 0.01, 0.5, 10, vec![0]);
        assert_eq!(out1, 10);
        let out2 = h.apply(true, 0.01, 0.505, 11, vec![1]);
        assert_eq!(out2, 10);
    }

    #[test]
    fn boundary_oracles() {
        let b = HoldoutBoundary::new(0.7).unwrap();
        assert!(b.safety_det(0.699));
        assert!(!b.safety_det(0.701));
        assert!((b.accuracy_det(0.7) - 1.0).abs() < 1e-12);
        assert!((b.accuracy_det(0.0) - 0.3).abs() < 1e-12);
    }
}
