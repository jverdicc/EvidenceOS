// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EValueFn {
    /// Simple likelihood ratio: e = (acc / null_acc)^n for n observations.
    LikelihoodRatio { n_observations: usize },
    /// Fixed e-value regardless of data.
    Fixed(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullSpec {
    pub domain: String,
    pub null_accuracy: f64,
    pub e_value_fn: EValueFn,
}

impl NullSpec {
    pub fn compute_e_value(&self, observed_acc: f64) -> f64 {
        match self.e_value_fn {
            EValueFn::LikelihoodRatio { n_observations } => {
                if self.null_accuracy == 0.0 {
                    return 0.0;
                }
                let ratio = (observed_acc / self.null_accuracy).max(0.0);
                ratio.powf(n_observations as f64).clamp(0.0, f64::MAX)
            }
            EValueFn::Fixed(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OracleResolution {
    pub num_buckets: u32,
    pub delta_sigma: f64,
    pub codec_version: u32,
    pub ttl_epochs: Option<u64>,
}

impl OracleResolution {
    pub fn new(num_buckets: u32, delta_sigma: f64) -> EvidenceOSResult<Self> {
        if num_buckets < 2 || delta_sigma < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(Self {
            num_buckets,
            delta_sigma,
            codec_version: 1,
            ttl_epochs: None,
        })
    }

    pub fn bits_per_call(&self) -> f64 {
        (self.num_buckets as f64).log2()
    }

    pub fn quantize_unit_interval(&self, v: f64) -> u32 {
        let clamped = if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) };
        let max_idx = (self.num_buckets - 1) as f64;
        (clamped * max_idx).round().clamp(0.0, max_idx) as u32
    }

    pub fn is_expired(&self, current_epoch: u64, calibrated_at_epoch: u64) -> bool {
        self.ttl_epochs
            .map(|ttl| current_epoch.saturating_sub(calibrated_at_epoch) > ttl)
            .unwrap_or(false)
    }

    pub fn validate_canonical_bytes(&self, bytes: &[u8]) -> EvidenceOSResult<u32> {
        if bytes.len() != 1 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let bucket = u32::from(bytes[0]);
        if bucket >= self.num_buckets {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(bucket)
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HysteresisState<T> {
    pub last_input: Option<T>,
    pub last_raw: Option<f64>,
    pub last_bucket: Option<u32>,
}

impl<T: Clone> HysteresisState<T> {
    pub fn apply(&mut self, local: bool, delta_sigma: f64, raw: f64, bucket: u32, input: T) -> u32 {
        let out = match (local, self.last_raw, self.last_bucket) {
            (true, Some(prev_raw), Some(prev_bucket)) if (raw - prev_raw).abs() < delta_sigma => {
                prev_bucket
            }
            _ => bucket,
        };
        self.last_input = Some(input);
        self.last_raw = Some(raw);
        self.last_bucket = Some(out);
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResult {
    pub bucket: u32,
    pub raw_accuracy: f64,
    pub e_value: f64,
    pub k_bits: f64,
    pub hysteresis_applied: bool,
}

/// A private holdout of binary labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldoutLabels {
    labels: Vec<u8>,
}

impl HoldoutLabels {
    pub fn new(labels: Vec<u8>) -> EvidenceOSResult<Self> {
        if labels.is_empty() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        for &b in &labels {
            if b != 0 && b != 1 {
                return Err(EvidenceOSError::InvalidArgument);
            }
        }
        Ok(Self { labels })
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
    pub fn labels_bytes(&self) -> &[u8] {
        &self.labels
    }

    pub fn accuracy(&self, predictions: &[u8]) -> EvidenceOSResult<f64> {
        if predictions.len() != self.labels.len() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let mut correct = 0u64;
        for (p, y) in predictions.iter().zip(self.labels.iter()) {
            if *p != 0 && *p != 1 {
                return Err(EvidenceOSError::InvalidArgument);
            }
            if p == y {
                correct += 1;
            }
        }
        Ok(correct as f64 / self.labels.len() as f64)
    }

    pub fn hamming_distance(a: &[u8], b: &[u8]) -> EvidenceOSResult<u64> {
        if a.len() != b.len() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(a.iter().zip(b.iter()).filter(|(x, y)| x != y).count() as u64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyOracleState {
    pub resolution: OracleResolution,
    pub null_spec: NullSpec,
    holdout: HoldoutLabels,
    last_preds: Option<Vec<u8>>,
    last_raw: Option<f64>,
    last_bucket: Option<u32>,
}

impl AccuracyOracleState {
    pub fn new(
        holdout: HoldoutLabels,
        resolution: OracleResolution,
        null_spec: NullSpec,
    ) -> EvidenceOSResult<Self> {
        Ok(Self {
            resolution,
            null_spec,
            holdout,
            last_preds: None,
            last_raw: None,
            last_bucket: None,
        })
    }

    pub fn query(&mut self, preds: &[u8]) -> EvidenceOSResult<OracleResult> {
        let raw = self.holdout.accuracy(preds)?;
        let bucket = self.resolution.quantize_unit_interval(raw);
        let local = self
            .last_preds
            .as_ref()
            .map(|last| HoldoutLabels::hamming_distance(last, preds).map(|d| d <= 1))
            .transpose()?
            .unwrap_or(false);
        let hysteresis_applied = matches!((local, self.last_raw, self.last_bucket),
            (true, Some(prev_raw), Some(_)) if (raw - prev_raw).abs() < self.resolution.delta_sigma);
        let output_bucket = if hysteresis_applied {
            self.last_bucket.unwrap_or(bucket)
        } else {
            bucket
        };
        self.last_preds = Some(preds.to_vec());
        self.last_raw = Some(raw);
        self.last_bucket = Some(output_bucket);
        Ok(OracleResult {
            bucket: output_bucket,
            raw_accuracy: raw,
            e_value: self.null_spec.compute_e_value(raw),
            k_bits: self.resolution.bits_per_call(),
            hysteresis_applied,
        })
    }
}

/// A private scalar boundary b in [0,1].
#[derive(Debug, Clone, Copy)]
pub struct HoldoutBoundary {
    pub b: f64,
}

impl HoldoutBoundary {
    pub fn new(b: f64) -> EvidenceOSResult<Self> {
        if !(0.0..=1.0).contains(&b) {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(Self { b })
    }

    pub fn accuracy_det(&self, x: f64) -> f64 {
        (1.0 - (x - self.b).abs()).clamp(0.0, 1.0)
    }
    pub fn safety_det(&self, x: f64) -> bool {
        x <= self.b
    }
    pub fn commitment_preimage(&self) -> [u8; 8] {
        self.b.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn null_spec_likelihood_ratio_at_null() {
        let n = NullSpec {
            domain: "d".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::LikelihoodRatio { n_observations: 8 },
        };
        assert!((n.compute_e_value(0.5) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn oracle_resolution_ttl_expired() {
        let mut r = OracleResolution::new(8, 0.01).expect("resolution");
        r.ttl_epochs = Some(10);
        assert!(r.is_expired(15, 3));
    }

    #[test]
    fn accuracy_oracle_state_hysteresis_local_stalls() {
        let holdout = HoldoutLabels::new(vec![1, 1, 1, 1]).expect("holdout");
        let mut state = AccuracyOracleState::new(
            holdout,
            OracleResolution::new(8, 0.26).expect("resolution"),
            NullSpec {
                domain: "labels".into(),
                null_accuracy: 0.5,
                e_value_fn: EValueFn::Fixed(1.0),
            },
        )
        .expect("state");
        let r1 = state.query(&[1, 1, 1, 1]).expect("query1");
        let r2 = state.query(&[1, 1, 1, 0]).expect("query2");
        assert!(r2.hysteresis_applied);
        assert_eq!(r1.bucket, r2.bucket);
    }

    #[test]
    fn accuracy_oracle_state_rejects_non_binary_preds() {
        let holdout = HoldoutLabels::new(vec![1, 1]).expect("holdout");
        let mut state = AccuracyOracleState::new(
            holdout,
            OracleResolution::new(8, 0.1).expect("resolution"),
            NullSpec {
                domain: "labels".into(),
                null_accuracy: 0.5,
                e_value_fn: EValueFn::Fixed(1.0),
            },
        )
        .expect("state");
        assert!(matches!(
            state.query(&[1, 2]),
            Err(EvidenceOSError::InvalidArgument)
        ));
    }

    #[test]
    fn canonical_bytes_rejects_extra_bytes() {
        let r = OracleResolution::new(8, 0.0).expect("resolution");
        assert!(matches!(
            r.validate_canonical_bytes(&[0, 1]),
            Err(EvidenceOSError::InvalidArgument)
        ));
    }

    proptest! {
        #[test]
        fn oracle_canonical_validation_roundtrip(
            buckets in 2u32..=255,
            bucket in 0u32..=254,
        ) {
            prop_assume!(bucket < buckets);
            let resolution = OracleResolution::new(buckets, 0.0).expect("valid resolution");
            let encoded = [bucket as u8];
            let decoded = resolution.validate_canonical_bytes(&encoded)
                .expect("single-byte bucket in range must decode");
            prop_assert_eq!(decoded, bucket);

            let overflow = [buckets as u8];
            prop_assert!(matches!(
                resolution.validate_canonical_bytes(&overflow),
                Err(EvidenceOSError::InvalidArgument)
            ));

            prop_assert!(matches!(
                resolution.validate_canonical_bytes(&[]),
                Err(EvidenceOSError::InvalidArgument)
            ));
            prop_assert!(matches!(
                resolution.validate_canonical_bytes(&[encoded[0], 0]),
                Err(EvidenceOSError::InvalidArgument)
            ));
        }
    }
}
