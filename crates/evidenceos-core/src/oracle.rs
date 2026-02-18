// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ORACLE_CODEC_SPEC_V1: &str =
    "oracle-resolution/v1;codec=unsigned-big-endian;canonical=zero-high-bits;bucket-range=[0,num_symbols)";

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
pub enum TieBreaker {
    Lower,
    Upper,
    NearestEven,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OracleResolution {
    pub num_symbols: u32,
    pub bit_width: u8,
    pub codec_hash: [u8; 32],
    pub calibration_manifest_hash: [u8; 32],
    pub calibrated_at_epoch: u64,
    pub ttl_epochs: Option<u64>,
    pub delta_sigma: f64,
    pub tie_breaker: TieBreaker,
}

impl OracleResolution {
    pub fn new(num_symbols: u32, delta_sigma: f64) -> EvidenceOSResult<Self> {
        if num_symbols < 2 || delta_sigma < 0.0 || delta_sigma.is_nan() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let bit_width = Self::compute_bit_width(num_symbols)?;
        let codec_hash = Self::codec_hash_for_spec();
        Ok(Self {
            num_symbols,
            bit_width,
            codec_hash,
            calibration_manifest_hash: [0u8; 32],
            calibrated_at_epoch: 0,
            ttl_epochs: None,
            delta_sigma,
            tie_breaker: TieBreaker::NearestEven,
        })
    }

    pub fn with_calibration(mut self, manifest_hash: [u8; 32], calibrated_at_epoch: u64) -> Self {
        self.calibration_manifest_hash = manifest_hash;
        self.calibrated_at_epoch = calibrated_at_epoch;
        self
    }

    fn compute_bit_width(num_symbols: u32) -> EvidenceOSResult<u8> {
        if num_symbols < 2 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let bits = 32 - (num_symbols - 1).leading_zeros();
        u8::try_from(bits).map_err(|_| EvidenceOSError::InvalidArgument)
    }

    fn codec_hash_for_spec() -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ORACLE_CODEC_SPEC_V1.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn bits_per_call(&self) -> f64 {
        (self.num_symbols as f64).log2()
    }

    pub fn encoded_len_bytes(&self) -> usize {
        (self.bit_width as usize).div_ceil(8)
    }

    pub fn encode_bucket(&self, bucket: u32) -> EvidenceOSResult<Vec<u8>> {
        if bucket >= self.num_symbols {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let expected_len = self.encoded_len_bytes();
        let mut out = vec![0u8; expected_len];
        let be = bucket.to_be_bytes();
        let start = be.len().saturating_sub(expected_len);
        out.copy_from_slice(&be[start..]);
        Ok(out)
    }

    pub fn decode_bucket(&self, bytes: &[u8]) -> EvidenceOSResult<u32> {
        if bytes.len() != self.encoded_len_bytes() {
            return Err(EvidenceOSError::InvalidCanonicalEncoding);
        }
        if !self.bit_width.is_multiple_of(8) {
            let unused_high_bits = 8 - (self.bit_width % 8);
            let mask = u8::MAX << (8 - unused_high_bits);
            if bytes[0] & mask != 0 {
                return Err(EvidenceOSError::InvalidCanonicalEncoding);
            }
        }
        let mut value = 0u32;
        for &b in bytes {
            value = (value << 8) | u32::from(b);
        }
        if value >= self.num_symbols {
            return Err(EvidenceOSError::InvalidCanonicalEncoding);
        }
        Ok(value)
    }

    pub fn quantize_unit_interval(&self, v: f64) -> EvidenceOSResult<u32> {
        if v.is_nan() {
            return Err(EvidenceOSError::NaNNotAllowed);
        }
        let clamped = v.clamp(0.0, 1.0);
        let max_idx = (self.num_symbols - 1) as f64;
        let scaled = (clamped * max_idx).clamp(0.0, max_idx);
        let bucket = match self.tie_breaker {
            TieBreaker::Lower => scaled.floor(),
            TieBreaker::Upper => scaled.ceil(),
            TieBreaker::NearestEven => {
                let floor = scaled.floor();
                let frac = scaled - floor;
                if (frac - 0.5).abs() < f64::EPSILON {
                    if (floor as u64) % 2 == 0 {
                        floor
                    } else {
                        floor + 1.0
                    }
                } else {
                    scaled.round()
                }
            }
        };
        Ok(bucket.clamp(0.0, max_idx) as u32)
    }

    pub fn ttl_expired(&self, current_epoch: u64) -> bool {
        self.ttl_epochs
            .map(|ttl| current_epoch.saturating_sub(self.calibrated_at_epoch) >= ttl)
            .unwrap_or(false)
    }

    pub fn validate_canonical_bytes(&self, bytes: &[u8]) -> EvidenceOSResult<u32> {
        self.decode_bucket(bytes)
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
        let bucket = self.resolution.quantize_unit_interval(raw)?;
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
    fn encoding_len_known_values() {
        let cases = [
            (2, 1u8, 1usize),
            (3, 2, 1),
            (4, 2, 1),
            (7, 3, 1),
            (8, 3, 1),
            (9, 4, 1),
            (255, 8, 1),
            (256, 8, 1),
            (257, 9, 2),
            (1024, 10, 2),
        ];
        for (num_symbols, bit_width, encoded_len) in cases {
            let r = OracleResolution::new(num_symbols, 0.1).expect("resolution");
            assert_eq!(r.bit_width, bit_width);
            assert_eq!(r.encoded_len_bytes(), encoded_len);
        }
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let r = OracleResolution::new(257, 0.0).expect("resolution");
        assert!(matches!(
            r.decode_bucket(&[]),
            Err(EvidenceOSError::InvalidCanonicalEncoding)
        ));
        assert!(matches!(
            r.decode_bucket(&[0x00]),
            Err(EvidenceOSError::InvalidCanonicalEncoding)
        ));
        assert!(matches!(
            r.decode_bucket(&[0x00, 0x01, 0x02]),
            Err(EvidenceOSError::InvalidCanonicalEncoding)
        ));
    }

    #[test]
    fn decode_rejects_unused_bits_nonzero() {
        let r = OracleResolution::new(3, 0.0).expect("resolution");
        assert!(matches!(
            r.validate_canonical_bytes(&[0b1111_1111]),
            Err(EvidenceOSError::InvalidCanonicalEncoding)
        ));
    }

    #[test]
    fn decode_rejects_bucket_out_of_range() {
        let r = OracleResolution::new(3, 0.0).expect("resolution");
        assert!(matches!(
            r.decode_bucket(&[3]),
            Err(EvidenceOSError::InvalidCanonicalEncoding)
        ));
    }

    #[test]
    fn ttl_expired_boundary() {
        let mut r = OracleResolution::new(8, 0.01).expect("resolution");
        r.calibrated_at_epoch = 10;
        r.ttl_epochs = Some(5);
        assert!(!r.ttl_expired(14));
        assert!(r.ttl_expired(15));
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
    fn delta_sigma_zero_disables_hysteresis() {
        let holdout = HoldoutLabels::new(vec![1, 1, 1, 1]).expect("holdout");
        let mut state = AccuracyOracleState::new(
            holdout,
            OracleResolution::new(8, 0.0).expect("resolution"),
            NullSpec {
                domain: "labels".into(),
                null_accuracy: 0.5,
                e_value_fn: EValueFn::Fixed(1.0),
            },
        )
        .expect("state");
        let _ = state.query(&[1, 1, 1, 1]).expect("query1");
        let r2 = state.query(&[1, 1, 1, 0]).expect("query2");
        assert!(!r2.hysteresis_applied);
    }

    #[test]
    fn quantize_nan_rejected() {
        let r = OracleResolution::new(8, 0.0).expect("resolution");
        assert!(matches!(
            r.quantize_unit_interval(f64::NAN),
            Err(EvidenceOSError::NaNNotAllowed)
        ));
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
