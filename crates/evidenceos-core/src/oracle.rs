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
use crate::oracle_registry::OracleBackend;
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
    /// Mixture likelihood ratio for binary accuracy e-processes.
    MixtureBinaryMartingale { grid: Vec<f64> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullSpec {
    pub domain: String,
    pub null_accuracy: f64,
    pub e_value_fn: EValueFn,
}

impl NullSpec {
    pub fn compute_e_value(&self, observed_acc: f64) -> f64 {
        match &self.e_value_fn {
            EValueFn::LikelihoodRatio { n_observations } => {
                if self.null_accuracy == 0.0 {
                    return 0.0;
                }
                let ratio = (observed_acc / self.null_accuracy).max(0.0);
                ratio.powf(*n_observations as f64).clamp(0.0, f64::MAX)
            }
            EValueFn::Fixed(v) => *v,
            EValueFn::MixtureBinaryMartingale { grid } => {
                if grid.is_empty() || self.null_accuracy <= 0.0 || self.null_accuracy >= 1.0 {
                    return 0.0;
                }
                let n_observations = 1usize;
                let k = (observed_acc.clamp(0.0, 1.0) * n_observations as f64)
                    .round()
                    .clamp(0.0, n_observations as f64) as usize;
                let mut sum = 0.0;
                for p_i in grid {
                    if self.null_accuracy >= 1.0 {
                        return 0.0;
                    }
                    let success = (p_i / self.null_accuracy).powf(k as f64);
                    let failure = ((1.0 - p_i) / (1.0 - self.null_accuracy))
                        .powf((n_observations - k) as f64);
                    let term = success * failure;
                    if !term.is_finite() || term < 0.0 {
                        return 0.0;
                    }
                    sum += term;
                }
                (sum / (grid.len() as f64)).clamp(0.0, f64::MAX)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TieBreaker {
    Lower,
    Upper,
    NearestEven,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalityPolicy {
    Hamming { max_bits: u32 },
    BucketRadius { r: u32 },
    ExactMatchOnly,
    CustomHashNeighborhood { prefix_bits: u16, salt: [u8; 32] },
}

impl Default for LocalityPolicy {
    fn default() -> Self {
        Self::Hamming { max_bits: 1 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResolution {
    pub num_symbols: u32,
    pub bit_width: u8,
    pub codec_hash: [u8; 32],
    pub calibration_manifest_hash: [u8; 32],
    pub calibrated_at_epoch: u64,
    pub ttl_epochs: Option<u64>,
    pub delta_sigma: f64,
    pub tie_breaker: TieBreaker,
    #[serde(default)]
    pub locality_policy: LocalityPolicy,
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
            locality_policy: LocalityPolicy::default(),
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
                    if (floor as u64).is_multiple_of(2) {
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
            .map(|ttl| current_epoch.saturating_sub(self.calibrated_at_epoch) > ttl)
            .unwrap_or(false)
    }

    pub fn validate_canonical_bytes(&self, bytes: &[u8]) -> EvidenceOSResult<u32> {
        self.decode_bucket(bytes)
    }

    pub fn is_local(&self, prev: &[u8], next: &[u8]) -> EvidenceOSResult<bool> {
        match &self.locality_policy {
            LocalityPolicy::Hamming { max_bits } => {
                HoldoutLabels::hamming_distance(prev, next).map(|d| d <= u64::from(*max_bits))
            }
            LocalityPolicy::BucketRadius { r } => {
                let prev_bucket = Self::bucket_from_bytes(prev)?;
                let next_bucket = Self::bucket_from_bytes(next)?;
                Ok(prev_bucket.abs_diff(next_bucket) <= u64::from(*r))
            }
            LocalityPolicy::ExactMatchOnly => Ok(prev == next),
            LocalityPolicy::CustomHashNeighborhood { prefix_bits, salt } => {
                if *prefix_bits > 256 {
                    return Err(EvidenceOSError::InvalidArgument);
                }
                let prev_hash = Self::salted_hash(salt, prev);
                let next_hash = Self::salted_hash(salt, next);
                Ok(Self::shared_prefix_bits(&prev_hash, &next_hash) >= u32::from(*prefix_bits))
            }
        }
    }

    fn bucket_from_bytes(bytes: &[u8]) -> EvidenceOSResult<u64> {
        let digest = Sha256::digest(bytes);
        let head = digest
            .get(..8)
            .ok_or(EvidenceOSError::InvalidCanonicalEncoding)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(head);
        Ok(u64::from_be_bytes(arr))
    }

    fn salted_hash(salt: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(data);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn shared_prefix_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
        let mut count = 0u32;
        for (aa, bb) in a.iter().zip(b.iter()) {
            let x = aa ^ bb;
            if x == 0 {
                count += 8;
                continue;
            }
            count += x.leading_zeros() - 24;
            break;
        }
        count
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
        if null_spec.domain.trim().is_empty()
            || !null_spec.null_accuracy.is_finite()
            || null_spec.null_accuracy <= 0.0
            || null_spec.null_accuracy > 1.0
        {
            return Err(EvidenceOSError::InvalidArgument);
        }
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
            .map(|last| self.resolution.is_local(last, preds))
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

    /// Query through an untrusted external oracle backend while preserving kernel-side
    /// canonicalization and fail-closed accounting (§3.3, §5.1, §10.1, §11.2).
    pub fn query_with_backend(
        &mut self,
        backend: &mut dyn OracleBackend,
        preds: &[u8],
    ) -> EvidenceOSResult<OracleResult> {
        let raw = backend.query_raw_metric(preds)?;
        if !raw.is_finite() {
            return Err(EvidenceOSError::OracleViolation);
        }
        let bucket = self.resolution.quantize_unit_interval(raw)?;
        let local = self
            .last_preds
            .as_ref()
            .map(|last| self.resolution.is_local(last, preds))
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
    fn ttl_expired_true_when_epoch_delta_exceeds() {
        let mut r = OracleResolution::new(8, 0.01).expect("resolution");
        r.calibrated_at_epoch = 10;
        r.ttl_epochs = Some(5);
        assert!(!r.ttl_expired(15));
        assert!(r.ttl_expired(16));
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
    fn locality_policy_changes_hysteresis_acceptance_behavior() {
        let holdout = HoldoutLabels::new(vec![1, 1, 1, 1]).expect("holdout");
        let mut exact_state = AccuracyOracleState::new(
            holdout.clone(),
            OracleResolution::new(8, 0.26).expect("resolution"),
            NullSpec {
                domain: "labels".into(),
                null_accuracy: 0.5,
                e_value_fn: EValueFn::Fixed(1.0),
            },
        )
        .expect("state");
        exact_state.resolution.locality_policy = LocalityPolicy::ExactMatchOnly;

        let mut hamming_state = AccuracyOracleState::new(
            holdout,
            OracleResolution::new(8, 0.26).expect("resolution"),
            NullSpec {
                domain: "labels".into(),
                null_accuracy: 0.5,
                e_value_fn: EValueFn::Fixed(1.0),
            },
        )
        .expect("state");
        hamming_state.resolution.locality_policy = LocalityPolicy::Hamming { max_bits: 1 };

        let _ = exact_state.query(&[1, 1, 1, 1]).expect("exact query1");
        let _ = hamming_state.query(&[1, 1, 1, 1]).expect("hamming query1");

        let exact = exact_state.query(&[1, 1, 1, 0]).expect("exact query2");
        let hamming = hamming_state.query(&[1, 1, 1, 0]).expect("hamming query2");

        assert!(!exact.hysteresis_applied);
        assert!(hamming.hysteresis_applied);
    }

    #[test]
    fn locality_policy_does_not_change_canonical_bucket_encoding() {
        let mut a = OracleResolution::new(16, 0.0).expect("resolution");
        let mut b = OracleResolution::new(16, 0.0).expect("resolution");
        a.locality_policy = LocalityPolicy::ExactMatchOnly;
        b.locality_policy = LocalityPolicy::BucketRadius { r: 3 };

        let encoded_a = a.encode_bucket(7).expect("encode a");
        let encoded_b = b.encode_bucket(7).expect("encode b");

        assert_eq!(encoded_a, encoded_b);
        assert_eq!(a.validate_canonical_bytes(&encoded_a).expect("decode a"), 7);
        assert_eq!(b.validate_canonical_bytes(&encoded_b).expect("decode b"), 7);
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
                Err(EvidenceOSError::InvalidCanonicalEncoding)
            ));

            prop_assert!(matches!(
                resolution.validate_canonical_bytes(&[]),
                Err(EvidenceOSError::InvalidCanonicalEncoding)
            ));
            prop_assert!(matches!(
                resolution.validate_canonical_bytes(&[encoded[0], 0]),
                Err(EvidenceOSError::InvalidCanonicalEncoding)
            ));
        }
    }
}

#[cfg(test)]
mod matrix_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn tie_breaker_halfway_boundary() {
        let mut r = OracleResolution::new(3, 0.0).expect("r");
        r.tie_breaker = TieBreaker::Lower;
        assert_eq!(r.quantize_unit_interval(0.25).expect("q"), 0);
        r.tie_breaker = TieBreaker::Upper;
        assert_eq!(r.quantize_unit_interval(0.25).expect("q"), 1);
        r.tie_breaker = TieBreaker::NearestEven;
        assert_eq!(r.quantize_unit_interval(0.25).expect("q"), 0);
    }

    #[test]
    fn encode_decode_handles_multibyte_symbol_space() {
        let r = OracleResolution::new(1024, 0.0).expect("r");
        let bytes = r.encode_bucket(700).expect("enc");
        assert_eq!(bytes.len(), 2);
        assert_eq!(r.decode_bucket(&bytes).expect("dec"), 700);
        assert_eq!(r.validate_canonical_bytes(&bytes).expect("val"), 700);
    }

    #[test]
    fn leakage_charge_is_log2_alphabet_size() {
        let r = OracleResolution::new(256, 0.0).expect("r");
        assert!((r.bits_per_call() - 8.0).abs() < 1e-12);

        // Support size upper-bound used by transcript accounting: |Y| <= 2^k.
        let support_upper_bound = 2f64.powf(r.bits_per_call());
        assert!(support_upper_bound >= f64::from(r.num_symbols));
        assert!((support_upper_bound - f64::from(r.num_symbols)).abs() < 1e-12);
    }

    #[test]
    fn canonical_encoding_rejects_padding_ambiguity() {
        let r = OracleResolution::new(8, 0.0).expect("r");
        let canonical = r.encode_bucket(3).expect("enc");
        assert_eq!(canonical.len(), 1);
        assert_eq!(r.validate_canonical_bytes(&canonical).expect("dec"), 3);

        // Same value with extra leading byte must fail-closed.
        assert!(matches!(
            r.validate_canonical_bytes(&[0, canonical[0]]),
            Err(EvidenceOSError::InvalidCanonicalEncoding)
        ));
    }

    #[test]
    fn ttl_none_vs_zero_and_one_boundaries() {
        let mut r = OracleResolution::new(8, 0.0).expect("r");
        r.calibrated_at_epoch = 10;
        r.ttl_epochs = None;
        assert!(!r.ttl_expired(10));
        r.ttl_epochs = Some(0);
        assert!(!r.ttl_expired(10));
        assert!(r.ttl_expired(11));
        r.ttl_epochs = Some(1);
        assert!(!r.ttl_expired(11));
        assert!(r.ttl_expired(12));
    }
    #[test]
    fn quantize_clamps_out_of_range() {
        let r = OracleResolution::new(8, 0.0).expect("r");
        assert_eq!(r.quantize_unit_interval(-10.0).expect("q"), 0);
        assert_eq!(r.quantize_unit_interval(10.0).expect("q"), 7);
    }
    #[test]
    fn holdout_labels_rejects_non_binary() {
        assert!(HoldoutLabels::new(vec![0, 2]).is_err());
    }
    #[test]
    fn holdout_labels_rejects_empty() {
        assert!(HoldoutLabels::new(vec![]).is_err());
    }
    #[test]
    fn tie_breaker_unit_cases() {
        let mut r = OracleResolution::new(3, 0.0).expect("r");
        r.tie_breaker = TieBreaker::Lower;
        assert_eq!(r.quantize_unit_interval(0.25).expect("q"), 0);
        r.tie_breaker = TieBreaker::Upper;
        assert_eq!(r.quantize_unit_interval(0.25).expect("q"), 1);
        r.tie_breaker = TieBreaker::NearestEven;
        assert_eq!(r.quantize_unit_interval(0.25).expect("q"), 0);
    }
    #[test]
    fn null_spec_rejects_empty_domain() {
        let hold = HoldoutLabels::new(vec![1, 0]).expect("h");
        let resolution = OracleResolution::new(8, 0.0).expect("r");
        let spec = NullSpec {
            domain: "   ".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::Fixed(1.0),
        };
        assert!(AccuracyOracleState::new(hold, resolution, spec).is_err());
    }
    #[test]
    fn null_spec_rejects_invalid_null_accuracy() {
        for acc in [0.0, -0.1, 1.1, f64::NAN, f64::INFINITY] {
            let hold = HoldoutLabels::new(vec![1, 0]).expect("h");
            let resolution = OracleResolution::new(8, 0.0).expect("r");
            let spec = NullSpec {
                domain: "d".into(),
                null_accuracy: acc,
                e_value_fn: EValueFn::Fixed(1.0),
            };
            assert!(AccuracyOracleState::new(hold, resolution, spec).is_err());
        }
    }
    #[test]
    fn accuracy_oracle_state_rejects_len_mismatch() {
        let hold = HoldoutLabels::new(vec![1, 0]).expect("h");
        let mut s = AccuracyOracleState::new(
            hold,
            OracleResolution::new(8, 0.1).expect("r"),
            NullSpec {
                domain: "d".into(),
                null_accuracy: 0.5,
                e_value_fn: EValueFn::Fixed(1.0),
            },
        )
        .expect("s");
        assert!(s.query(&[1]).is_err());
    }
    #[test]
    fn codec_hash_is_stable() {
        let a = OracleResolution::new(8, 0.0).expect("r").codec_hash;
        let b = OracleResolution::new(16, 0.0).expect("r").codec_hash;
        assert_eq!(a, b);
    }
    #[test]
    fn calibration_fields_roundtrip() {
        let h = [7u8; 32];
        let r = OracleResolution::new(8, 0.0)
            .expect("r")
            .with_calibration(h, 42);
        assert_eq!(r.calibration_manifest_hash, h);
        assert_eq!(r.calibrated_at_epoch, 42);
    }
    #[test]
    fn null_accuracy_validation() {
        let n = NullSpec {
            domain: "d".into(),
            null_accuracy: 0.0,
            e_value_fn: EValueFn::LikelihoodRatio { n_observations: 1 },
        };
        assert_eq!(n.compute_e_value(0.5), 0.0);
    }
    #[test]
    fn fixed_e_value_validation() {
        let n = NullSpec {
            domain: "d".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::Fixed(2.0),
        };
        assert_eq!(n.compute_e_value(0.1), 2.0);
    }
    #[test]
    fn compute_e_value_rejects_nan() {
        let n = NullSpec {
            domain: "d".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::LikelihoodRatio { n_observations: 1 },
        };
        assert_eq!(n.compute_e_value(f64::NAN), 0.0);
    }
    #[test]
    fn null_spec_domain_is_non_semantic() {
        let a = NullSpec {
            domain: "a".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::Fixed(1.1),
        };
        let b = NullSpec {
            domain: "b".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::Fixed(1.1),
        };
        assert_eq!(a.compute_e_value(0.7), b.compute_e_value(0.7));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test] fn oracle_roundtrip_varlen_symbols_proptest(num in 2u32..4096u32, b in 0u32..4095u32) { prop_assume!(b<num); let r=OracleResolution::new(num,0.0).expect("r"); let enc=r.encode_bucket(b).expect("e"); let dec=r.decode_bucket(&enc).expect("d"); prop_assert_eq!(dec,b); }
        #[test] fn tie_breaker_proptest(v in 0.0f64..1.0f64) { let r=OracleResolution::new(16,0.0).expect("r"); let b=r.quantize_unit_interval(v).expect("q"); prop_assert!(b<16); }
        #[test] fn ttl_expiry_proptest(base in 0u64..1000u64, ttl in 1u64..100u64) { let mut r=OracleResolution::new(8,0.0).expect("r"); r.calibrated_at_epoch=base; r.ttl_epochs=Some(ttl); prop_assert!(!r.ttl_expired(base+ttl)); prop_assert!(r.ttl_expired(base+ttl+1)); }
        #[test] fn ttl_monotone_proptest(calibrated in 0u64..10_000u64, ttl in 1u64..1024u64, current_a in 0u64..12_000u64, current_b in 0u64..12_000u64) {
            let mut r=OracleResolution::new(8,0.0).expect("r");
            r.calibrated_at_epoch=calibrated;
            r.ttl_epochs=Some(ttl);
            let low = current_a.min(current_b);
            let high = current_a.max(current_b);
            prop_assert!(u8::from(r.ttl_expired(low)) <= u8::from(r.ttl_expired(high)));
        }
        #[test] fn quantize_proptest(v in -10.0f64..10.0f64) { let r=OracleResolution::new(8,0.0).expect("r"); let b=r.quantize_unit_interval(v); prop_assert!(b.is_ok() || v.is_nan()); }
        #[test] fn holdout_labels_proptest(xs in prop::collection::vec(0u8..2u8,1..128)) { let h=HoldoutLabels::new(xs.clone()).expect("h"); prop_assert_eq!(h.len(), xs.len()); }
        #[test] fn oracle_query_proptest(xs in prop::collection::vec(0u8..2u8,2..64)) { let hold=HoldoutLabels::new(xs.clone()).expect("h"); let mut s=AccuracyOracleState::new(hold, OracleResolution::new(8,0.1).expect("r"), NullSpec{domain:"d".into(),null_accuracy:0.5,e_value_fn:EValueFn::Fixed(1.0)}).expect("s"); let r=s.query(&xs).expect("q"); prop_assert!(r.k_bits.is_finite()); }
        #[test] fn null_accuracy_proptest(a in 0.0f64..1.0f64, o in 0.0f64..1.0f64) { let n=NullSpec{domain:"d".into(),null_accuracy:a,e_value_fn:EValueFn::LikelihoodRatio{n_observations:2}}; let e=n.compute_e_value(o); prop_assert!(e.is_finite() || e.is_nan()); }
        #[test] fn fixed_e_value_proptest(v in 0.0f64..10.0f64) { let n=NullSpec{domain:"d".into(),null_accuracy:0.5,e_value_fn:EValueFn::Fixed(v)}; prop_assert_eq!(n.compute_e_value(0.2),v); }
        #[test] fn compute_e_value_proptest(a in 0.1f64..1.0f64, o in 0.0f64..1.0f64, nobs in 1usize..8usize) { let n=NullSpec{domain:"d".into(),null_accuracy:a,e_value_fn:EValueFn::LikelihoodRatio{n_observations:nobs}}; let e=n.compute_e_value(o); prop_assert!(e>=0.0 || e.is_nan()); }
        #[test] fn null_spec_domain_proptest(name in "[a-z]{1,8}") { let n=NullSpec{domain:name,null_accuracy:0.5,e_value_fn:EValueFn::Fixed(1.0)}; prop_assert_eq!(n.compute_e_value(0.9),1.0); }
    }
}
