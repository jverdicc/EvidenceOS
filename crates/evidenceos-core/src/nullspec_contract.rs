use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::oracle::EValueFn;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EValueSpecV1 {
    LikelihoodRatio { n_observations: usize },
    Fixed(f64),
    MixtureBinaryMartingale { grid: Vec<f64> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NullSpecContractV1 {
    pub id: String,
    pub domain: String,
    pub null_accuracy: f64,
    pub e_value: EValueSpecV1,
    pub created_at_unix: u64,
    pub version: u32,
}

impl NullSpecContractV1 {
    pub fn compute_id(&self) -> EvidenceOSResult<String> {
        let mut unsigned = self.clone();
        unsigned.id.clear();
        let bytes = canonical_json_bytes(&unsigned)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn canonical_json_bytes(&self) -> EvidenceOSResult<Vec<u8>> {
        canonical_json_bytes(self)
    }

    pub fn validate(&self, allow_fixed_e_value_in_dev: bool) -> EvidenceOSResult<()> {
        if self.version != 1 {
            return Err(EvidenceOSError::NullSpecInvalid(
                "unsupported nullspec contract version".to_string(),
            ));
        }
        if self.domain.trim().is_empty() {
            return Err(EvidenceOSError::NullSpecInvalid(
                "nullspec domain is required".to_string(),
            ));
        }
        if !self.null_accuracy.is_finite() || self.null_accuracy <= 0.0 || self.null_accuracy > 1.0
        {
            return Err(EvidenceOSError::NullSpecInvalid(
                "null_accuracy must be in (0,1]".to_string(),
            ));
        }
        let computed = self.compute_id()?;
        if self.id != computed {
            return Err(EvidenceOSError::NullSpecInvalid(
                "nullspec id mismatch".to_string(),
            ));
        }
        match &self.e_value {
            EValueSpecV1::LikelihoodRatio { n_observations } => {
                if *n_observations == 0 {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "n_observations must be > 0".to_string(),
                    ));
                }
            }
            EValueSpecV1::Fixed(v) => {
                if !allow_fixed_e_value_in_dev {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "fixed e-value is disabled".to_string(),
                    ));
                }
                if !v.is_finite() || *v < 0.0 {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "fixed e-value must be finite and >= 0".to_string(),
                    ));
                }
            }
            EValueSpecV1::MixtureBinaryMartingale { grid } => {
                if grid.is_empty() {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "mixture grid cannot be empty".to_string(),
                    ));
                }
                for p in grid {
                    if !p.is_finite() || *p <= 0.0 || *p >= 1.0 {
                        return Err(EvidenceOSError::NullSpecInvalid(
                            "mixture grid values must be in (0,1)".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn compute_e_value(&self, observed_accuracy: f64) -> EvidenceOSResult<f64> {
        self.compute_e_value_with_n(observed_accuracy, self.default_n_observations())
    }

    pub fn compute_e_value_with_n(
        &self,
        observed_accuracy: f64,
        n_observations: usize,
    ) -> EvidenceOSResult<f64> {
        if !observed_accuracy.is_finite() {
            return Err(EvidenceOSError::NullSpecInvalid(
                "observed accuracy must be finite".to_string(),
            ));
        }
        let p_hat = observed_accuracy.clamp(0.0, 1.0);
        match &self.e_value {
            EValueSpecV1::LikelihoodRatio { n_observations } => {
                let ratio = (p_hat / self.null_accuracy).max(0.0);
                Ok(ratio.powf(*n_observations as f64).clamp(0.0, f64::MAX))
            }
            EValueSpecV1::Fixed(v) => Ok(*v),
            EValueSpecV1::MixtureBinaryMartingale { grid } => {
                if n_observations == 0 {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "n_observations must be > 0 for mixture".to_string(),
                    ));
                }
                let n = n_observations as f64;
                let k = (p_hat * n).round().clamp(0.0, n) as usize;
                let mut sum = 0.0f64;
                for p_i in grid {
                    let ratio_success = p_i / self.null_accuracy;
                    let ratio_failure = (1.0 - p_i) / (1.0 - self.null_accuracy);
                    if !ratio_success.is_finite()
                        || !ratio_failure.is_finite()
                        || ratio_success <= 0.0
                        || ratio_failure <= 0.0
                    {
                        return Err(EvidenceOSError::NullSpecInvalid(
                            "invalid mixture ratio".to_string(),
                        ));
                    }
                    let term = ratio_success.powf(k as f64)
                        * ratio_failure.powf((n_observations - k) as f64);
                    if !term.is_finite() || term < 0.0 {
                        return Err(EvidenceOSError::NullSpecInvalid(
                            "mixture term is not finite".to_string(),
                        ));
                    }
                    sum += term;
                    if !sum.is_finite() {
                        return Err(EvidenceOSError::NullSpecInvalid(
                            "mixture accumulation overflow".to_string(),
                        ));
                    }
                }
                let out = sum / (grid.len() as f64);
                if !out.is_finite() || out < 0.0 {
                    return Err(EvidenceOSError::NullSpecInvalid(
                        "mixture e-value is invalid".to_string(),
                    ));
                }
                Ok(out)
            }
        }
    }

    pub fn as_oracle_evalue(&self) -> EValueFn {
        match &self.e_value {
            EValueSpecV1::LikelihoodRatio { n_observations } => EValueFn::LikelihoodRatio {
                n_observations: *n_observations,
            },
            EValueSpecV1::Fixed(v) => EValueFn::Fixed(*v),
            EValueSpecV1::MixtureBinaryMartingale { grid } => {
                EValueFn::MixtureBinaryMartingale { grid: grid.clone() }
            }
        }
    }

    fn default_n_observations(&self) -> usize {
        match self.e_value {
            EValueSpecV1::LikelihoodRatio { n_observations } => n_observations,
            _ => 1,
        }
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> EvidenceOSResult<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| EvidenceOSError::Internal)?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).map_err(|_| EvidenceOSError::Internal)
}

fn sort_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Map::new();
            for (k, v) in entries {
                out.insert(k, sort_json(v));
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}
