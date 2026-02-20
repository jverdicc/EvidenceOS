use crate::eprocess::DirichletMixtureEProcess;
use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::nullspec::{EProcessKind, NullSpecContractV1, NullSpecKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryConfig {
    pub alpha_drift_micros: u32,
    pub check_every_epochs: u64,
    pub max_staleness_epochs: u64,
}

impl CanaryConfig {
    pub fn barrier(self) -> EvidenceOSResult<f64> {
        if self.alpha_drift_micros == 0 || self.alpha_drift_micros > 1_000_000 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        if self.check_every_epochs == 0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let alpha = f64::from(self.alpha_drift_micros) / 1_000_000.0;
        Ok(1.0 / alpha)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanaryState {
    pub e_drift: f64,
    pub barrier: f64,
    pub last_epoch_checked: u64,
    pub config: CanaryConfig,
    pub drift_frozen: bool,
    #[serde(default)]
    counts: Vec<u64>,
    #[serde(default)]
    total: u64,
}

impl CanaryState {
    pub fn new(config: CanaryConfig) -> EvidenceOSResult<Self> {
        let barrier = config.barrier()?;
        Ok(Self {
            e_drift: 1.0,
            barrier,
            last_epoch_checked: 0,
            config,
            drift_frozen: false,
            counts: Vec::new(),
            total: 0,
        })
    }

    pub fn reset(&mut self) {
        self.e_drift = 1.0;
        self.last_epoch_checked = 0;
        self.drift_frozen = false;
        self.counts.clear();
        self.total = 0;
    }

    pub fn update_with_bucket(
        &mut self,
        contract: &NullSpecContractV1,
        y_bucket: usize,
        epoch: u64,
    ) -> EvidenceOSResult<bool> {
        if self.drift_frozen {
            return Ok(true);
        }
        if self.last_epoch_checked > 0
            && epoch.saturating_sub(self.last_epoch_checked) > self.config.max_staleness_epochs
        {
            self.drift_frozen = true;
            return Ok(true);
        }
        if self.last_epoch_checked > 0
            && epoch > self.last_epoch_checked
            && epoch.saturating_sub(self.last_epoch_checked) < self.config.check_every_epochs
        {
            return Ok(false);
        }

        self.e_drift = match (&contract.kind, &contract.eprocess) {
            (
                NullSpecKind::DiscreteBuckets { p0 },
                EProcessKind::DirichletMultinomialMixture { alpha },
            ) => {
                if self.counts.is_empty() {
                    self.counts = vec![0_u64; p0.len()];
                }
                if self.counts.len() != p0.len() || alpha.len() != p0.len() {
                    return Err(EvidenceOSError::InvalidArgument);
                }
                let mut ep = DirichletMixtureEProcess {
                    alpha: alpha.clone(),
                    counts: self.counts.clone(),
                    total: self.total,
                    e: self.e_drift,
                };
                ep.update(y_bucket, p0)?;
                self.counts = ep.counts;
                self.total = ep.total;
                ep.e
            }
            (
                NullSpecKind::ParametricBernoulli { p },
                EProcessKind::LikelihoodRatioFixedAlt { alt },
            ) => {
                if alt.len() != 2 || !p.is_finite() || *p <= 0.0 || *p >= 1.0 || y_bucket > 1 {
                    return Err(EvidenceOSError::InvalidArgument);
                }
                let p0 = if y_bucket == 1 { *p } else { 1.0 - *p };
                let inc = alt[y_bucket] / p0;
                let next_e = self.e_drift * inc;
                if !next_e.is_finite() || next_e < 0.0 {
                    return Err(EvidenceOSError::InvalidArgument);
                }
                next_e
            }
            _ => return Err(EvidenceOSError::InvalidArgument),
        };

        self.last_epoch_checked = epoch;
        if self.e_drift >= self.barrier {
            self.drift_frozen = true;
        }
        Ok(self.drift_frozen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contract() -> NullSpecContractV1 {
        NullSpecContractV1 {
            schema: "evidenceos.nullspec.v1".to_string(),
            nullspec_id: [0; 32],
            oracle_id: "oracle-a".to_string(),
            oracle_resolution_hash: [1; 32],
            holdout_handle: "holdout-a".to_string(),
            epoch_created: 1,
            ttl_epochs: 100,
            kind: NullSpecKind::DiscreteBuckets { p0: vec![0.2, 0.8] },
            eprocess: EProcessKind::DirichletMultinomialMixture {
                alpha: vec![1.0, 1.0],
            },
            calibration_manifest_hash: None,
            created_by: "ops".to_string(),
            signature_ed25519: vec![],
        }
    }

    #[test]
    fn drift_barrier_crossing_triggers_freeze() {
        let mut state = CanaryState::new(CanaryConfig {
            alpha_drift_micros: 100_000,
            check_every_epochs: 1,
            max_staleness_epochs: 10,
        })
        .expect("state");
        let contract = sample_contract();
        for epoch in 1..10 {
            let frozen = state
                .update_with_bucket(&contract, 0, epoch)
                .expect("update should succeed");
            if frozen {
                break;
            }
        }
        assert!(state.drift_frozen);
        assert!(state.e_drift >= state.barrier);
    }

    #[test]
    fn boundary_at_exactly_barrier_freezes() {
        let mut state = CanaryState::new(CanaryConfig {
            alpha_drift_micros: 200_000,
            check_every_epochs: 1,
            max_staleness_epochs: 10,
        })
        .expect("state");
        state.e_drift = state.barrier;
        let contract = sample_contract();
        let frozen = state
            .update_with_bucket(&contract, 0, 1)
            .expect("update should succeed");
        assert!(frozen);
    }

    #[test]
    fn deterministic_with_fixed_stream() {
        let cfg = CanaryConfig {
            alpha_drift_micros: 50_000,
            check_every_epochs: 1,
            max_staleness_epochs: 10,
        };
        let mut a = CanaryState::new(cfg).expect("a");
        let mut b = CanaryState::new(cfg).expect("b");
        let contract = sample_contract();
        let stream = [0usize, 1, 0, 0, 1, 0];
        for (i, bucket) in stream.into_iter().enumerate() {
            let epoch = (i + 1) as u64;
            let af = a
                .update_with_bucket(&contract, bucket, epoch)
                .expect("a update");
            let bf = b
                .update_with_bucket(&contract, bucket, epoch)
                .expect("b update");
            assert_eq!(a.e_drift, b.e_drift);
            assert_eq!(af, bf);
        }
    }
}
