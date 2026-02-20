use crate::error::{EvidenceOSError, EvidenceOSResult};

#[derive(Debug, Clone)]
pub struct DirichletMixtureEProcess {
    pub alpha: Vec<f64>,
    pub counts: Vec<u64>,
    pub total: u64,
    pub e: f64,
}

impl DirichletMixtureEProcess {
    pub fn new(alpha: Vec<f64>) -> EvidenceOSResult<Self> {
        if alpha.is_empty() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        for a in &alpha {
            if !a.is_finite() || *a <= 0.0 {
                return Err(EvidenceOSError::InvalidArgument);
            }
        }
        Ok(Self {
            counts: vec![0_u64; alpha.len()],
            alpha,
            total: 0,
            e: 1.0,
        })
    }

    pub fn update(&mut self, y_bucket_index: usize, p0: &[f64]) -> EvidenceOSResult<f64> {
        if y_bucket_index >= self.counts.len() || p0.len() != self.counts.len() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let p0y = p0[y_bucket_index];
        if !p0y.is_finite() || p0y <= 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }
        for p in p0 {
            if !p.is_finite() || *p < 0.0 {
                return Err(EvidenceOSError::InvalidArgument);
            }
        }
        for a in &self.alpha {
            if !a.is_finite() || *a <= 0.0 {
                return Err(EvidenceOSError::InvalidArgument);
            }
        }

        let alpha_sum: f64 = self.alpha.iter().sum();
        let predictive_alt = (self.counts[y_bucket_index] as f64 + self.alpha[y_bucket_index])
            / (self.total as f64 + alpha_sum);
        let increment = predictive_alt / p0y;
        let next_e = self.e * increment;
        if !increment.is_finite() || increment < 0.0 || !next_e.is_finite() || next_e < 0.0 {
            return Err(EvidenceOSError::InvalidArgument);
        }

        self.e = next_e;
        self.counts[y_bucket_index] = self.counts[y_bucket_index].saturating_add(1);
        self.total = self.total.saturating_add(1);
        Ok(self.e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn hand_verified_k3_sequence() {
        let mut ep = DirichletMixtureEProcess::new(vec![1.0, 1.0, 1.0]).expect("new");
        let p0 = vec![0.2, 0.3, 0.5];
        let e1 = ep.update(0, &p0).expect("e1");
        assert!((e1 - (1.0 / 3.0) / 0.2).abs() < 1e-12);
        let e2 = ep.update(2, &p0).expect("e2");
        let expected2 = e1 * ((1.0 / 4.0) / 0.5);
        assert!((e2 - expected2).abs() < 1e-12);
    }

    #[test]
    fn rejects_bad_inputs() {
        let mut ep = DirichletMixtureEProcess::new(vec![1.0, 1.0]).expect("new");
        assert!(ep.update(0, &[0.0, 1.0]).is_err());
        assert!(ep.update(0, &[f64::NAN, 1.0]).is_err());
        assert!(ep.update(0, &[f64::INFINITY, 1.0]).is_err());
        assert!(DirichletMixtureEProcess::new(vec![0.0, 1.0]).is_err());
    }

    #[test]
    fn deterministic_for_same_stream() {
        let p0 = vec![0.25, 0.25, 0.5];
        let stream = vec![0_usize, 2, 1, 2, 2, 0];
        let mut a = DirichletMixtureEProcess::new(vec![0.5, 0.5, 0.5]).expect("new a");
        let mut b = DirichletMixtureEProcess::new(vec![0.5, 0.5, 0.5]).expect("new b");
        for i in stream {
            let ea = a.update(i, &p0).expect("ea");
            let eb = b.update(i, &p0).expect("eb");
            assert_eq!(ea, eb);
        }
    }

    proptest! {
        #[test]
        fn eprocess_is_finite_nonnegative(
            len in 2usize..8,
            raw in proptest::collection::vec(0.001f64..1.0, 2..8),
            alpha_raw in proptest::collection::vec(0.001f64..3.0, 2..8),
            draws in proptest::collection::vec(0usize..7, 1..64),
        ) {
            let raw: Vec<f64> = raw.into_iter().take(len).collect();
            let alpha_raw: Vec<f64> = alpha_raw.into_iter().take(len).collect();
            prop_assume!(raw.len() == len && alpha_raw.len() == len);
            let sum: f64 = raw.iter().sum();
            let p0: Vec<f64> = raw.iter().map(|v| v / sum).collect();
            let mut ep = DirichletMixtureEProcess::new(alpha_raw.clone()).expect("new");
            for d in draws {
                let idx = d % p0.len();
                let e = ep.update(idx, &p0).expect("update");
                prop_assert!(e.is_finite());
                prop_assert!(e >= 0.0);
            }
        }
    }

    #[test]
    fn monte_carlo_null_average_e_close_to_one() {
        use rand::distributions::{Distribution, WeightedIndex};

        let p0 = vec![0.2, 0.3, 0.5];
        let dist = WeightedIndex::new(p0.clone()).expect("dist");
        let mut avg = 0.0;
        let runs = 32_u64;
        let t = 64_u64;
        for seed in 0..runs {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mut ep = DirichletMixtureEProcess::new(vec![1.0, 1.0, 1.0]).expect("new");
            for _ in 0..t {
                let y = dist.sample(&mut rng);
                let _ = ep.update(y, &p0).expect("update");
            }
            avg += ep.e;
        }
        avg /= runs as f64;
        assert!(avg > 0.0 && avg < 2.0, "avg={avg}");
    }
}
