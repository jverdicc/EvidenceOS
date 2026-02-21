use std::sync::Arc;

use crate::ledger;

pub mod router;

pub trait EpistemicIntervention: Send + Sync {
    fn intervention_id(&self) -> &str;
    fn calculate_k_cost(&self, alphabet_size: u64, transcript_len: usize) -> f64;
    fn certification_threshold(&self, alpha: f64, k_tot: f64) -> f64;
    fn nullspec_id(&self) -> &str;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ClassicalSupportBound;

impl EpistemicIntervention for ClassicalSupportBound {
    fn intervention_id(&self) -> &str {
        "classical-support-bound.v1"
    }

    fn calculate_k_cost(&self, alphabet_size: u64, transcript_len: usize) -> f64 {
        if alphabet_size < 2 {
            return 0.0;
        }
        (alphabet_size as f64).log2() * transcript_len as f64
    }

    fn certification_threshold(&self, alpha: f64, k_tot: f64) -> f64 {
        ledger::certification_barrier(alpha, k_tot)
    }

    fn nullspec_id(&self) -> &str {
        "nullspec.classical.v1"
    }
}

pub fn default_control_arm() -> Arc<dyn EpistemicIntervention> {
    Arc::new(ClassicalSupportBound)
}

#[cfg(all(test, feature = "trial-harness"))]
mod tests;
