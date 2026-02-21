use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;

use super::EpistemicIntervention;

#[derive(Clone)]
pub struct TrialRouter {
    arms: Vec<Arc<dyn EpistemicIntervention>>,
}

impl TrialRouter {
    pub fn new(arms: Vec<Arc<dyn EpistemicIntervention>>) -> Self {
        Self { arms }
    }

    pub fn assign(&self) -> (Arc<dyn EpistemicIntervention>, String) {
        assert!(
            !self.arms.is_empty(),
            "trial router requires at least one arm"
        );
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&nonce[..8]);
        let index_seed = u64::from_le_bytes(seed);
        let idx = (index_seed % self.arms.len() as u64) as usize;
        (Arc::clone(&self.arms[idx]), hex::encode(nonce))
    }
}
