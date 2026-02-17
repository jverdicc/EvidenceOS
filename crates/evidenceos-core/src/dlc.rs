// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};

/// Deterministic Logical Clock (DLC).
///
/// Protocol-visible time is advanced in deterministic epochs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DlcConfig {
    pub epoch_size: u64,

    /// Optional protocol-level path-length normalization (PLN): if set,
    /// each tick uses this constant cost regardless of the provided cost.
    pub pln_constant_cost: Option<u64>,
}

impl DlcConfig {
    pub fn new(epoch_size: u64) -> EvidenceOSResult<Self> {
        if epoch_size == 0 {
            return Err(EvidenceOSError::InvalidArgument(
                "epoch_size must be positive".to_string(),
            ));
        }
        Ok(Self {
            epoch_size,
            pln_constant_cost: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicLogicalClock {
    cfg: DlcConfig,
    logical_instructions: u64,
}

impl DeterministicLogicalClock {
    pub fn new(cfg: DlcConfig) -> Self {
        Self {
            cfg,
            logical_instructions: 0,
        }
    }

    pub fn cfg(&self) -> DlcConfig {
        self.cfg
    }

    pub fn logical_instructions(&self) -> u64 {
        self.logical_instructions
    }

    pub fn current_epoch(&self) -> u64 {
        if self.logical_instructions == 0 {
            0
        } else {
            self.logical_instructions.div_ceil(self.cfg.epoch_size)
        }
    }

    pub fn tick(&mut self, cost: u64) -> u64 {
        let c = self.cfg.pln_constant_cost.unwrap_or(cost);
        self.logical_instructions = self.logical_instructions.saturating_add(c);
        self.current_epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlc_epoch_rounding() {
        let cfg = DlcConfig::new(10).unwrap();
        let mut dlc = DeterministicLogicalClock::new(cfg);
        assert_eq!(dlc.current_epoch(), 0);
        assert_eq!(dlc.tick(1), 1);
        assert_eq!(dlc.tick(8), 1);
        assert_eq!(dlc.tick(1), 1);
        assert_eq!(dlc.tick(1), 2);
    }

    #[test]
    fn pln_constant_cost_overrides() {
        let mut cfg = DlcConfig::new(10).unwrap();
        cfg.pln_constant_cost = Some(7);
        let mut dlc = DeterministicLogicalClock::new(cfg);
        assert_eq!(dlc.tick(1), 1);
        assert_eq!(dlc.logical_instructions(), 7);
        assert_eq!(dlc.tick(100), 2);
    }
}
