// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};

/// Deterministic Logical Clock (DLC).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DlcConfig {
    pub epoch_size: u64,
    /// SIMULATION NOTE: This field implements protocol-level PLN: all execution paths are charged
    /// the constant cost, removing data-dependent timing variation from the logical transcript. In
    /// production hardware deployments, true cycle-accurate PLN requires padding NOP execution in
    /// the verified hardware base (VHB). This field only removes timing as a protocol variable.
    /// See §12.6.
    pub pln_constant_cost: Option<u64>,
}

impl DlcConfig {
    pub fn new(epoch_size: u64) -> EvidenceOSResult<Self> {
        if epoch_size == 0 || epoch_size >= u64::MAX / 2 {
            return Err(EvidenceOSError::InvalidArgument);
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

    pub fn tick(&mut self, cost: u64) -> EvidenceOSResult<u64> {
        let c = self.cfg.pln_constant_cost.unwrap_or(cost);
        self.logical_instructions = self
            .logical_instructions
            .checked_add(c)
            .ok_or(EvidenceOSError::InvalidArgument)?;
        Ok(self.current_epoch())
    }

    pub fn reset_to_epoch(&mut self, epoch: u64) -> EvidenceOSResult<()> {
        self.logical_instructions = epoch
            .checked_mul(self.cfg.epoch_size)
            .ok_or(EvidenceOSError::InvalidArgument)?;
        Ok(())
    }

    pub fn instructions_until_next_epoch(&self) -> u64 {
        self.cfg.epoch_size - (self.logical_instructions % self.cfg.epoch_size)
    }

    pub fn is_at_epoch_boundary(&self) -> bool {
        self.logical_instructions
            .is_multiple_of(self.cfg.epoch_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_overflow_returns_err() {
        let cfg = DlcConfig::new(10).expect("cfg");
        let mut dlc = DeterministicLogicalClock {
            cfg,
            logical_instructions: u64::MAX - 1,
        };
        assert!(matches!(dlc.tick(2), Err(EvidenceOSError::InvalidArgument)));
    }

    #[test]
    fn pln_ignores_actual_cost() {
        let mut cfg = DlcConfig::new(10).expect("cfg");
        cfg.pln_constant_cost = Some(5);
        let mut dlc = DeterministicLogicalClock::new(cfg);
        dlc.tick(100).expect("tick");
        assert_eq!(dlc.logical_instructions(), 5);
    }

    #[test]
    fn reset_to_epoch_correct() {
        let cfg = DlcConfig::new(10).expect("cfg");
        let mut dlc = DeterministicLogicalClock::new(cfg);
        dlc.reset_to_epoch(3).expect("reset");
        assert_eq!(dlc.logical_instructions(), 30);
    }
}
