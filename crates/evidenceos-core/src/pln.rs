use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistributionSummary {
    pub mean_cycles: u64,
    pub p95_cycles: u64,
    pub p99_cycles: u64,
}

impl DistributionSummary {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.mean_cycles == 0 || self.p95_cycles == 0 || self.p99_cycles == 0 {
            return Err("distribution values must be > 0");
        }
        if self.p95_cycles < self.mean_cycles {
            return Err("p95_cycles must be >= mean_cycles");
        }
        if self.p99_cycles < self.p95_cycles {
            return Err("p99_cycles must be >= p95_cycles");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecommendedPlnCosts {
    pub syscall_constant_cost: u64,
    pub wasm_instruction_constant_cost: u64,
}

impl RecommendedPlnCosts {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.syscall_constant_cost == 0 || self.wasm_instruction_constant_cost == 0 {
            return Err("recommended costs must be > 0");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlnProfile {
    pub cpu_model: String,
    pub syscall_cycles: DistributionSummary,
    pub wasm_instruction_cycles: DistributionSummary,
    pub recommended_pln_constant_cost: RecommendedPlnCosts,
}

impl PlnProfile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.cpu_model.trim().is_empty() {
            return Err("cpu_model must be non-empty");
        }
        self.syscall_cycles.validate()?;
        self.wasm_instruction_cycles.validate()?;
        self.recommended_pln_constant_cost.validate()?;
        if self.recommended_pln_constant_cost.syscall_constant_cost < self.syscall_cycles.p99_cycles
        {
            return Err("syscall_constant_cost must be >= syscall p99");
        }
        if self
            .recommended_pln_constant_cost
            .wasm_instruction_constant_cost
            < self.wasm_instruction_cycles.p99_cycles
        {
            return Err("wasm_instruction_constant_cost must be >= wasm p99");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_profile() -> PlnProfile {
        PlnProfile {
            cpu_model: "test-cpu".to_string(),
            syscall_cycles: DistributionSummary {
                mean_cycles: 10,
                p95_cycles: 15,
                p99_cycles: 20,
            },
            wasm_instruction_cycles: DistributionSummary {
                mean_cycles: 4,
                p95_cycles: 6,
                p99_cycles: 8,
            },
            recommended_pln_constant_cost: RecommendedPlnCosts {
                syscall_constant_cost: 20,
                wasm_instruction_constant_cost: 8,
            },
        }
    }

    #[test]
    fn pln_profile_validates() {
        let p = valid_profile();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn pln_profile_rejects_invalid_distribution() {
        let mut p = valid_profile();
        p.syscall_cycles.p95_cycles = 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn pln_profile_rejects_understated_recommendation() {
        let mut p = valid_profile();
        p.recommended_pln_constant_cost
            .wasm_instruction_constant_cost = 7;
        assert!(p.validate().is_err());
    }
}
