use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistributionSummary {
    #[serde(alias = "mean_cycles")]
    pub mean_fuel: u64,
    #[serde(alias = "p95_cycles")]
    pub p95_fuel: u64,
    #[serde(alias = "p99_cycles")]
    pub p99_fuel: u64,
}

impl DistributionSummary {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.mean_fuel == 0 || self.p95_fuel == 0 || self.p99_fuel == 0 {
            return Err("distribution values must be > 0");
        }
        if self.p95_fuel < self.mean_fuel {
            return Err("p95_fuel must be >= mean_fuel");
        }
        if self.p99_fuel < self.p95_fuel {
            return Err("p99_fuel must be >= p95_fuel");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecommendedPlnCosts {
    #[serde(alias = "syscall_constant_cost")]
    pub syscall_target_fuel: u64,
    #[serde(alias = "wasm_instruction_constant_cost")]
    pub wasm_instruction_target_fuel: u64,
}

impl RecommendedPlnCosts {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.syscall_target_fuel == 0 || self.wasm_instruction_target_fuel == 0 {
            return Err("recommended costs must be > 0");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlnProfile {
    pub cpu_model: String,
    #[serde(alias = "syscall_cycles")]
    pub syscall_fuel: DistributionSummary,
    #[serde(alias = "wasm_instruction_cycles")]
    pub wasm_instruction_fuel: DistributionSummary,
    #[serde(alias = "recommended_pln_constant_cost")]
    pub recommended_pln_target_fuel: RecommendedPlnCosts,
}

impl PlnProfile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.cpu_model.trim().is_empty() {
            return Err("cpu_model must be non-empty");
        }
        self.syscall_fuel.validate()?;
        self.wasm_instruction_fuel.validate()?;
        self.recommended_pln_target_fuel.validate()?;
        if self.recommended_pln_target_fuel.syscall_target_fuel < self.syscall_fuel.p99_fuel {
            return Err("syscall_constant_cost must be >= syscall p99");
        }
        if self
            .recommended_pln_target_fuel
            .wasm_instruction_target_fuel
            < self.wasm_instruction_fuel.p99_fuel
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
            syscall_fuel: DistributionSummary {
                mean_fuel: 10,
                p95_fuel: 15,
                p99_fuel: 20,
            },
            wasm_instruction_fuel: DistributionSummary {
                mean_fuel: 4,
                p95_fuel: 6,
                p99_fuel: 8,
            },
            recommended_pln_target_fuel: RecommendedPlnCosts {
                syscall_target_fuel: 20,
                wasm_instruction_target_fuel: 8,
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
        p.syscall_fuel.p95_fuel = 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn pln_profile_rejects_understated_recommendation() {
        let mut p = valid_profile();
        p.recommended_pln_target_fuel.wasm_instruction_target_fuel = 7;
        assert!(p.validate().is_err());
    }
}
