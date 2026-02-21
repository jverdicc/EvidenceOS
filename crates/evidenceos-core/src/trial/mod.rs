use std::sync::Arc;

use crate::ledger;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod router;

pub const MAX_INTERVENTION_DESCRIPTOR_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OraclePolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencePolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NullSpecPolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputPolicyDescriptor {
    pub policy_id: String,
    pub params: Value,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChargeContext {
    pub alphabet_size: u64,
    pub transcript_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KChargeResult {
    pub k_charge: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BarrierContext {
    pub alpha: f64,
    pub k_tot: f64,
}

pub fn canonicalize_descriptor_json(value: &Value) -> Result<Vec<u8>, &'static str> {
    let bytes = crate::capsule::canonical_json(value).map_err(|_| "canonicalization failed")?;
    if bytes.len() > MAX_INTERVENTION_DESCRIPTOR_BYTES {
        return Err("descriptor too large");
    }
    Ok(bytes)
}

pub trait EpistemicIntervention: Send + Sync {
    fn id(&self) -> &str;
    fn version(&self) -> &str;
    fn arm_parameters(&self) -> Value;
    fn oracle_policy(&self) -> OraclePolicyDescriptor;
    fn dependence_policy(&self) -> DependencePolicyDescriptor;
    fn nullspec_policy(&self) -> NullSpecPolicyDescriptor;
    fn output_policy(&self) -> OutputPolicyDescriptor;
    fn compute_k_charge(&self, ctx: &ChargeContext) -> KChargeResult;
    fn certification_barrier_multiplier(&self, ctx: &BarrierContext) -> f64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ClassicalSupportBound;

impl EpistemicIntervention for ClassicalSupportBound {
    fn id(&self) -> &str {
        "classical-support-bound"
    }

    fn version(&self) -> &str {
        "v1"
    }

    fn arm_parameters(&self) -> Value {
        serde_json::json!({"charge_model": "log2_alphabet"})
    }

    fn oracle_policy(&self) -> OraclePolicyDescriptor {
        OraclePolicyDescriptor {
            policy_id: "oracle.default.v1".to_string(),
            params: serde_json::json!({"hysteresis": "kernel-default"}),
        }
    }

    fn dependence_policy(&self) -> DependencePolicyDescriptor {
        DependencePolicyDescriptor {
            policy_id: "dependence.default.v1".to_string(),
            params: serde_json::json!({"tax": "kernel-default"}),
        }
    }

    fn nullspec_policy(&self) -> NullSpecPolicyDescriptor {
        NullSpecPolicyDescriptor {
            policy_id: "nullspec.classical.v1".to_string(),
            params: serde_json::json!({"gating": "strict"}),
        }
    }

    fn output_policy(&self) -> OutputPolicyDescriptor {
        OutputPolicyDescriptor {
            policy_id: "output.structured.v1".to_string(),
            params: serde_json::json!({"require_structured_claims": true}),
        }
    }

    fn compute_k_charge(&self, ctx: &ChargeContext) -> KChargeResult {
        let k_charge = if ctx.alphabet_size < 2 {
            0.0
        } else {
            (ctx.alphabet_size as f64).log2() * ctx.transcript_len as f64
        };
        KChargeResult { k_charge }
    }

    fn certification_barrier_multiplier(&self, ctx: &BarrierContext) -> f64 {
        ledger::certification_barrier(ctx.alpha, ctx.k_tot)
    }
}

pub fn default_control_arm() -> Arc<dyn EpistemicIntervention> {
    Arc::new(ClassicalSupportBound)
}

#[cfg(all(test, feature = "trial-harness"))]
mod tests;
