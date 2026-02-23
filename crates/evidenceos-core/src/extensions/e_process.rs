use crate::extensions::nullspec::{KernelObservation, NullSpec};

#[derive(Debug, Clone)]
pub enum EProcessError {
    InvalidUpdate,
}

pub trait EProcess: Send + Sync {
    fn id(&self) -> &'static str;

    /// Update evidence wealth W given new observation.
    /// Must satisfy: E_H0[result] <= current_wealth
    /// (supermartingale property under H0).
    /// Proof or citation required for contributions.
    fn update(
        &self,
        current_wealth: f64,
        observation: &KernelObservation,
        null_spec: &dyn NullSpec,
    ) -> Result<f64, EProcessError>;

    /// Citation or proof sketch that this construction
    /// satisfies the supermartingale property.
    fn validity_reference(&self) -> &str;
}
