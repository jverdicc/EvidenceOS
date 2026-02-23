#[derive(Debug, Clone)]
pub struct KernelObservation;

#[derive(Debug, Clone)]
pub enum NullSpecError {
    UnsupportedObservation,
}

pub trait NullSpec: Send + Sync {
    /// Unique identifier for registry lookup
    fn id(&self) -> &'static str;

    /// Human-readable null hypothesis description
    fn null_hypothesis(&self) -> &str;

    /// Update e-value given a new kernel-released
    /// observation. observation is post-canonicalization
    /// and post-charge — the kernel has already metered
    /// the leakage for this symbol.
    fn update_e_value(
        &self,
        current_e: f64,
        observation: &KernelObservation,
    ) -> Result<f64, NullSpecError>;

    /// k-bit cost this NullSpec charges per evaluation.
    /// Must be >= log2(oracle_num_symbols).
    fn leakage_cost_bits(&self) -> f64;

    /// Citation for the underlying statistical method.
    fn citation(&self) -> Option<&str>;
}
