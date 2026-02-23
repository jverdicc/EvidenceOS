#[derive(Debug, Clone)]
pub struct Symbol;

#[derive(Debug, Clone)]
pub struct LedgerContext;

pub trait CostModel: Send + Sync {
    fn id(&self) -> &'static str;

    fn charge_bits(
        &self,
        symbol: &Symbol,
        alphabet_size: usize,
        context: &LedgerContext,
    ) -> f64;

    /// Must satisfy: charge >= 0 for all inputs.
    /// Recommended: charge >= log2(alphabet_size)
    /// for conservative soundness. Tighter models
    /// require separate theoretical justification.
    fn is_conservative(&self) -> bool;
}
