use wasmtime::{Config, OptLevel};

/// Builds the canonical deterministic Wasmtime configuration used by
/// sandboxed EvidenceOS wasm runtimes.
pub fn deterministic_wasmtime_config() -> Config {
    let mut cfg = Config::new();
    cfg.consume_fuel(true);
    cfg.cranelift_nan_canonicalization(true);
    cfg.cranelift_opt_level(OptLevel::None);
    cfg.wasm_simd(false);
    cfg.wasm_relaxed_simd(false);
    cfg.wasm_multi_memory(false);
    cfg.wasm_memory64(false);
    cfg
}
