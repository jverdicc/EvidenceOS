use wasmtime::Config;

pub(crate) fn deterministic_wasmtime_config() -> Config {
    evidenceos_core::wasm_config::deterministic_wasmtime_config()
}
