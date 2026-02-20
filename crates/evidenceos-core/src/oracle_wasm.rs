use crate::aspec::{verify_aspec, AspecLane, AspecPolicy};
use crate::error::{EvidenceOSError, EvidenceOSResult};
use wasmtime::{
    Config, Engine, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

#[derive(Debug, Clone)]
pub struct WasmOracleSandboxPolicy {
    pub max_memory_bytes: usize,
    pub max_fuel: u64,
}

impl Default for WasmOracleSandboxPolicy {
    fn default() -> Self {
        Self {
            max_memory_bytes: 1 << 20,
            max_fuel: 250_000,
        }
    }
}

#[derive(Debug)]
struct OracleStoreData {
    limits: StoreLimits,
}

pub struct WasmOracleSandbox {
    engine: Engine,
    module: Module,
    policy: WasmOracleSandboxPolicy,
}

impl WasmOracleSandbox {
    pub fn new(
        wasm: &[u8],
        aspec_policy: &AspecPolicy,
        policy: WasmOracleSandboxPolicy,
    ) -> EvidenceOSResult<Self> {
        let report = verify_aspec(wasm, aspec_policy);
        let ignorable = [
            "missing required export: run",
            "missing required import emit_structured_claim in env:: or kernel::",
            "disallowed export: oracle_query",
        ];
        let critical_reasons: Vec<_> = report
            .reasons
            .iter()
            .filter(|reason| !ignorable.iter().any(|msg| *reason == msg))
            .collect();
        if !matches!(report.lane, AspecLane::HighAssurance) || !critical_reasons.is_empty() {
            return Err(EvidenceOSError::AspecRejected);
        }

        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.cranelift_nan_canonicalization(true);
        cfg.wasm_simd(false);
        cfg.wasm_relaxed_simd(false);
        cfg.wasm_memory64(false);
        let engine = Engine::new(&cfg).map_err(|_| EvidenceOSError::OracleViolation)?;
        let module = Module::new(&engine, wasm).map_err(|_| EvidenceOSError::OracleViolation)?;

        let has_memory = module
            .exports()
            .any(|e| e.name() == "memory" && matches!(e.ty(), ExternType::Memory(_)));
        if !has_memory {
            return Err(EvidenceOSError::OracleViolation);
        }

        Ok(Self {
            engine,
            module,
            policy,
        })
    }

    pub fn query_raw_metric(&self, preds: &[u8]) -> EvidenceOSResult<f64> {
        if preds.is_empty() || preds.iter().any(|b| *b > 1) {
            return Err(EvidenceOSError::InvalidArgument);
        }
        let mut request = Vec::with_capacity(4 + preds.len());
        request.extend_from_slice(&(preds.len() as u32).to_le_bytes());
        request.extend_from_slice(preds);

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.policy.max_memory_bytes)
            .build();
        let mut store = Store::new(
            &self.engine,
            OracleStoreData {
                limits: store_limits,
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.policy.max_fuel)
            .map_err(|_| EvidenceOSError::OracleViolation)?;

        let linker = Linker::<OracleStoreData>::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|_| EvidenceOSError::OracleViolation)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(EvidenceOSError::OracleViolation)?;
        let query = instance
            .get_typed_func::<(i32, i32), f64>(&mut store, "oracle_query")
            .map_err(|_| EvidenceOSError::OracleViolation)?;

        memory
            .write(&mut store, 0, &request)
            .map_err(|_| EvidenceOSError::OracleViolation)?;
        let metric = query
            .call(&mut store, (0, request.len() as i32))
            .map_err(|_| EvidenceOSError::OracleViolation)?;
        if !metric.is_finite() {
            return Err(EvidenceOSError::OracleViolation);
        }
        Ok(metric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aspec::FloatPolicy;

    fn oracle_wat(body: &str) -> Vec<u8> {
        wat::parse_str(format!(
            "(module (memory (export \"memory\") 1) (func (export \"oracle_query\") (param i32 i32) (result f64) {body}))"
        ))
        .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn aspec_rejects_wasi_imports() {
        let wasm = wat::parse_str("(module (import \"wasi_snapshot_preview1\" \"fd_write\" (func)) (memory (export \"memory\") 1) (func (export \"oracle_query\") (param i32 i32) (result f64) f64.const 0.1))")
            .unwrap_or_else(|_| unreachable!());
        let policy = AspecPolicy {
            float_policy: FloatPolicy::Allow,
            ..AspecPolicy::default()
        };
        let sandbox = WasmOracleSandbox::new(&wasm, &policy, WasmOracleSandboxPolicy::default());
        assert!(sandbox.is_err());
    }

    #[test]
    fn wasm_query_rejects_nan() {
        let wasm = oracle_wat("f64.const nan:canonical");
        let policy = AspecPolicy {
            float_policy: FloatPolicy::Allow,
            ..AspecPolicy::default()
        };
        let sandbox = WasmOracleSandbox::new(&wasm, &policy, WasmOracleSandboxPolicy::default())
            .unwrap_or_else(|_| unreachable!());
        assert!(sandbox.query_raw_metric(&[0, 1]).is_err());
    }
}
