// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use thiserror::Error;
use wasmtime::{
    Caller, Config, Engine, Extern, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap,
};

const TRACE_DOMAIN: &[u8] = b"evidenceos:judge_trace:v1";
const WASM_PAGE_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct ExecutionLimits {
    pub max_fuel: u64,
    pub max_memory_bytes: usize,
    pub max_output_bytes: usize,
    pub max_output_calls: u32,
    pub max_host_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub output: Vec<u8>,
    pub fuel_used: u64,
    pub trace_hash: [u8; 32],
    pub output_calls: u32,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    #[error("wasm trap: {0}")]
    Trap(String),
    #[error("structured output was not emitted")]
    OutputMissing,
    #[error("structured output exceeds configured maximum bytes")]
    OutputTooLarge,
    #[error("too many structured outputs")]
    TooManyOutputs,
    #[error("guest memory access is out-of-bounds")]
    MemoryOob,
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("invalid wasm module: {0}")]
    InvalidModule(String),
    #[error("host call limit exceeded")]
    TooManyHostCalls,
}

#[derive(Debug, Clone)]
enum HostCall {
    Emit(Vec<u8>),
    GetLogicalEpoch(u64),
}

#[derive(Debug)]
struct HostState {
    logical_epoch: u64,
    limits: ExecutionLimits,
    store_limits: StoreLimits,
    output: Option<Vec<u8>>,
    output_calls: u32,
    host_calls: u32,
    transcript: Vec<HostCall>,
    host_error: Option<ExecutionError>,
}

#[derive(Debug, Clone)]
pub struct WasmExecutor {
    engine: Engine,
}

impl WasmExecutor {
    pub fn new() -> Result<Self, ExecutionError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_threads(false);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.wasm_multi_memory(false);
        config.wasm_reference_types(false);
        config.wasm_memory64(false);
        let engine = Engine::new(&config)
            .map_err(|err| ExecutionError::InvalidModule(format!("engine init failed: {err}")))?;
        Ok(Self { engine })
    }

    pub fn execute(
        &self,
        wasm: &[u8],
        logical_epoch: u64,
        limits: ExecutionLimits,
    ) -> Result<ExecutionResult, ExecutionError> {
        if wasm.is_empty() {
            return Err(ExecutionError::InvalidModule(
                "wasm module is empty".to_string(),
            ));
        }
        if limits.max_memory_bytes < WASM_PAGE_BYTES {
            return Err(ExecutionError::InvalidModule(
                "max_memory_bytes must be at least one wasm page".to_string(),
            ));
        }

        let module = Module::new(&self.engine, wasm)
            .map_err(|err| ExecutionError::InvalidModule(err.to_string()))?;

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                logical_epoch,
                limits,
                store_limits,
                output: None,
                output_calls: 0,
                host_calls: 0,
                transcript: Vec::new(),
                host_error: None,
            },
        );
        store.limiter(|host| &mut host.store_limits);
        store
            .set_fuel(limits.max_fuel)
            .map_err(|err| ExecutionError::InvalidModule(err.to_string()))?;

        let mut linker = Linker::<HostState>::new(&self.engine);
        self.define_host_abi(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|err| map_trap(&store, err))?;

        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .map_err(|err| ExecutionError::InvalidModule(format!("missing run export: {err}")))?;

        run.call(&mut store, ())
            .map_err(|err| map_trap(&store, err))?;

        let remaining = store
            .get_fuel()
            .map_err(|err| ExecutionError::Trap(err.to_string()))?;
        let fuel_used = limits.max_fuel.saturating_sub(remaining);

        let host = store.data();
        if let Some(err) = host.host_error.clone() {
            return Err(err);
        }
        let output = host.output.clone().ok_or(ExecutionError::OutputMissing)?;
        let trace_hash = compute_trace_hash(
            wasm,
            logical_epoch,
            fuel_used,
            &host.transcript,
            &output,
            host.output_calls,
        );
        Ok(ExecutionResult {
            output,
            fuel_used,
            trace_hash,
            output_calls: host.output_calls,
        })
    }

    fn define_host_abi(&self, linker: &mut Linker<HostState>) -> Result<(), ExecutionError> {
        for module in ["kernel", "env"] {
            linker
                .func_wrap(
                    module,
                    "emit_structured_claim",
                    |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> Result<(), Trap> {
                        charge_host_call(&mut caller)?;
                        let data = read_memory(&mut caller, ptr, len)?;
                        let host = caller.data_mut();
                        host.output_calls = host.output_calls.saturating_add(1);
                        if host.output_calls > host.limits.max_output_calls {
                            host.host_error = Some(ExecutionError::TooManyOutputs);
                            return Err(Trap::new("too many structured outputs"));
                        }
                        if data.len() > host.limits.max_output_bytes {
                            host.host_error = Some(ExecutionError::OutputTooLarge);
                            return Err(Trap::new("structured output too large"));
                        }
                        host.output = Some(data.clone());
                        host.transcript.push(HostCall::Emit(data));
                        Ok(())
                    },
                )
                .map_err(|err| ExecutionError::InvalidModule(err.to_string()))?;

            linker
                .func_wrap(
                    module,
                    "get_logical_epoch",
                    |mut caller: Caller<'_, HostState>| -> Result<i64, Trap> {
                        charge_host_call(&mut caller)?;
                        let host = caller.data_mut();
                        host.transcript
                            .push(HostCall::GetLogicalEpoch(host.logical_epoch));
                        Ok(host.logical_epoch as i64)
                    },
                )
                .map_err(|err| ExecutionError::InvalidModule(err.to_string()))?;
        }
        Ok(())
    }
}

fn charge_host_call(caller: &mut Caller<'_, HostState>) -> Result<(), Trap> {
    let host = caller.data_mut();
    host.host_calls = host.host_calls.saturating_add(1);
    if host.host_calls > host.limits.max_host_calls {
        host.host_error = Some(ExecutionError::TooManyHostCalls);
        return Err(Trap::new("host call limit exceeded"));
    }
    Ok(())
}

fn read_memory(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Result<Vec<u8>, Trap> {
    if ptr < 0 || len < 0 {
        caller.data_mut().host_error = Some(ExecutionError::MemoryOob);
        return Err(Trap::new("negative pointer or length"));
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let end = ptr.checked_add(len).ok_or_else(|| {
        caller.data_mut().host_error = Some(ExecutionError::MemoryOob);
        Trap::new("pointer overflow")
    })?;

    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => memory,
        _ => {
            caller.data_mut().host_error = Some(ExecutionError::MemoryOob);
            return Err(Trap::new("memory export not found"));
        }
    };
    if end > memory.data_size(&mut *caller) {
        caller.data_mut().host_error = Some(ExecutionError::MemoryOob);
        return Err(Trap::new("memory out of bounds"));
    }
    let mut data = vec![0_u8; len];
    memory.read(&mut *caller, ptr, &mut data).map_err(|_| {
        caller.data_mut().host_error = Some(ExecutionError::MemoryOob);
        Trap::new("memory read failed")
    })?;
    Ok(data)
}

fn map_trap(store: &Store<HostState>, err: anyhow::Error) -> ExecutionError {
    if let Some(host) = store.data().host_error.clone() {
        return host;
    }
    let msg = err.to_string();
    if msg.to_ascii_lowercase().contains("fuel") {
        return ExecutionError::FuelExhausted;
    }
    ExecutionError::Trap(msg)
}

fn compute_trace_hash(
    wasm: &[u8],
    logical_epoch: u64,
    fuel_used: u64,
    transcript: &[HostCall],
    output: &[u8],
    output_calls: u32,
) -> [u8; 32] {
    let module_hash = Sha256::digest(wasm);
    let mut h = Sha256::new();
    h.update(TRACE_DOMAIN);
    h.update(module_hash);
    h.update(logical_epoch.to_be_bytes());
    h.update(fuel_used.to_be_bytes());
    h.update(output_calls.to_be_bytes());
    h.update((transcript.len() as u32).to_be_bytes());
    for call in transcript {
        match call {
            HostCall::Emit(bytes) => {
                h.update([0x01]);
                h.update((bytes.len() as u32).to_be_bytes());
                h.update(bytes);
            }
            HostCall::GetLogicalEpoch(epoch) => {
                h.update([0x02]);
                h.update(epoch.to_be_bytes());
            }
        }
    }
    h.update((output.len() as u32).to_be_bytes());
    h.update(output);
    let out = h.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&out);
    hash
}
