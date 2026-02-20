// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use thiserror::Error;
use wasmtime::{
    Caller, Config, Engine, Extern, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use evidenceos_core::nullspec_contract::NullSpecContractV1;
use evidenceos_core::oracle::{AccuracyOracleState, HoldoutLabels, NullSpec, OracleResolution};
use evidenceos_core::structured_claims;

const TRACE_DOMAIN: &[u8] = b"evidenceos:judge_trace:v2";
const TRACE_INPUT_CAP_BYTES: usize = 64;
const WASM_PAGE_BYTES: u64 = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct VaultConfig {
    pub max_fuel: u64,
    pub max_memory_bytes: u64,
    pub max_output_bytes: u32,
    pub max_oracle_calls: u32,
}

#[derive(Debug, Clone)]
pub struct VaultExecutionContext {
    pub holdout_labels: Vec<u8>,
    pub oracle_num_buckets: u32,
    pub oracle_delta_sigma: f64,
    pub null_spec: NullSpecContractV1,
    pub output_schema_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VaultExecutionResult {
    pub canonical_output: Vec<u8>,
    pub judge_trace_hash: [u8; 32],
    pub fuel_used: u64,
    pub oracle_calls: u32,
    pub output_bytes: u32,
    pub e_value_total: f64,
    pub leakage_bits_total: f64,
    pub kout_bits_total: f64,
    pub oracle_buckets: Vec<u32>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VaultError {
    #[error("invalid vault configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid wasm module: {0}")]
    InvalidModule(String),
    #[error("wasm trap: {0}")]
    Trap(String),
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("guest memory out-of-bounds")]
    MemoryOob,
    #[error("output exceeds maximum bytes")]
    OutputTooLarge,
    #[error("output already emitted")]
    OutputAlreadyEmitted,
    #[error("structured output was not emitted")]
    OutputMissing,
    #[error("oracle call limit exceeded")]
    OracleCallLimitExceeded,
    #[error("invalid oracle input")]
    InvalidOracleInput,
    #[error("missing required export: run")]
    MissingRunExport,
    #[error("invalid structured claim: {0}")]
    InvalidStructuredClaim(String),
}

#[derive(Debug, Clone)]
enum HostCallRecord {
    OracleBucket {
        input_digest: [u8; 32],
        bucket: u32,
    },
    EmitStructuredClaim {
        output_preview: Vec<u8>,
        output_len: u32,
    },
}

#[derive(Debug)]
struct VaultHostState {
    config: VaultConfig,
    store_limits: StoreLimits,
    oracle_state: AccuracyOracleState,
    holdout_len: usize,
    oracle_calls: u32,
    output: Option<Vec<u8>>,
    host_error: Option<VaultError>,
    leakage_bits: f64,
    accumulated_log_e_value: f64,
    has_zero_e_value: bool,
    output_schema_id: String,
    kout_bits: f64,
    call_trace: Vec<HostCallRecord>,
}

#[derive(Clone)]
pub struct VaultEngine {
    engine: Engine,
}

impl VaultEngine {
    pub fn new() -> Result<Self, VaultError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.wasm_multi_memory(false);
        config.wasm_memory64(false);

        let engine = Engine::new(&config)
            .map_err(|err| VaultError::InvalidModule(format!("engine init failed: {err}")))?;
        Ok(Self { engine })
    }

    pub fn execute(
        &self,
        wasm: &[u8],
        context: &VaultExecutionContext,
        config: VaultConfig,
    ) -> Result<VaultExecutionResult, VaultError> {
        validate_config(&config)?;
        if wasm.is_empty() {
            return Err(VaultError::InvalidModule(
                "wasm module is empty".to_string(),
            ));
        }

        let module = Module::new(&self.engine, wasm)
            .map_err(|err| VaultError::InvalidModule(err.to_string()))?;
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(config.max_memory_bytes as usize)
            .build();

        let holdout = HoldoutLabels::new(context.holdout_labels.clone())
            .map_err(|_| VaultError::InvalidConfig("invalid holdout labels".to_string()))?;
        let resolution =
            OracleResolution::new(context.oracle_num_buckets, context.oracle_delta_sigma)
                .map_err(|_| VaultError::InvalidConfig("invalid oracle resolution".to_string()))?;
        let null_spec = NullSpec {
            domain: context.null_spec.domain.clone(),
            null_accuracy: context.null_spec.null_accuracy,
            e_value_fn: context.null_spec.as_oracle_evalue(),
        };
        let oracle_state = AccuracyOracleState::new(holdout.clone(), resolution, null_spec)
            .map_err(|_| VaultError::InvalidConfig("invalid oracle state".to_string()))?;

        let mut store = Store::new(
            &self.engine,
            VaultHostState {
                config,
                store_limits,
                oracle_state,
                holdout_len: holdout.len(),
                oracle_calls: 0,
                output: None,
                host_error: None,
                leakage_bits: 0.0,
                accumulated_log_e_value: 0.0,
                has_zero_e_value: false,
                output_schema_id: context.output_schema_id.clone(),
                kout_bits: 0.0,
                call_trace: Vec::new(),
            },
        );
        store.limiter(|state| &mut state.store_limits);
        store
            .set_fuel(config.max_fuel)
            .map_err(|err| VaultError::InvalidConfig(err.to_string()))?;

        let mut linker = Linker::new(&self.engine);
        self.define_imports(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|err| map_trap(&store, err))?;

        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .map_err(|_| VaultError::MissingRunExport)?;
        run.call(&mut store, ())
            .map_err(|err| map_trap(&store, err))?;

        let remaining_fuel = store
            .get_fuel()
            .map_err(|err| VaultError::Trap(err.to_string()))?;
        let fuel_used = config.max_fuel.saturating_sub(remaining_fuel);
        let host = store.data();
        if let Some(err) = host.host_error.clone() {
            return Err(err);
        }
        let output = host.output.clone().ok_or(VaultError::OutputMissing)?;
        let output_bytes = u32::try_from(output.len())
            .map_err(|_| VaultError::InvalidConfig("output length overflow".to_string()))?;

        let judge_trace_hash = compute_judge_trace_hash(
            wasm,
            &host.call_trace,
            &output,
            fuel_used,
            host.oracle_calls,
        );

        let e_value_total = if host.has_zero_e_value {
            0.0
        } else {
            host.accumulated_log_e_value.exp()
        };

        let oracle_buckets: Vec<u32> = host
            .call_trace
            .iter()
            .filter_map(|c| match c {
                HostCallRecord::OracleBucket { bucket, .. } => Some(*bucket),
                HostCallRecord::EmitStructuredClaim { .. } => None,
            })
            .collect();

        Ok(VaultExecutionResult {
            canonical_output: output,
            judge_trace_hash,
            fuel_used,
            oracle_calls: host.oracle_calls,
            output_bytes,
            e_value_total,
            leakage_bits_total: host.leakage_bits,
            kout_bits_total: host.kout_bits,
            oracle_buckets,
        })
    }

    fn define_imports(&self, linker: &mut Linker<VaultHostState>) -> Result<(), VaultError> {
        for module in ["env", "kernel"] {
            linker
                .func_wrap(
                    module,
                    "oracle_bucket",
                    |mut caller: Caller<'_, VaultHostState>,
                     pred_ptr: i32,
                     pred_len: i32|
                     -> anyhow::Result<i32> {
                        let preds = read_guest_memory(&mut caller, pred_ptr, pred_len)?;
                        let host = caller.data_mut();
                        host.oracle_calls = host.oracle_calls.saturating_add(1);
                        if host.oracle_calls > host.config.max_oracle_calls {
                            host.host_error = Some(VaultError::OracleCallLimitExceeded);
                            return Err(anyhow::anyhow!("oracle call limit exceeded"));
                        }
                        if preds.len() != host.holdout_len || preds.iter().any(|b| *b > 1) {
                            host.host_error = Some(VaultError::InvalidOracleInput);
                            return Err(anyhow::anyhow!("invalid oracle input"));
                        }

                        let oracle_result = host.oracle_state.query(&preds).map_err(|_| {
                            host.host_error = Some(VaultError::InvalidOracleInput);
                            anyhow::anyhow!("oracle query failed")
                        })?;
                        host.leakage_bits += oracle_result.k_bits;
                        if oracle_result.e_value == 0.0 {
                            host.has_zero_e_value = true;
                            host.accumulated_log_e_value = f64::NEG_INFINITY;
                        } else if oracle_result.e_value.is_finite() && oracle_result.e_value > 0.0 {
                            if !host.has_zero_e_value {
                                host.accumulated_log_e_value += oracle_result.e_value.ln();
                            }
                        } else {
                            host.host_error = Some(VaultError::InvalidOracleInput);
                            return Err(anyhow::anyhow!("invalid oracle e-value"));
                        }
                        let mut input_digest = [0_u8; 32];
                        input_digest.copy_from_slice(&Sha256::digest(&preds));
                        host.call_trace.push(HostCallRecord::OracleBucket {
                            input_digest,
                            bucket: oracle_result.bucket,
                        });
                        Ok(oracle_result.bucket as i32)
                    },
                )
                .map_err(|err| VaultError::InvalidModule(err.to_string()))?;

            linker
                .func_wrap(
                    module,
                    "emit_structured_claim",
                    |mut caller: Caller<'_, VaultHostState>,
                     ptr: i32,
                     len: i32|
                     -> anyhow::Result<i32> {
                        let output = read_guest_memory(&mut caller, ptr, len)?;
                        let host = caller.data_mut();
                        if host.output.is_some() {
                            host.host_error = Some(VaultError::OutputAlreadyEmitted);
                            return Err(anyhow::anyhow!(
                                "emit_structured_claim may only succeed once"
                            ));
                        }
                        if output.len() > host.config.max_output_bytes as usize {
                            host.host_error = Some(VaultError::OutputTooLarge);
                            return Err(anyhow::anyhow!("structured output too large"));
                        }
                        let validated = structured_claims::validate_and_canonicalize(
                            &host.output_schema_id,
                            &output,
                        )
                        .map_err(|_| {
                            host.host_error = Some(VaultError::InvalidStructuredClaim(
                                "schema validation failed".to_string(),
                            ));
                            anyhow::anyhow!("structured claim validation failed")
                        })?;
                        if validated.canonical_bytes.len() > host.config.max_output_bytes as usize {
                            host.host_error = Some(VaultError::OutputTooLarge);
                            return Err(anyhow::anyhow!("structured output too large"));
                        }
                        host.kout_bits = validated.kout_bits_upper_bound as f64;
                        host.call_trace.push(HostCallRecord::EmitStructuredClaim {
                            output_preview: validated
                                .canonical_bytes
                                .iter()
                                .copied()
                                .take(TRACE_INPUT_CAP_BYTES)
                                .collect(),
                            output_len: validated.canonical_bytes.len() as u32,
                        });
                        host.output = Some(validated.canonical_bytes);
                        Ok(0)
                    },
                )
                .map_err(|err| VaultError::InvalidModule(err.to_string()))?;
        }

        Ok(())
    }
}

fn validate_config(config: &VaultConfig) -> Result<(), VaultError> {
    if config.max_fuel == 0 {
        return Err(VaultError::InvalidConfig(
            "max_fuel must be > 0".to_string(),
        ));
    }
    if config.max_memory_bytes < WASM_PAGE_BYTES {
        return Err(VaultError::InvalidConfig(
            "max_memory_bytes must be at least one wasm page".to_string(),
        ));
    }
    if config.max_output_bytes == 0 {
        return Err(VaultError::InvalidConfig(
            "max_output_bytes must be > 0".to_string(),
        ));
    }
    if config.max_oracle_calls == 0 {
        return Err(VaultError::InvalidConfig(
            "max_oracle_calls must be > 0".to_string(),
        ));
    }
    Ok(())
}

fn read_guest_memory(
    caller: &mut Caller<'_, VaultHostState>,
    ptr: i32,
    len: i32,
) -> anyhow::Result<Vec<u8>> {
    if ptr < 0 || len < 0 {
        caller.data_mut().host_error = Some(VaultError::MemoryOob);
        return Err(anyhow::anyhow!("negative pointer/length"));
    }

    let ptr = ptr as usize;
    let len = len as usize;
    let end = ptr.checked_add(len).ok_or_else(|| {
        caller.data_mut().host_error = Some(VaultError::MemoryOob);
        anyhow::anyhow!("pointer overflow")
    })?;

    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => memory,
        _ => {
            caller.data_mut().host_error = Some(VaultError::MemoryOob);
            return Err(anyhow::anyhow!("missing exported memory"));
        }
    };

    if end > memory.data_size(&mut *caller) {
        caller.data_mut().host_error = Some(VaultError::MemoryOob);
        return Err(anyhow::anyhow!("memory read out-of-bounds"));
    }

    let mut data = vec![0_u8; len];
    memory.read(&mut *caller, ptr, &mut data).map_err(|_| {
        caller.data_mut().host_error = Some(VaultError::MemoryOob);
        anyhow::anyhow!("memory read failed")
    })?;
    Ok(data)
}

fn map_trap(store: &Store<VaultHostState>, err: anyhow::Error) -> VaultError {
    if let Some(host_error) = store.data().host_error.clone() {
        return host_error;
    }
    if err.to_string().to_ascii_lowercase().contains("fuel") {
        return VaultError::FuelExhausted;
    }
    VaultError::Trap(err.to_string())
}

fn compute_judge_trace_hash(
    wasm: &[u8],
    calls: &[HostCallRecord],
    output: &[u8],
    fuel_used: u64,
    oracle_calls: u32,
) -> [u8; 32] {
    let wasm_hash = Sha256::digest(wasm);
    let output_hash = Sha256::digest(output);
    let mut trace = Vec::new();

    trace.extend_from_slice(TRACE_DOMAIN);
    trace.extend_from_slice(&wasm_hash);
    trace.extend_from_slice(&fuel_used.to_be_bytes());
    trace.extend_from_slice(&oracle_calls.to_be_bytes());
    trace.extend_from_slice(&(calls.len() as u32).to_be_bytes());

    for call in calls {
        match call {
            HostCallRecord::OracleBucket {
                input_digest,
                bucket,
            } => {
                trace.push(0x01);
                trace.extend_from_slice(input_digest);
                trace.extend_from_slice(&bucket.to_be_bytes());
            }
            HostCallRecord::EmitStructuredClaim {
                output_preview,
                output_len,
            } => {
                trace.push(0x02);
                trace.extend_from_slice(&output_len.to_be_bytes());
                trace.extend_from_slice(&(output_preview.len() as u32).to_be_bytes());
                trace.extend_from_slice(output_preview);
            }
        }
    }

    trace.extend_from_slice(&output_hash);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&Sha256::digest(trace));
    out
}
