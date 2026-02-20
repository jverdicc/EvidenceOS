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

use getrandom::getrandom;
use sha2::{Digest, Sha256};
use thiserror::Error;
use wasmtime::{Caller, Engine, Extern, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

use evidenceos_core::nullspec_contract::NullSpecContractV1;
use evidenceos_core::oracle::{AccuracyOracleState, HoldoutLabels, NullSpec, OracleResolution};
use evidenceos_core::structured_claims;

use crate::wasm_config::deterministic_wasmtime_config;

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
    pub dp_epsilon_budget: f64,
    pub dp_delta_budget: f64,
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
    pub dp_epsilon_total: f64,
    pub dp_delta_total: f64,
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
    #[error("invalid differential privacy input")]
    InvalidDpInput,
    #[error("differential privacy budget exceeded")]
    DpBudgetExceeded,
    #[error("secure random generator failure")]
    RngFailure,
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
    DpPrimitive {
        mechanism: u8,
        epsilon_bits: u64,
        delta_bits: u64,
        arg0_bits: u64,
        arg1_bits: u64,
        noise_bits: u64,
        output_bits: u64,
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
    dp_epsilon_total: f64,
    dp_delta_total: f64,
    dp_epsilon_budget: f64,
    dp_delta_budget: f64,
}

#[derive(Clone)]
pub struct VaultEngine {
    engine: Engine,
}

impl VaultEngine {
    pub fn new() -> Result<Self, VaultError> {
        let config = deterministic_wasmtime_config();

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
                dp_epsilon_total: 0.0,
                dp_delta_total: 0.0,
                dp_epsilon_budget: context.dp_epsilon_budget,
                dp_delta_budget: context.dp_delta_budget,
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
                HostCallRecord::DpPrimitive { .. } => None,
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
            dp_epsilon_total: host.dp_epsilon_total,
            dp_delta_total: host.dp_delta_total,
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

            linker
                .func_wrap(
                    module,
                    "dp_laplace_i64",
                    |mut caller: Caller<'_, VaultHostState>,
                     value: i64,
                     scale: f64,
                     epsilon: f64,
                     delta: f64|
                     -> anyhow::Result<i64> {
                        validate_dp_charge_inputs(scale, epsilon, delta).map_err(|err| {
                            caller.data_mut().host_error = Some(err);
                            anyhow::anyhow!("invalid dp input")
                        })?;
                        charge_dp_budget(caller.data_mut(), epsilon, delta).map_err(|err| {
                            caller.data_mut().host_error = Some(err);
                            anyhow::anyhow!("dp budget exhausted")
                        })?;
                        let noise = sample_laplace(scale).map_err(|err| {
                            caller.data_mut().host_error = Some(err);
                            anyhow::anyhow!("laplace sampling failed")
                        })?;
                        let noised = (value as f64) + noise;
                        let rounded = noised.round();
                        if !rounded.is_finite()
                            || rounded < i64::MIN as f64
                            || rounded > i64::MAX as f64
                        {
                            caller.data_mut().host_error = Some(VaultError::InvalidDpInput);
                            return Err(anyhow::anyhow!("laplace output overflow"));
                        }
                        let out = rounded as i64;
                        caller
                            .data_mut()
                            .call_trace
                            .push(HostCallRecord::DpPrimitive {
                                mechanism: 0x10,
                                epsilon_bits: epsilon.to_bits(),
                                delta_bits: delta.to_bits(),
                                arg0_bits: (value as f64).to_bits(),
                                arg1_bits: scale.to_bits(),
                                noise_bits: noise.to_bits(),
                                output_bits: (out as f64).to_bits(),
                            });
                        Ok(out)
                    },
                )
                .map_err(|err| VaultError::InvalidModule(err.to_string()))?;

            linker
                .func_wrap(
                    module,
                    "dp_gaussian_f64",
                    |mut caller: Caller<'_, VaultHostState>,
                     value: f64,
                     sigma: f64,
                     epsilon: f64,
                     delta: f64|
                     -> anyhow::Result<f64> {
                        if !value.is_finite() {
                            caller.data_mut().host_error = Some(VaultError::InvalidDpInput);
                            return Err(anyhow::anyhow!("invalid gaussian value"));
                        }
                        validate_dp_charge_inputs(sigma, epsilon, delta).map_err(|err| {
                            caller.data_mut().host_error = Some(err);
                            anyhow::anyhow!("invalid dp input")
                        })?;
                        charge_dp_budget(caller.data_mut(), epsilon, delta).map_err(|err| {
                            caller.data_mut().host_error = Some(err);
                            anyhow::anyhow!("dp budget exhausted")
                        })?;
                        let noise = sample_gaussian(sigma).map_err(|err| {
                            caller.data_mut().host_error = Some(err);
                            anyhow::anyhow!("gaussian sampling failed")
                        })?;
                        let out = value + noise;
                        if !out.is_finite() {
                            caller.data_mut().host_error = Some(VaultError::InvalidDpInput);
                            return Err(anyhow::anyhow!("gaussian output invalid"));
                        }
                        caller
                            .data_mut()
                            .call_trace
                            .push(HostCallRecord::DpPrimitive {
                                mechanism: 0x11,
                                epsilon_bits: epsilon.to_bits(),
                                delta_bits: delta.to_bits(),
                                arg0_bits: value.to_bits(),
                                arg1_bits: sigma.to_bits(),
                                noise_bits: noise.to_bits(),
                                output_bits: out.to_bits(),
                            });
                        Ok(out)
                    },
                )
                .map_err(|err| VaultError::InvalidModule(err.to_string()))?;
        }

        Ok(())
    }
}

fn validate_dp_charge_inputs(
    scale_or_sigma: f64,
    epsilon: f64,
    delta: f64,
) -> Result<(), VaultError> {
    if !scale_or_sigma.is_finite()
        || !epsilon.is_finite()
        || !delta.is_finite()
        || scale_or_sigma <= 0.0
        || epsilon < 0.0
        || !(0.0..=1.0).contains(&delta)
    {
        return Err(VaultError::InvalidDpInput);
    }
    Ok(())
}

fn charge_dp_budget(host: &mut VaultHostState, epsilon: f64, delta: f64) -> Result<(), VaultError> {
    let epsilon_next = host.dp_epsilon_total + epsilon;
    let delta_next = host.dp_delta_total + delta;
    if !epsilon_next.is_finite() || !delta_next.is_finite() {
        return Err(VaultError::InvalidDpInput);
    }
    if epsilon_next > host.dp_epsilon_budget + f64::EPSILON
        || delta_next > host.dp_delta_budget + f64::EPSILON
    {
        return Err(VaultError::DpBudgetExceeded);
    }
    host.dp_epsilon_total = epsilon_next;
    host.dp_delta_total = delta_next;
    Ok(())
}

fn sample_unit_f64_open01() -> Result<f64, VaultError> {
    let mut bytes = [0_u8; 8];
    getrandom(&mut bytes).map_err(|_| VaultError::RngFailure)?;
    let raw = u64::from_be_bytes(bytes);
    let mantissa = (raw >> 11) as f64;
    let unit = mantissa / ((1_u64 << 53) as f64);
    Ok(unit.clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON))
}

fn sample_laplace(scale: f64) -> Result<f64, VaultError> {
    let u = sample_unit_f64_open01()?;
    let shifted = u - 0.5;
    let sign = if shifted < 0.0 { -1.0 } else { 1.0 };
    Ok(-scale * sign * (1.0 - 2.0 * shifted.abs()).ln())
}

fn sample_gaussian(sigma: f64) -> Result<f64, VaultError> {
    let u1 = sample_unit_f64_open01()?;
    let u2 = sample_unit_f64_open01()?;
    let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    Ok(sigma * z0)
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
            HostCallRecord::DpPrimitive {
                mechanism,
                epsilon_bits,
                delta_bits,
                arg0_bits,
                arg1_bits,
                noise_bits,
                output_bits,
            } => {
                trace.push(0x03);
                trace.push(*mechanism);
                trace.extend_from_slice(&epsilon_bits.to_be_bytes());
                trace.extend_from_slice(&delta_bits.to_be_bytes());
                trace.extend_from_slice(&arg0_bits.to_be_bytes());
                trace.extend_from_slice(&arg1_bits.to_be_bytes());
                trace.extend_from_slice(&noise_bits.to_be_bytes());
                trace.extend_from_slice(&output_bits.to_be_bytes());
            }
        }
    }

    trace.extend_from_slice(&output_hash);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&Sha256::digest(trace));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidenceos_core::nullspec_contract::{EValueSpecV1, NullSpecContractV1};

    fn test_context(dp_epsilon_budget: f64, dp_delta_budget: f64) -> VaultExecutionContext {
        VaultExecutionContext {
            holdout_labels: vec![0, 1, 0, 1],
            oracle_num_buckets: 2,
            oracle_delta_sigma: 0.0,
            null_spec: NullSpecContractV1 {
                id: "".to_string(),
                domain: "test".to_string(),
                null_accuracy: 0.5,
                e_value: EValueSpecV1::Fixed(1.0),
                created_at_unix: 0,
                version: 1,
            },
            output_schema_id: "legacy/v1".to_string(),
            dp_epsilon_budget,
            dp_delta_budget,
        }
    }

    fn test_config() -> VaultConfig {
        VaultConfig {
            max_fuel: 5_000_000,
            max_memory_bytes: 65_536,
            max_output_bytes: 16,
            max_oracle_calls: 4,
        }
    }

    #[test]
    fn dp_primitive_consumes_budget() {
        let wasm = wat::parse_str(
            r#"(module
                (import "env" "dp_laplace_i64" (func $dp_laplace_i64 (param i64 f64 f64 f64) (result i64)))
                (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\01")
                (func (export "run")
                    i64.const 7
                    f64.const 1
                    f64.const 0.2
                    f64.const 0
                    call $dp_laplace_i64
                    drop
                    i32.const 0
                    i32.const 1
                    call $emit
                    drop))"#,
        )
        .expect("wat");

        let engine = VaultEngine::new().expect("engine");
        let result = engine
            .execute(&wasm, &test_context(0.5, 0.0), test_config())
            .expect("execute");
        assert!(result.dp_epsilon_total >= 0.2);
        assert!(result.dp_delta_total.abs() < 1e-12);
    }

    #[test]
    fn dp_budget_exceeded_fails_closed() {
        let wasm = wat::parse_str(
            r#"(module
                (import "env" "dp_laplace_i64" (func $dp_laplace_i64 (param i64 f64 f64 f64) (result i64)))
                (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\01")
                (func (export "run")
                    i64.const 1
                    f64.const 1
                    f64.const 0.2
                    f64.const 0
                    call $dp_laplace_i64
                    drop
                    i64.const 1
                    f64.const 1
                    f64.const 0.2
                    f64.const 0
                    call $dp_laplace_i64
                    drop
                    i32.const 0
                    i32.const 1
                    call $emit
                    drop))"#,
        )
        .expect("wat");

        let engine = VaultEngine::new().expect("engine");
        let err = engine
            .execute(&wasm, &test_context(0.3, 0.0), test_config())
            .expect_err("budget exceed should fail");
        assert_eq!(err, VaultError::DpBudgetExceeded);
    }
}
