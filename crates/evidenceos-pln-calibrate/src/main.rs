#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use evidenceos_core::pln::{DistributionSummary, PlnProfile, RecommendedPlnCosts};
use evidenceos_core::wasm_config::deterministic_wasmtime_config;
use std::fs;
use std::path::PathBuf;
use wasmtime::{Engine, Instance, Module, Store};

#[derive(Debug, Parser)]
#[command(name = "evidenceos-pln-calibrate")]
#[command(about = "Generate hardware-local PLN fuel profile")]
struct Args {
    #[arg(long, default_value = "./data")]
    data_dir: String,

    #[arg(long, default_value_t = 2000)]
    samples: usize,
}

fn cpu_model() -> String {
    if let Ok(text) = fs::read_to_string("/proc/cpuinfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("model name\t: ") {
                return rest.trim().to_string();
            }
        }
    }
    "unknown-cpu".to_string()
}

fn summarize(samples: &mut [u64]) -> DistributionSummary {
    samples.sort_unstable();
    let mean_fuel = (samples.iter().copied().sum::<u64>() / (samples.len() as u64)).max(1);
    let p95_idx = ((samples.len() * 95) / 100).min(samples.len().saturating_sub(1));
    let p99_idx = ((samples.len() * 99) / 100).min(samples.len().saturating_sub(1));
    DistributionSummary {
        mean_fuel,
        p95_fuel: samples[p95_idx].max(mean_fuel),
        p99_fuel: samples[p99_idx].max(samples[p95_idx].max(mean_fuel)),
    }
}

fn wasmtime_engine() -> Result<Engine, String> {
    let cfg = deterministic_wasmtime_config();
    Engine::new(&cfg).map_err(|e| format!("engine init failed: {e}"))
}

fn fuel_cost_for_wat(engine: &Engine, wat_src: &str, export: &str) -> Result<u64, String> {
    let wasm = wat::parse_str(wat_src).map_err(|e| format!("wat parse failed: {e}"))?;
    let module = Module::new(engine, &wasm).map_err(|e| format!("module create failed: {e}"))?;
    let mut store = Store::new(engine, ());
    let fuel_budget = 2_000_000;
    store
        .set_fuel(fuel_budget)
        .map_err(|e| format!("set fuel failed: {e}"))?;
    let instance =
        Instance::new(&mut store, &module, &[]).map_err(|e| format!("instantiate failed: {e}"))?;
    let f = instance
        .get_typed_func::<(), ()>(&mut store, export)
        .map_err(|e| format!("load export failed: {e}"))?;
    f.call(&mut store, ())
        .map_err(|e| format!("function call failed: {e}"))?;
    let remaining = store
        .get_fuel()
        .map_err(|e| format!("get fuel failed: {e}"))?;
    Ok(fuel_budget.saturating_sub(remaining))
}

fn fuel_cost_syscall_like(engine: &Engine) -> Result<u64, String> {
    fuel_cost_for_wat(
        engine,
        r#"(module
            (func (export \"run\")
                i32.const 0
                drop
                i32.const 1
                drop)
        )"#,
        "run",
    )
}

fn fuel_cost_wasm_instruction_block(engine: &Engine) -> Result<u64, String> {
    fuel_cost_for_wat(
        engine,
        r#"(module
            (func (export \"run\")
                (local i32)
                i32.const 0
                local.set 0
                loop
                    local.get 0
                    i32.const 1
                    i32.add
                    local.tee 0
                    i32.const 512
                    i32.lt_s
                    br_if 0
                end)
        )"#,
        "run",
    )
}

fn sample_fuel(samples: usize, op: impl Fn() -> Result<u64, String>) -> Result<Vec<u64>, String> {
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        out.push(op()?);
    }
    Ok(out)
}

fn build_profile(samples: usize) -> Result<PlnProfile, String> {
    let samples = samples.max(100);
    let engine = wasmtime_engine()?;
    let mut syscall = sample_fuel(samples, || fuel_cost_syscall_like(&engine))?;
    let mut wasm = sample_fuel(samples, || fuel_cost_wasm_instruction_block(&engine))?;
    let syscall_summary = summarize(&mut syscall);
    let wasm_summary = summarize(&mut wasm);
    let profile = PlnProfile {
        cpu_model: cpu_model(),
        syscall_fuel: syscall_summary.clone(),
        wasm_instruction_fuel: wasm_summary.clone(),
        recommended_pln_target_fuel: RecommendedPlnCosts {
            syscall_target_fuel: syscall_summary.p99_fuel,
            wasm_instruction_target_fuel: wasm_summary.p99_fuel,
        },
    };
    profile.validate().map_err(str::to_string)?;
    Ok(profile)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let data_dir = PathBuf::from(args.data_dir);
    fs::create_dir_all(&data_dir)?;
    let profile = build_profile(args.samples)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let out_path = data_dir.join("pln_profile.json");
    let payload = serde_json::to_vec_pretty(&profile)?;
    fs::write(&out_path, payload)?;
    println!("wrote {}", out_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_monotone() {
        let mut d = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let s = summarize(&mut d);
        assert!(s.mean_fuel > 0);
        assert!(s.p95_fuel >= s.mean_fuel);
        assert!(s.p99_fuel >= s.p95_fuel);
    }
}
