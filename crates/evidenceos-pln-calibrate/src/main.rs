#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use evidenceos_core::pln::{DistributionSummary, PlnProfile, RecommendedPlnCosts};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(name = "evidenceos-pln-calibrate")]
#[command(about = "Generate hardware-local PLN timing profile")]
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
    let mean_cycles = (samples.iter().copied().sum::<u64>() / (samples.len() as u64)).max(1);
    let p95_idx = ((samples.len() * 95) / 100).min(samples.len().saturating_sub(1));
    let p99_idx = ((samples.len() * 99) / 100).min(samples.len().saturating_sub(1));
    DistributionSummary {
        mean_cycles,
        p95_cycles: samples[p95_idx].max(mean_cycles),
        p99_cycles: samples[p99_idx].max(samples[p95_idx].max(mean_cycles)),
    }
}

fn time_syscall_cycles(samples: usize) -> Vec<u64> {
    (0..samples)
        .map(|_| {
            let start = Instant::now();
            let _ = std::thread::current().id();
            start.elapsed().as_nanos().max(1) as u64
        })
        .collect()
}

fn time_wasm_instruction_cycles(samples: usize) -> Vec<u64> {
    (0..samples)
        .map(|_| {
            let start = Instant::now();
            let mut acc = 0u64;
            for i in 0..512u64 {
                acc = acc.wrapping_add(i.rotate_left((i % 13) as u32));
            }
            std::hint::black_box(acc);
            start.elapsed().as_nanos().max(1) as u64 / 512
        })
        .collect()
}

fn build_profile(samples: usize) -> PlnProfile {
    let mut syscall = time_syscall_cycles(samples.max(100));
    let mut wasm = time_wasm_instruction_cycles(samples.max(100));
    let syscall_summary = summarize(&mut syscall);
    let wasm_summary = summarize(&mut wasm);
    let profile = PlnProfile {
        cpu_model: cpu_model(),
        syscall_cycles: syscall_summary.clone(),
        wasm_instruction_cycles: wasm_summary.clone(),
        recommended_pln_constant_cost: RecommendedPlnCosts {
            syscall_constant_cost: syscall_summary.p99_cycles,
            wasm_instruction_constant_cost: wasm_summary.p99_cycles,
        },
    };
    let _ = profile.validate();
    profile
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let data_dir = PathBuf::from(args.data_dir);
    fs::create_dir_all(&data_dir)?;
    let profile = build_profile(args.samples);
    profile
        .validate()
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
        assert!(s.mean_cycles > 0);
        assert!(s.p95_cycles >= s.mean_cycles);
        assert!(s.p99_cycles >= s.p95_cycles);
    }
}
