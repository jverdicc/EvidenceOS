use evidenceos_core::ledger::ConservationLedger;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FLOAT_TOLERANCE: f64 = 1e-12;

#[derive(Debug, Deserialize)]
struct Fixture {
    alpha: f64,
    k_bits_budget: Option<f64>,
    access_credit_budget: Option<f64>,
    transcript: Vec<TranscriptItem>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct TranscriptItem {
    #[allow(dead_code)]
    oracle_call: String,
    #[allow(dead_code)]
    oracle_output: String,
    op: Operation,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
enum Operation {
    #[serde(rename = "charge_all")]
    ChargeAll {
        k_bits: f64,
        epsilon: f64,
        delta: f64,
        access_credit: f64,
        event_kind: String,
        meta: Value,
    },
    #[serde(rename = "charge_kout_bits")]
    ChargeKoutBits { kout_bits: f64 },
    #[serde(rename = "settle_e_value")]
    SettleEValue {
        e_value: f64,
        event_kind: String,
        meta: Value,
    },
}

#[derive(Debug, Deserialize)]
struct Expected {
    k_bits_total: f64,
    alpha_prime: f64,
    certification_barrier: f64,
    frozen_transitions: Vec<bool>,
    final_frozen: bool,
}

#[derive(Debug, Deserialize)]
struct RunResult {
    k_bits_total: f64,
    alpha_prime: f64,
    certification_barrier: f64,
    frozen_transitions: Vec<bool>,
    final_frozen: bool,
}

fn apply_fixture_rust(fixture: &Fixture) -> RunResult {
    let mut ledger = ConservationLedger::new(fixture.alpha)
        .expect("valid alpha")
        .with_budgets(fixture.k_bits_budget, fixture.access_credit_budget);

    let mut frozen_transitions = Vec::with_capacity(fixture.transcript.len());
    for item in &fixture.transcript {
        match &item.op {
            Operation::ChargeAll {
                k_bits,
                epsilon,
                delta,
                access_credit,
                event_kind,
                meta,
            } => {
                let _ = ledger.charge_all(
                    *k_bits,
                    *epsilon,
                    *delta,
                    *access_credit,
                    event_kind,
                    meta.clone(),
                );
            }
            Operation::ChargeKoutBits { kout_bits } => {
                let _ = ledger.charge_kout_bits(*kout_bits);
            }
            Operation::SettleEValue {
                e_value,
                event_kind,
                meta,
            } => {
                let _ = ledger.settle_e_value(*e_value, event_kind, meta.clone());
            }
        }
        frozen_transitions.push(ledger.is_frozen());
    }

    RunResult {
        k_bits_total: ledger.k_bits_total(),
        alpha_prime: ledger.alpha_prime(),
        certification_barrier: ledger.barrier(),
        frozen_transitions,
        final_frozen: ledger.is_frozen(),
    }
}

fn run_fixture_python(fixture_path: &Path) -> RunResult {
    let kernel_dir = repository_root().join("tests/paper_conformance/paper_bundle/kernel");
    let runner = kernel_dir.join("run_reference.py");

    let output = Command::new("python3")
        .arg(runner)
        .arg(fixture_path)
        .current_dir(&kernel_dir)
        .output()
        .expect("python3 available");

    assert!(
        output.status.success(),
        "python runner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("valid python json output")
}

fn fixture_paths() -> Vec<PathBuf> {
    let dir = repository_root().join("tests/paper_conformance/fixtures");
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .expect("fixtures dir exists")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn assert_close(left: f64, right: f64, label: &str) {
    assert!(
        (left - right).abs() <= FLOAT_TOLERANCE,
        "{label} mismatch: left={left} right={right}"
    );
}

#[test]
fn paper_reference_conformance() {
    for fixture_path in fixture_paths() {
        let fixture: Fixture =
            serde_json::from_slice(&fs::read(&fixture_path).expect("fixture readable"))
                .expect("fixture parse");

        let rust_result = apply_fixture_rust(&fixture);
        let python_result = run_fixture_python(&fixture_path);

        assert_close(
            rust_result.k_bits_total,
            fixture.expected.k_bits_total,
            "rust k_bits_total vs fixture",
        );
        assert_close(
            rust_result.alpha_prime,
            fixture.expected.alpha_prime,
            "rust alpha_prime vs fixture",
        );
        assert_close(
            rust_result.certification_barrier,
            fixture.expected.certification_barrier,
            "rust certification_barrier vs fixture",
        );
        assert_eq!(
            rust_result.frozen_transitions, fixture.expected.frozen_transitions,
            "rust frozen transitions vs fixture"
        );
        assert_eq!(rust_result.final_frozen, fixture.expected.final_frozen);

        assert_close(
            rust_result.k_bits_total,
            python_result.k_bits_total,
            "rust vs python k_bits_total",
        );
        assert_close(
            rust_result.alpha_prime,
            python_result.alpha_prime,
            "rust vs python alpha_prime",
        );
        assert_close(
            rust_result.certification_barrier,
            python_result.certification_barrier,
            "rust vs python certification_barrier",
        );
        assert_eq!(
            rust_result.frozen_transitions, python_result.frozen_transitions,
            "rust vs python frozen transitions"
        );
        assert_eq!(rust_result.final_frozen, python_result.final_frozen);
    }
}
