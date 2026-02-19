#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use evidenceos_core::error::EvidenceOSError;
use evidenceos_core::ledger::ConservationLedger;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

#[derive(Debug, Arbitrary)]
enum Op {
    ChargeAll {
        k_bits: f64,
        epsilon: f64,
        delta: f64,
        access_credit: f64,
    },
    Settle { e_value: f64 },
}

#[derive(Debug, Arbitrary)]
struct Input {
    alpha_raw: f64,
    k_budget: Option<f64>,
    access_budget: Option<f64>,
    ops: Vec<Op>,
}

fn normalize_alpha(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.5;
    }
    x.abs().fract().clamp(1e-6, 1.0 - 1e-6)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let alpha = normalize_alpha(input.alpha_raw);
    let mut ledger = ConservationLedger::new(alpha)
        .map(|l| l.with_budgets(input.k_budget, input.access_budget))
        .unwrap_or_else(|_| ConservationLedger::new(0.5).expect("fixed alpha must be valid"));

    let mut frozen = ledger.frozen;
    for op in input.ops {
        let result = match op {
            Op::ChargeAll {
                k_bits,
                epsilon,
                delta,
                access_credit,
            } => ledger.charge_all(
                k_bits,
                epsilon,
                delta,
                access_credit,
                "fuzz_charge",
                Value::Null,
            ),
            Op::Settle { e_value } => ledger.settle_e_value(e_value, "fuzz_settle", Value::Null),
        };

        if frozen {
            assert!(matches!(result, Err(EvidenceOSError::Frozen)));
        }
        if matches!(result, Err(EvidenceOSError::Frozen)) {
            frozen = true;
        }

        assert!(ledger.k_bits_total >= 0.0 || ledger.k_bits_total.is_nan());
        assert!(ledger.access_credit_spent >= 0.0 || ledger.access_credit_spent.is_nan());
        assert!(ledger.wealth.is_finite());
        assert!(ledger.wealth > 0.0 || ledger.wealth == 0.0);
    }
});
