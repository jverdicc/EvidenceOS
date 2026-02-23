#[cfg(feature = "dp_lane")]
mod dp_lane_enabled_tests {
    use evidenceos_core::aspec::{verify_aspec, AspecLane, AspecPolicy, FloatPolicy};
    use evidenceos_core::dp_lane::{dp_gaussian_i64, dp_laplace_i64};
    use evidenceos_core::ledger::ConservationLedger;

    fn sample_mean_std(xs: &[f64]) -> (f64, f64) {
        let n = xs.len() as f64;
        let mean = xs.iter().sum::<f64>() / n;
        let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n;
        (mean, var.sqrt())
    }

    #[test]
    fn test_laplace_noise_is_centered() {
        let true_value = 10_000i64;
        let sensitivity = 2.0;
        let epsilon = 0.5;
        let mut diffs = Vec::new();
        for i in 0..10_000u64 {
            let (noisy, _) = dp_laplace_i64(true_value, sensitivity, epsilon, i);
            diffs.push((noisy - true_value) as f64);
        }
        let (mean, _) = sample_mean_std(&diffs);
        assert!(mean.abs() < 0.1 * (sensitivity / epsilon));
    }

    #[test]
    fn test_laplace_noise_scale() {
        let true_value = 0i64;
        let sensitivity = 3.0;
        let epsilon = 0.8;
        let mut diffs = Vec::new();
        for i in 0..10_000u64 {
            let (noisy, _) = dp_laplace_i64(true_value, sensitivity, epsilon, i + 100_000);
            diffs.push((noisy - true_value) as f64);
        }
        let (_, sample_std) = sample_mean_std(&diffs);
        let expected_std = (sensitivity / epsilon) * 2.0_f64.sqrt();
        assert!((sample_std - expected_std).abs() < 0.1 * expected_std);
    }

    #[test]
    fn test_gaussian_noise_scale() {
        let true_value = 0i64;
        let sensitivity = 2.0;
        let epsilon = 0.5;
        let delta = 1e-5;
        let sigma = sensitivity * (2.0 * (1.25 / delta).ln()).sqrt() / epsilon;
        let mut diffs = Vec::new();
        for i in 0..10_000u64 {
            let (noisy, _, _) =
                dp_gaussian_i64(true_value, sensitivity, epsilon, delta, i + 200_000);
            diffs.push((noisy - true_value) as f64);
        }
        let (_, sample_std) = sample_mean_std(&diffs);
        assert!((sample_std - sigma).abs() < 0.1 * sigma);
    }

    #[test]
    fn test_basic_composition_accumulates() {
        let mut ledger = ConservationLedger::new(0.05)
            .expect("ledger")
            .with_dp_budgets(Some(1.0), Some(1e-5));
        assert!(ledger.charge_dp_basic(0.4, 0.0).is_ok());
        assert!(ledger.charge_dp_basic(0.4, 0.0).is_ok());
        assert!(ledger.charge_dp_basic(0.4, 0.0).is_err());
    }

    #[test]
    fn test_aspec_rejects_dp_in_pass_lane() {
        let wasm = wat::parse_str(
            "(module
                (import \"env\" \"dp_laplace_i64\" (func (param i64 f64 f64 i64) (result i64 f64)))
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"run\") nop))",
        )
        .expect("wasm");

        let pass_policy = AspecPolicy {
            lane: AspecLane::HighAssurance,
            float_policy: FloatPolicy::RejectAll,
            ..AspecPolicy::default()
        };
        let report = verify_aspec(&wasm, &pass_policy);
        assert!(!report.ok);
        assert!(report
            .reasons
            .iter()
            .any(|r| r.contains("dp syscalls require HEAVY lane")));
    }
}

#[test]
#[cfg(not(feature = "dp_lane"))]
fn test_aspec_rejects_dp_when_feature_disabled() {
    use evidenceos_core::aspec::{verify_aspec, AspecPolicy};

    let wasm = wat::parse_str(
        "(module
            (import \"env\" \"dp_laplace_i64\" (func (param i64 f64 f64 i64) (result i64 f64)))
            (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
            (func (export \"run\") nop))",
    )
    .expect("wasm");

    let report = verify_aspec(&wasm, &AspecPolicy::default());
    assert!(!report.ok);
    assert!(report
        .reasons
        .iter()
        .any(|r| r.contains("dp syscalls require dp_lane feature")));
}
