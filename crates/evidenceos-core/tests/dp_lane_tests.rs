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
    fn test_laplace_noise_golden_for_fixed_seeds() {
        let samples: Vec<i64> = (0..16)
            .map(|seed| dp_laplace_i64(42, 2.0, 0.5, seed).0)
            .collect();
        let expected: Vec<i64> = vec![
            44, 41, 48, 43, 44, 38, 41, 37, 34, 36, 43, 41, 18, 40, 44, 46,
        ];
        assert_eq!(samples, expected);
    }

    #[test]
    fn test_gaussian_noise_golden_for_fixed_seeds() {
        let samples: Vec<i64> = (0..16)
            .map(|seed| dp_gaussian_i64(42, 2.0, 0.5, 1e-5_f64, seed).0)
            .collect();
        let expected: Vec<i64> = vec![
            26, 65, 33, 58, 56, 34, 17, 60, 39, 50, 63, 65, 53, 67, 29, 53,
        ];
        assert_eq!(samples, expected);
    }

    #[test]
    fn test_laplace_noise_centered_sanity() {
        let true_value = 10_000i64;
        let sensitivity = 2.0_f64;
        let epsilon = 0.5_f64;
        let diffs: Vec<f64> = (0..512u64)
            .map(|seed| {
                (dp_laplace_i64(true_value, sensitivity, epsilon, seed).0 - true_value) as f64
            })
            .collect();
        let (mean, sample_std) = sample_mean_std(&diffs);
        let expected_std = (sensitivity / epsilon) * 2.0_f64.sqrt();
        assert!(mean.abs() < 0.2 * (sensitivity / epsilon));
        assert!((sample_std - expected_std).abs() < 0.35 * expected_std);
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
