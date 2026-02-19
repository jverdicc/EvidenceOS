use evidenceos_core::oracle::{EValueFn, HoldoutBoundary, NullSpec, OracleResolution, TieBreaker};

#[test]
fn tie_breaker_matrix() {
    let mut r = OracleResolution::new(8, 0.0).expect("resolution");
    r.tie_breaker = TieBreaker::Lower;
    let l = r.quantize_unit_interval(0.5).expect("lower");
    r.tie_breaker = TieBreaker::Upper;
    let u = r.quantize_unit_interval(0.5).expect("upper");
    assert!(u >= l);
}

#[test]
fn ttl_matrix() {
    let mut r = OracleResolution::new(8, 0.0).expect("resolution");
    r.calibrated_at_epoch = 10;
    r.ttl_epochs = Some(3);
    assert!(r.ttl_expired(13));
}

#[test]
fn calibration_fields_matrix() {
    let h = [3u8; 32];
    let r = OracleResolution::new(8, 0.0)
        .expect("resolution")
        .with_calibration(h, 99);
    assert_eq!(r.calibration_manifest_hash, h);
    assert_eq!(r.calibrated_at_epoch, 99);
}

#[test]
fn codec_hash_matrix() {
    assert_eq!(
        OracleResolution::new(8, 0.0).expect("r").codec_hash,
        OracleResolution::new(16, 0.0).expect("r").codec_hash
    );
}

#[test]
fn fixed_e_value_matrix() {
    let n = NullSpec {
        domain: "d".into(),
        null_accuracy: 0.5,
        e_value_fn: EValueFn::Fixed(2.0),
    };
    assert_eq!(n.compute_e_value(0.1), 2.0);
}

#[test]
fn compute_e_value_matrix() {
    let n = NullSpec {
        domain: "d".into(),
        null_accuracy: 0.5,
        e_value_fn: EValueFn::LikelihoodRatio { n_observations: 2 },
    };
    assert!(n.compute_e_value(0.75) > 1.0);
}

#[test]
fn quantize_matrix() {
    let r = OracleResolution::new(8, 0.0).expect("r");
    assert_eq!(r.quantize_unit_interval(-1.0).expect("q"), 0);
    assert_eq!(r.quantize_unit_interval(2.0).expect("q"), 7);
}

#[test]
fn holdout_boundary_matrix() {
    let h = HoldoutBoundary::new(0.5).expect("boundary");
    assert!(h.safety_det(0.5));
}
