use evidenceos_core::oracle::{EValueFn, NullSpec, OracleResolution, TieBreaker};

#[test]
fn oracle_public_api_matrix() {
    let mut res = OracleResolution::new(300, 0.0).expect("resolution");
    res.tie_breaker = TieBreaker::Lower;
    let lower = res.quantize_unit_interval(0.5).expect("q");
    res.tie_breaker = TieBreaker::Upper;
    let upper = res.quantize_unit_interval(0.5).expect("q");
    res.tie_breaker = TieBreaker::NearestEven;
    let even = res.quantize_unit_interval(0.5).expect("q");
    assert!(lower <= upper);
    assert!(even <= upper);

    let bucket = 257;
    let encoded = res.encode_bucket(bucket).expect("encode");
    let decoded = res.decode_bucket(&encoded).expect("decode");
    assert_eq!(decoded, bucket);
    assert_eq!(
        res.validate_canonical_bytes(&encoded).expect("canonical"),
        bucket
    );

    res.calibrated_at_epoch = 9;
    res.ttl_epochs = None;
    assert!(!res.ttl_expired(10));
    res.ttl_epochs = Some(0);
    assert!(res.ttl_expired(9));
    res.ttl_epochs = Some(1);
    assert!(!res.ttl_expired(9));
    assert!(res.ttl_expired(10));

    let fixed = NullSpec {
        domain: "unit".into(),
        null_accuracy: 0.5,
        e_value_fn: EValueFn::Fixed(2.25),
    };
    assert_eq!(fixed.compute_e_value(0.01), 2.25);
}
