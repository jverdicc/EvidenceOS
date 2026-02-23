// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "dp_lane")]

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Sample Laplace noise with given sensitivity and epsilon. Returns noisy i64 value.
/// Panics if epsilon <= 0.0 or sensitivity <= 0.0.
pub fn dp_laplace_i64(
    true_value: i64,
    sensitivity: f64,
    epsilon: f64,
    rng_seed: u64,
) -> (i64, f64) {
    assert!(epsilon > 0.0 && sensitivity > 0.0);
    let scale = sensitivity / epsilon;
    let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
    let u: f64 = rng.gen_range(-0.5f64..0.5f64);
    let noise = if u == 0.0 {
        0.0
    } else {
        -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
    };
    let noisy = (true_value as f64 + noise)
        .clamp(i64::MIN as f64, i64::MAX as f64)
        .round() as i64;
    (noisy, epsilon)
}

/// Sample Gaussian noise with given sensitivity, epsilon, and delta.
/// Only valid for epsilon in (0, 1), delta > 0.
pub fn dp_gaussian_i64(
    true_value: i64,
    sensitivity: f64,
    epsilon: f64,
    delta: f64,
    rng_seed: u64,
) -> (i64, f64, f64) {
    assert!(epsilon > 0.0 && epsilon < 1.0);
    assert!(delta > 0.0 && delta < 1.0);
    assert!(sensitivity > 0.0);

    let sigma = sensitivity * (2.0 * (1.25 / delta).ln()).sqrt() / epsilon;
    let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
    let u1: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0f64);
    let u2: f64 = rng.gen_range(0.0f64..1.0f64);
    let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    let noise = z0 * sigma;
    let noisy = (true_value as f64 + noise)
        .clamp(i64::MIN as f64, i64::MAX as f64)
        .round() as i64;
    (noisy, epsilon, delta)
}
