## Status
Available under feature flag `dp_lane`.
Disabled by default.

## Composition Rule
Basic composition (Kairouz et al. 2015):
- `epsilon_total = sum of all epsilon charges`
- `delta_total = sum of all delta charges`

Conservative choice. Advanced composition is a roadmap item.

## Enabling
Compile with:

```bash
cargo build --features dp_lane
```

Set in daemon config:
- `epsilon_budget: <float>`
- `delta_budget: <float>`

## Syscalls
- `dp_laplace_i64(true_value, sensitivity, epsilon, seed)`
- `dp_gaussian_i64(true_value, sensitivity, epsilon, delta, seed)`

Both are restricted to the HEAVY lane only.

## Limitations
- Basic composition is conservative; advanced composition not yet implemented
- Seed is provided by DLC for determinism; caller cannot supply entropy
- i64 clamping may introduce bias for extreme values
