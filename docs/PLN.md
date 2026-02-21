# PLN calibration harness

`evidenceos-pln-calibrate` runs a deterministic local microbenchmark and writes:

- `data-dir/pln_profile.json`

## Run

```bash
cargo run -p evidenceos-pln-calibrate -- --data-dir ./data --samples 2000
```

Daemon loading:

- `evidenceos-daemon` now attempts to load and validate `data-dir/pln_profile.json` at startup.
- Invalid profiles fail startup.

## What it measures

- syscall-adjacent fuel sample distribution
- wasm-instruction-adjacent fuel sample distribution
- derived recommended `pln_target_fuel` values from p99 fuel usage

## Production profile

For paper-parity and threat-model scope, see [`PLN_PRODUCTION_PROFILE.md`](PLN_PRODUCTION_PROFILE.md).

## Limitations

- This is **not** cycle-accurate hardware padding.
- These measurements are hardware/firmware/kernel dependent.
- Profiles are **not portable** across hardware classes.
- Calibrate per deployment class (CPU model, microcode, kernel baseline).
- CI must not assert exact timing values; only profile parsing/validation is tested.
