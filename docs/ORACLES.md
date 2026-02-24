# Oracle Bundles (Signed WASM)

For a visual map of how the oracle subsystem fits into the sealed vault, see [`docs/ARCHITECTURE_DIAGRAMS.md`](ARCHITECTURE_DIAGRAMS.md).

External oracles are treated as **untrusted computation inside the vault**. They are constrained by interface controls, deterministic sandboxing, canonical realization encoding, and fail-closed enforcement; they are not trusted by intent.

## Bundle format

```
oracles/<oracle_id>/<version>/
  manifest.json
  oracle.wasm
  calibration_manifest.bin   # optional
  README.md                  # optional
```

## Manifest

`OracleBundleManifestV1` signs all fields except `signature_ed25519` over deterministic canonical bytes.

Key fields:
- oracle identity/version/interface pinning
- wasm sha256
- holdout handle
- OracleResolution and NullSpec pinning
- capability allowlist
- signer key id + signature

## Security controls

- Signature verification against trusted ed25519 authority IDs.
- Wasm hash pinning.
- ASPEC verification gate (PASS lane) with deterministic float policy.
- Runtime sandbox: no WASI, no host imports, bounded memory/fuel.
- ABI confinement: `memory` + `oracle_query(ptr,len)->f64` only.
- Output confinement: kernel quantizes/hysteresis/canonicalizes buckets.
- Fail closed: trap/oom/fuel/nan/inf or validation violations return `OracleViolation`.

## Bit-width semantics

- `OracleResolution.bit_width` is the minimal symbol width in bits (`ceil(log2(|Y|))`).
- `OraclePins.bit_width` records this same minimal bit-width (no byte-rounding/padding).

## Configuration

Use daemon flags:
- `--oracle-dir ./oracles`
- `--trusted-oracle-keys ./trusted_oracle_keys.json`

`trusted_oracle_keys.json`:

```json
{
  "keys": {
    "acme-root": "<ed25519_pubkey_hex>"
  }
}
```
