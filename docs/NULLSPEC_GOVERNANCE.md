# NullSpec governance registry

This document defines the production NullSpec governance workflow.

## Goals

- Precommit and version NullSpec contracts.
- Enforce ID-by-content and detached signatures.
- Fail closed on parse, validation, signature, and numeric errors.

## Contract schema (V1)

`NullSpecContractV1`:

- `id`: hex SHA-256 of canonical JSON bytes for the contract with `id=""`.
- `domain`: semantic domain (for example `accuracy.binary.v1`).
- `null_accuracy`: null success probability in `(0,1]`.
- `e_value`: one of:
  - `LikelihoodRatio { n_observations }`
  - `Fixed(f64)` (dev-only; rejected unless explicitly enabled)
  - `MixtureBinaryMartingale { grid: Vec<f64> }`
- `created_at_unix`: UNIX seconds.
- `version`: must be `1`.

## Canonicalization

Canonicalization uses recursive JSON key sorting across all objects. ID is always computed as:

1. Copy contract.
2. Clear `id` to empty string.
3. Canonically encode JSON.
4. Compute `SHA256` and hex-encode.

## Signatures and on-disk layout

Registry layout:

- `nullspecs/<domain>/<id>.json`
- `nullspecs/<domain>/<id>.sig`

The `.sig` file contains a hex Ed25519 signature over canonical JSON bytes.
Trusted public keys are loaded from a key directory; filename stem is the key ID and file body is 32-byte pubkey hex.

## Operator workflow

1. **Create** a contract JSON with `id` blank.
2. **Compute ID** from canonical bytes and set `id`.
3. **Sign** canonical bytes with an authorized Ed25519 key.
4. **Install** `<id>.json` and `<id>.sig` under `nullspecs/<domain>/`.
5. **Rotate** by publishing a new signed contract and switching daemon default/claim references by `id`.
6. **Deprecate** old contracts by removing mappings and eventually deleting files after retention policy.

## Daemon enforcement

- Daemon selects NullSpec by registry ID only.
- Claim capsules declaring unknown NullSpec IDs are rejected.
- Fixed e-values are denied in production unless `allow_fixed_e_value_in_dev` is enabled.

