# Holdout encryption at rest

Production holdouts must be encrypted at rest and must not be loaded from plaintext labels.

## Format

Encrypted holdout files (`labels.enc`) use:

- magic: `EHLD`
- version: `1`
- algorithm: `2` (`AES-256-GCM`)
- nonce: per-file random 12-byte nonce
- ciphertext: binary labels + authentication tag

`labels_sha256_hex` in `manifest.json` remains the SHA-256 hash of **decrypted labels**.

## Key providers

`encryption_key_id` is now enforced:

- `EnvKeyProvider` resolves `EVIDENCEOS_HOLDOUT_KEY_<KEY_ID>` (uppercased, `-` converted to `_`) as 32-byte hex key material.
- KMS provider stubs exist for AWS KMS, GCP KMS, and Azure Key Vault with explicit TODO markers for envelope-key integration.

## Runtime policy

- If `encryption_key_id` is present: `labels.enc` + decryption key are required (fail closed).
- If `encryption_key_id` is absent: plaintext `labels.bin` is only allowed when daemon is started with `--allow-plaintext-holdouts`.

## Permissions

On Unix, EvidenceOS enforces:

- holdout directory permissions: `0700`
- holdout label file permissions: `0600`

On Windows, configure ACLs to provide equivalent owner-only access for holdout directories and files.

## CLI tooling

- `evidenceosctl holdout encrypt --in labels.bin --out labels.enc --key-id <id>`
- `evidenceosctl holdout decrypt --in labels.enc --out labels.bin --key-id <id>`

`holdout decrypt` is intended for trusted admin workflows only.
