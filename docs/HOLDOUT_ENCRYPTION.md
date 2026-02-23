# Holdout encryption at rest

Production holdouts must be encrypted at rest. Plaintext holdouts are for local/dev workflows only.

## Supported modes in current code

EvidenceOS currently supports these holdout-label modes:

1. **Plaintext (dev-only):**
   - File: `labels.bin`
   - Allowed only when daemon starts with plaintext opt-in (`--allow-plaintext-holdouts` / `EVIDENCEOS_ALLOW_PLAINTEXT_HOLDOUTS=1`).
   - Forbidden in production mode (`EVIDENCEOS_PRODUCTION_MODE=1`).
2. **Encrypted at rest (AES-256-GCM):**
   - File: `labels.enc`
   - Requires `manifest.json.encryption_key_id` and key-provider material to decrypt.
3. **Envelope key material via KMS providers (core library support):**
   - `encryption_key_id` format: `<kms-key-resource>|<base64-ciphertext>`.
   - Cloud KMS decrypts/unwraps ciphertext into a 32-byte DEK used for `labels.enc`.
   - Backends implemented in `evidenceos-core`: AWS KMS, GCP KMS, Azure Key Vault, plus mock clients for tests.

## Encrypted file format (`labels.enc`)

`labels.enc` uses:

- magic: `EHLD`
- version: `1`
- algorithm: `2` (`AES-256-GCM`)
- nonce: per-file random 12-byte nonce
- ciphertext: binary labels + authentication tag

`labels_sha256_hex` in `manifest.json` is the SHA-256 hash of **decrypted labels**.

## Key providers

- `EnvKeyProvider`: resolves `EVIDENCEOS_HOLDOUT_KEY_<KEY_ID>` (uppercased, `-` converted to `_`) as 32-byte hex key material.
- `AwsKmsKeyProvider`, `GcpKmsKeyProvider`, `AzureKmsKeyProvider`: decrypt envelope ciphertext (`<resource>|<ciphertext_b64>`) to obtain the 32-byte DEK.
- `Mock` clients are used in tests to validate provider behavior without cloud dependencies.

## Operator runbooks

### A) Plaintext mode (development only)

1. Prepare holdout as `labels.bin` and set `manifest.json.encryption_key_id` to `null`.
2. Start daemon with `--allow-plaintext-holdouts` (or `EVIDENCEOS_ALLOW_PLAINTEXT_HOLDOUTS=1`).
3. Confirm production mode is **off**. Production mode rejects plaintext holdouts.

### B) Env-key encrypted mode (default runtime path)

1. Generate a 32-byte key and export it as hex in `EVIDENCEOS_HOLDOUT_KEY_<KEY_ID>`.
2. Encrypt labels:
   - `evidenceosctl holdout encrypt --in labels.bin --out labels.enc --key-id <key-id>`
3. Set `manifest.json.encryption_key_id` to `<key-id>`.
4. Place `labels.enc` in the holdout directory and remove plaintext `labels.bin` from runtime paths.

### C) KMS envelope mode (core provider path)

1. Generate a DEK (32 bytes).
2. Use your KMS to encrypt/wrap that DEK and obtain ciphertext.
3. Set holdout `encryption_key_id` to `<kms-key-resource>|<base64-ciphertext>`.
4. Ensure runtime/provider wiring uses the matching KMS provider implementation and required feature flags (`kms-aws`, `kms-gcp`, `kms-azure`) where applicable.
5. Store `labels.enc` (encrypted with the DEK) in the holdout directory.

## Runtime policy

- If `encryption_key_id` is present: `labels.enc` + successful key resolution are required (fail closed).
- If `encryption_key_id` is absent: only plaintext mode can load `labels.bin`, and only with explicit plaintext opt-in.

## Permissions

On Unix, EvidenceOS enforces:

- holdout directory permissions: `0700`
- holdout label file permissions: `0600`

On Windows, configure ACLs with equivalent owner-only access.

## Code references

- `crates/evidenceos-core/src/holdout_crypto.rs`
- `crates/evidenceos-daemon/src/server/core.rs`
- `crates/evidenceos-daemon/src/main.rs`
- `crates/evidenceos-core/tests/kms_holdout_providers_integration.rs`
