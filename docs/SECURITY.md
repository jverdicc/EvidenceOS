# Security Notes

## HMAC daemon authentication key rotation

EvidenceOS supports concurrent active HMAC keys for zero-downtime rotation.

### Configuration

- `EVIDENCEOS_HMAC_KEYS`: comma-delimited keyring in `kid:hexsecret` format.
  - Example: `EVIDENCEOS_HMAC_KEYS="default:001122,next-2026q2:aabbcc"`
- `EVIDENCEOS_HMAC_SHARED_SECRET`: legacy compatibility secret.
  - Maps to key-id `default`.
  - Use this during migration from single-key deployments.

Do not configure `default` in `EVIDENCEOS_HMAC_KEYS` while also setting `EVIDENCEOS_HMAC_SHARED_SECRET`; startup fails closed.

### Request headers

- `x-evidenceos-signature: sha256=<hex-hmac>` (required)
- `x-request-id` (required)
- `x-evidenceos-key-id` (optional; defaults to `default`)
- `x-evidenceos-timestamp` (optional; if set, skew-limited and signed)

Unknown `x-evidenceos-key-id` values are rejected with `UNAUTHENTICATED`.

### Rotation workflow

1. Add a new key to `EVIDENCEOS_HMAC_KEYS` while retaining existing active keys.
2. Roll clients to send `x-evidenceos-key-id` for the new key.
3. Validate telemetry and auth success rates.
4. Remove old key from keyring after migration completes.
