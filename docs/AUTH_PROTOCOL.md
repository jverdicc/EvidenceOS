# EvidenceOS Auth Protocol Contract

This document is the single source of truth for EvidenceOS HMAC request authentication.

## Required and optional headers

For HMAC-authenticated calls:

- **Required:** `x-request-id`
- **Required:** `x-evidenceos-signature`
- **Optional (recommended; required in production mode):** `x-evidenceos-timestamp`
- **Optional:** `x-evidenceos-key-id` (defaults to `default`)

Signature header format:

- `x-evidenceos-signature: sha256=<hex>`
- `<hex>` is lowercase hexadecimal HMAC-SHA256 output.

## Canonical signing material

Signing material is ASCII text with `:` separators, with no extra whitespace.

- Without timestamp: `{request_id}:{path}`
- With timestamp: `{request_id}:{path}:{timestamp}`

Where:

- `request_id` is the exact `x-request-id` value.
- `path` is the gRPC method path in the canonical form `/{service}/{method}`
  (example: `/evidenceos.v1.EvidenceOS/Health`).
- `timestamp` is the exact `x-evidenceos-timestamp` value (Unix epoch seconds string).

## Rust shared implementation

Canonical construction and verification live in:

- `crates/evidenceos-auth-protocol`

Key APIs:

- `signing_material(req_id, path, ts)`
- `verify_signature(secret, req_id, path, ts, provided_header)`

Any client or server implementation must use these APIs (or produce byte-identical behavior).

## Test vectors and drift prevention

Golden vectors are stored at:

- `crates/evidenceos-auth-protocol/tests/vectors/auth_signing_vectors.json`

All implementations should validate against these vectors to prevent client/server drift.
