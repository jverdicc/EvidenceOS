# Deployment Guide

This guide covers production-style deployment for EvidenceOS with Docker and Kubernetes Helm, including mTLS and secure signing-key handling.

## 1) Container image build

```bash
docker build -t evidenceos:local .
```

The image is built with a multi-stage Rust build and runs on a minimal distroless runtime.

## 2) Docker Compose lab deployment (mTLS + preflight)

1. Create local directories and materials:
   - `ops/certs/server.crt`
   - `ops/certs/server.key`
   - `ops/certs/ca.crt`
   - `ops/keys/<key-id>.key` (32-byte Ed25519 seed file, mode `0600`)
2. Start the stack:

```bash
docker compose up --build
```

Default exposed ports:
- gRPC: `50051`
- HTTP preflight: `8081`
- metrics: `9464`

## 3) Helm deployment (Kubernetes)

Chart path:

```text
deploy/helm/evidenceos
```

### Install example

```bash
helm upgrade --install evidenceos deploy/helm/evidenceos \
  --set image.repository=evidenceos \
  --set image.tag=local \
  --set mtls.enabled=true \
  --set mtls.existingSecret=evidenceos-mtls \
  --set signingKeys.provider=file \
  --set signingKeys.existingSecret=evidenceos-signing-key
```

### Required secrets

- mTLS secret (if `mtls.enabled=true`) with keys:
  - `server.crt`
  - `server.key`
  - `ca.crt`
- File signing key secret with one or more key files mounted under `/data/keys`.

### Health checks

The chart configures:
- readiness probe: TCP on gRPC port.
- liveness probe: TCP on preflight HTTP port.

## 4) Signing key provider modes

`EVIDENCEOS_KEY_PROVIDER`:
- `file` (default): load keys from `/data/keys` and enforce permissions.
- `kms`: load key from KMS hook interface.

KMS hook env vars:
- `EVIDENCEOS_KMS_PROVIDER`: `mock`, `aws`, `gcp`, `azure`
- `EVIDENCEOS_KMS_KEY_ID`: required for cloud KMS providers; format `<kms-key-resource>|<base64-ciphertext>` (optional for `mock`)
- `EVIDENCEOS_KMS_MOCK_KEY_HEX`: required only for `mock` provider.

`aws/gcp/azure` providers are implemented behind feature flags (`kms-aws`, `kms-gcp`, `kms-azure`) and perform decrypt/unwrap against the configured cloud KMS.

## 5) Key permission requirements

On Unix-like systems, daemon startup enforces file-key permissions to be `0600` or stricter (no group/world bits).
If key files are broader than `0600`, startup fails closed.

## 6) Accounting store on-disk schema and crash recovery

The daemon persists account balances at `<data-dir>/accounts.json` as a JSON object:

```json
{
  "accounts": {
    "<principal-id>": {
      "credit_balance": 100,
      "daily_mint_remaining": 100,
      "last_mint_day": 20000,
      "limits": {
        "credit_limit": 100,
        "daily_mint_limit": 100
      },
      "burned_total": 0,
      "denied_total": 0
    }
  }
}
```

Writes use an atomic + durable sequence:

1. write full JSON payload to `<data-dir>/accounts.tmp`
2. `fsync` the temp file
3. `rename` temp file over `accounts.json`
4. `fsync` the containing directory (Unix)

Recovery behavior:

- A crash before rename keeps the previous `accounts.json` intact.
- A crash after rename but before process completion still leaves a complete JSON file at `accounts.json`.
- Partial JSON at `accounts.json` is not expected from daemon-managed writes with this flow.
