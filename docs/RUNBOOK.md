# Operator Runbook

## Scope

Operational checklist for running EvidenceOS daemon in lab/enterprise environments.

## Startup checks

1. Confirm TLS and mTLS assets are present and not world-readable.
2. Confirm signing key source configuration:
   - file mode (`EVIDENCEOS_KEY_PROVIDER=file`) with `/data/keys`
   - or KMS mode (`EVIDENCEOS_KEY_PROVIDER=kms`) with required env vars.
3. Start daemon and verify listeners:
   - gRPC port reachable
   - preflight HTTP port reachable

## Health verification

### Kubernetes

```bash
kubectl get pods
kubectl describe pod <pod-name>
```

Expect passing readiness/liveness probes.

### Docker Compose

```bash
docker compose ps
docker compose logs --tail=200 evidenceos
```

## Key management operations

### File-backed keys

- Keep key files mode `0600`.
- Rotate key by adding new `<key-id>.key` file and updating `active_key_id` in `/data/keys/active_key_id`.
- Restart daemon to apply rotation.

### KMS-backed keys

- Set:
  - `EVIDENCEOS_KEY_PROVIDER=kms`
  - `EVIDENCEOS_KMS_PROVIDER=<aws|gcp|azure|mock>`
  - `EVIDENCEOS_KMS_KEY_ID=<id>` (provider-specific)
- `mock` provider can be used for test harness validation via `EVIDENCEOS_KMS_MOCK_KEY_HEX`.

## Incident handling

### Startup failure: "signing key permissions are too broad"

1. Fix permissions:

```bash
chmod 600 /data/keys/*.key
```

2. Restart workload.

### Startup failure: KMS provider unimplemented

- Expected for `aws/gcp/azure` until organization-specific plugin implementation is provided.
- Switch to file provider for immediate recovery if policy allows.

## Security guardrails

- Do not place key material in command-line args.
- Do not copy key bytes into logs or tickets.
- Prefer Kubernetes secrets or external secret stores over plaintext files.
