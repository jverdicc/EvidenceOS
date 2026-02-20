# Operations Guide

## Deployment checklist

- Enforce TLS for every gRPC listener (`--tls-cert`, `--tls-key`) and require mTLS for operator/private environments (`--mtls-client-ca`, `--require-client-cert`).
- Configure request authentication (`--auth-token` or `--auth-hmac-key`) and keep credentials out of logs.
- Set `--max-request-bytes` defensively for your workload envelope.
- Store daemon data (`--data-dir`) on durable storage with backups for:
  - `etl.log`
  - `state.json`
  - `keys/`
  - `nullspec/`
  - `oracle_operator_config.json`
  - `epoch_control.json`
  - `etl_governance_events.log`

## Key management and rotation

EvidenceOS ETL signatures and operator configuration changes are signed with Ed25519 keys.

### Daemon ETL signing keys

1. Generate a fresh 32-byte Ed25519 secret seed offline.
2. Compute key id from the public key and write `<data-dir>/keys/<key_id_hex>.key`.
3. Update `<data-dir>/keys/active_key_id`.
4. Restart daemon.
5. Verify new STH signatures via `GetSignedTreeHead` + `GetPublicKey`.

Keep historical keys available while historical artifacts may be audited.

### Operator governance signing keys

1. Provision operator key seeds in secure storage (HSM/KMS/secret manager).
2. Publish the operator public key in `<data-dir>/trusted_oracle_keys.json` as `{ "keys": { "<key_id>": "<pubkey_hex>" } }`.
3. Use `evidenceosctl` commands with `--signing-key` and `--key-id` for mutable operations.
4. Reload daemon config (SIGHUP) after changing trusted keys.

## NullSpec lifecycle

- Author and sign: `evidenceosctl nullspec create ... --signing-key ...`
- Install: `evidenceosctl nullspec install --data-dir ... --contract ...`
- Activate: `evidenceosctl nullspec activate --data-dir ... --oracle-id ... --holdout ... --nullspec-id ...`
- Inspect: `evidenceosctl nullspec list/show ...`

Each install/activate operation writes an auditable governance event to `etl_governance_events.log`.

## Calibration and TTL management

Use operator commands to update oracle runtime policy without code edits:

- `evidenceosctl oracle list --data-dir ...`
- `evidenceosctl oracle show --data-dir ... --oracle-id ...`
- `evidenceosctl oracle set-ttl --data-dir ... --oracle-id ... --ttl-epochs ... --signing-key ... --key-id ...`
- `evidenceosctl oracle rotate-calibration --data-dir ... --oracle-id ... --calib-hash ... --signing-key ... --key-id ...`
- `evidenceosctl governance events list/show ...`

Then signal daemon reload (`kill -HUP <pid>`) so updates are re-read and applied.

## Epoch settlement and safe config changes

For operator-controlled epoch progression:

- Advance epoch: `evidenceosctl epoch advance --data-dir ... --to <epoch> --signing-key ... --key-id ...`
- Reload daemon (`SIGHUP`) to apply.

Recommended safe-change order:

1. Stage signed governance change with `evidenceosctl`.
2. Verify event appears in `etl_governance_events.log`.
3. Reload daemon.
4. Observe structured `config_reload` logs and canary behavior.
5. Continue with normal claim traffic.

## Canary operations

- Query canary state:
  - `evidenceosctl canary status --data-dir ... --claim-name ... --holdout ...`
- Reset (requires signed governance event document):
  - `evidenceosctl canary reset --data-dir ... --claim-name ... --holdout ... --governance-event ...`

Perform resets only under incident workflow and preserve event artifacts.

## What’s not covered

- External IAM / SSO policy for operator access.
- Automated HSM workflows and remote attestation for key custody.
- Multi-region ETL replication and disaster-recovery runbooks.
- Governance policy approval process (human process before signatures).

## Durable storage mode and crash recovery

The daemon now enforces a durable-before-ack discipline for `ExecuteClaim`, `ExecuteClaimV2`, and `RevokeClaim`:

- ETL append/revoke is flushed with `sync_data` before the RPC can succeed.
- Claim/revocation state is persisted via atomic write+rename with file and parent-directory sync.
- A `pending_mutation.json` intent record in `<data-dir>` is used for crash recovery between ETL durability and state checkpointing.

On startup, if `pending_mutation.json` exists, the daemon replays it into in-memory state, persists `state.json`, and then removes the pending file.

Crash-test failpoints can be enabled with cargo feature `crash-test-failpoints` and env var `EVIDENCEOS_CRASH_FAILPOINT`:

- `after_etl_append_execute_claim`
- `after_etl_append_execute_claim_v2`
- `after_etl_append_revoke_claim`
