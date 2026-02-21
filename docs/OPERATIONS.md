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
- Keep NullSpec governance assets available to the daemon, either at defaults under `--data-dir`
  (`nullspec-registry/`, `trusted-nullspec-keys/`) or explicitly via
  `--nullspec-registry-dir` and `--nullspec-authority-keys-dir`.

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

- Runtime registry loading is cached in memory and periodically reloaded. If reload fails,
  claim execution fails closed until a successful reload.

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

## Generating signed oracle operator records (provenance enforced)

Use `evidenceos-operator` to produce `oracle_operator_config.json` entries with verifiable provenance.

1. Prepare inputs:
   - `calibration_manifest.json` (exact bytes are hashed into `calibration_manifest_hash_hex`).
   - `disjointness_proof.json` (exact bytes are hashed into `disjointness_attestation.proof_sha256_hex`).
2. Sign the record:

```bash
cargo run -p evidenceos-operator -- sign-oracle-record \
  --data-dir ./data \
  --oracle-id settle \
  --ttl-epochs 86400 \
  --signing-key ./ops-k1.seed \
  --key-id ops-k1 \
  --calibration-manifest-path ./calibration_manifest.json \
  --disjointness-proof-path ./disjointness_proof.json \
  --disjointness-scope "global/settle"
```

3. Reload the daemon configuration:

```bash
kill -HUP <daemon-pid>
```

In production mode (`EVIDENCEOS_PRODUCTION_MODE=1`), daemon startup/reload and oracle freeze paths enforce:
- non-empty calibration manifest hash for oracle provenance,
- structured disjointness attestation (`oracle_disjointness_v1` + scope + proof hash),
- non-expired operator record (`updated_at_epoch + ttl_epochs`),
- valid Ed25519 signature over canonical payload.

## Access-credit accounting (identity-bound)

The daemon now enforces per-principal access credit in addition to claim/topic/holdout budgets.

- Principal identity is derived from request metadata (`authorization`, `x-evidenceos-signature`, or `x-client-cert-fp`).
- Account records are persisted in `${DATA_DIR}/accounts.json` with:
  - `credit_balance`
  - `daily_mint_remaining`
  - `last_mint_day`
  - `limits`
- Credit charge for claim execution:
  - `ΔC = λk*k_bits + λcpu*fuel + λmem*max_memory_pages`
- Configuration knobs:
  - `EVIDENCEOS_LAMBDA_K_PER_BIT`
  - `EVIDENCEOS_LAMBDA_CPU_PER_FUEL`
  - `EVIDENCEOS_LAMBDA_MEM_PER_WASM_PAGE`
- Worst-case fail-closed charging if a measurement is missing:
  - `EVIDENCEOS_CREDIT_WORST_CASE_K_BITS`
  - `EVIDENCEOS_CREDIT_WORST_CASE_FUEL`
  - `EVIDENCEOS_CREDIT_WORST_CASE_PAGES`

### Admission / staking hook

The daemon uses an `AdmissionProvider` interface (`max_credit` and `admit`) to support an external stake/admission policy. The default provider is static-limit based and configured via:

- `EVIDENCEOS_DEFAULT_CREDIT_LIMIT`
- `EVIDENCEOS_PRINCIPAL_CREDIT_LIMITS` (comma-separated `principal=limit`)

### Operator RPCs

New operator-only RPCs:

- `GrantCredit(principal_id, amount, reason)`
- `SetCreditLimit(principal_id, limit)`

Operator principals are configured by `EVIDENCEOS_OPERATOR_PRINCIPALS` (comma-separated principal IDs).
