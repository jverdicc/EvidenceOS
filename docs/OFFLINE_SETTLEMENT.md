# Offline settlement scaffold (air-gapped mode)

## Ingest mode (daemon)

Run daemon with:

```bash
evidenceos-daemon --offline-settlement-ingest --data-dir ./data
```

In this mode, execute paths write unsigned settlement proposals to:

- `data-dir/settlement_spool/<epoch>/<claim_id>.json`

No ETL append is performed during ingest mode.

## Offline signing tool

```bash
cargo run -p evidenceos-settle-offline -- \
  --spool-dir ./data/settlement_spool \
  --out-dir ./signed-settlements \
  --signer-key-hex <32-byte-ed25519-secret-hex>
```

The tool validates proposal integrity, signs canonical proposal payloads, and writes signed settlement records.

## Import signed settlements

```bash
evidenceos-daemon \
  --data-dir ./data \
  --import-signed-settlements-dir ./signed-settlements \
  --offline-settlement-verify-key-hex <32-byte-ed25519-public-hex>
```

Import is apply-only: daemon verifies signatures and appends settled capsule bytes to ETL.
