# ETL indexer for arm-stratified analytics

`evidenceos-etl-indexer` builds a deterministic SQLite index from an ETL file so analytics queries do not scan raw ETL bytes for each request.

## Build the index

```bash
cargo run -p evidenceos-etl-indexer -- \
  --etl ./data/etl.log \
  --output ./data/etl-index.sqlite
```

Behavior:
- Reads ETL sequentially and verifies each record CRC.
- Fails closed on CRC corruption, truncated records, unknown event kinds, or unknown capsule schema.
- Parses claim capsules and writes terminal-state rows (`SETTLED`, `CERTIFIED`, `REVOKED`, `TAINTED`, `STALE`, `FREEZE`) to `settlements`.
- Writes `index_manifest` with:
  - ETL file SHA-256 digest,
  - index schema version,
  - tool version.

Because the index is rebuilt from ETL alone and inserts rows in ETL order, rebuild output is deterministic for a given ETL file.

## Schema overview

### `settlements`
Columns include:
- `etl_index` (primary key)
- `capsule_hash`
- `claim_id`
- `claim_name`
- `arm_id`
- `intervention_id`
- `outcome`
- `k_bits_total`
- `ended_at`
- `topic_id`
- `holdout_ref`
- `decision`

Indexes:
- `(arm_id, outcome)`
- `(intervention_id, outcome)`
- `(claim_name)`
- `(ended_at)`

### `index_manifest`
Single row containing deterministic build metadata.

## Query examples

All FREEZE events for a trial arm:

```sql
SELECT etl_index, claim_id, intervention_id, k_bits_total
FROM settlements
WHERE arm_id = 42 AND outcome = 'FREEZE'
ORDER BY etl_index;
```

All certified outcomes for an intervention:

```sql
SELECT claim_id, arm_id, ended_at
FROM settlements
WHERE intervention_id = 'intervention-A' AND outcome = 'CERTIFIED'
ORDER BY ended_at DESC;
```

Validate build provenance:

```sql
SELECT etl_file_digest, schema_version, tool_version
FROM index_manifest;
```
