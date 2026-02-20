# Canary Pulse Drift Detection

Canary Pulse is a drift circuit breaker for certification safety.

## What the canary tracks

For each `(claim_name, holdout_ref)` stream, the daemon maintains a drift e-value (`e_drift`) using the active NullSpec e-process over oracle bucket observations.

State includes:

- `e_drift`: accumulated drift evidence
- `barrier = 1/alpha_drift` (from `alpha_drift_micros`)
- cadence controls: `check_every_epochs`, `max_staleness_epochs`
- `drift_frozen`: sticky freeze flag when barrier is crossed or state is stale

## Freeze trigger

Certification is fail-closed when canary drift is frozen:

- if `e_drift >= barrier`, canary is frozen
- if canary checks are stale past `max_staleness_epochs`, canary is frozen
- while frozen, claims in that stream are forced to reject/defer from certification

Each canary freeze emits incident evidence into ETL as a `canary_incident` entry for audit.

## Operations

### Status

```bash
evidenceosctl canary status --data-dir <DATA_DIR> --claim-name <CLAIM> --holdout <HOLDOUT>
```

### Reset (governed)

Reset requires a signed governance event file with:

- `event_type: "canary_reset"`
- non-empty `signature_ed25519`

```bash
evidenceosctl canary reset \
  --data-dir <DATA_DIR> \
  --claim-name <CLAIM> \
  --holdout <HOLDOUT> \
  --governance-event <SIGNED_EVENT_JSON>
```

Resets are appended to `etl_governance_events.log` for audit.
