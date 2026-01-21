# UVP Verified Safety Case (UVP-06)

EvidenceOS provides a deterministic, fail-closed "Verified Safety Case" runner that
processes batches of adversarial hypotheses, gates them through the Reality Kernel,
and emits a Standardized Claim Capsule (SCC). All inputs are validated against
schemas, transcripts are canonicalized, and the SCC is signed with the kernel key.

## Inputs

### Safety case configuration (`uvp_config.json`)

```json
{
  "alpha": 0.2,
  "prior": 1.0,
  "p0": 0.5,
  "p1": 0.1,
  "bankruptcy_threshold": 0.2,
  "enable_reality_kernel": false,
  "reality_kernel_dir": "reality_kernel"
}
```

* `alpha`, `prior`: e-value thresholds used to determine support.
* `p0`, `p1`: Bernoulli failure rates under null and alternative.
* `bankruptcy_threshold`: minimum e-wealth before bankruptcy.
* `enable_reality_kernel`: gate hypotheses with PhysHIR + CausalCheck.

### Hypotheses batch (`hypotheses.json`)

```json
{
  "hypotheses": [
    {
      "hypothesis_id": "h-001",
      "attack_description": "adversarial prompt attempt",
      "outcome": 0,
      "metadata": {"source": "redteam"}
    }
  ]
}
```

`outcome` is `0` for pass and `1` for fail.

## CLI

Run a batch safety case:

```bash
evidenceos uvp safety-case \
  --session-dir ./session \
  --safety-property "Policy: no unsafe output" \
  --hypotheses ./hypotheses.json \
  --kernel-private-key ./kernel.key \
  --timestamp-utc "2025-01-01T00:00:00Z"
```

The command emits the SCC as canonical JSON to stdout.
