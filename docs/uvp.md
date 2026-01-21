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
# UVP Sessions and Verified Safety Case (SCC)

EvidenceOS implements UVP (Universal Verification Protocol) syscalls as a deterministic local
state machine backed by a session directory. The session folder stores canonical JSON artifacts
for announce/propose/evaluate/certify and produces a Standardized Claim Capsule (SCC).

## Session layout

```
.uvp/<session_id>/
  announce.json
  propose.json
  evaluations.jsonl
  ewl_state.json
  reality_gate_report.json
  scc.json
```

All JSON is written in canonical form to preserve determinism for hashing, transcript semantics,
and decision traces.

## Syscalls

- `uvp_announce(session_dir, pds_manifest)`
  - Writes `announce.json` and initializes `ewl_state.json` from the EWL policy.
- `uvp_propose(session_dir, causal_dag, physhir, payload_hashes)`
  - Writes `propose.json` with the causal graph, PhysHIR payload, and payload hashes.
- `uvp_evaluate(session_dir, hypothesis, outcome_x, meta)`
  - Appends a record to `evaluations.jsonl` and updates `ewl_state.json`.
  - Runs Reality Kernel gating (PhysHIR, causal DAG, and optional canary invariance) before
    spending evidence wealth.
- `uvp_certify(session_dir, kernel_keypair, timestamp_utc)`
  - Builds the SCC, hashes the payload, signs it, and writes `scc.json`.

## Schemas

UVP schemas live in `schemas/uvp/`:

- `announce.schema.json`
- `propose.schema.json`
- `evaluation.schema.json`
- `ewl_state.schema.json`
- `reality_gate_report.schema.json`
- `scc.schema.json`
- `physhir.schema.json`
- `causal_dag.schema.json`

These schemas are used for fail-closed validation of session artifacts.

## CLI

The CLI mirrors the syscall interface:

```
# Initialize a session
$ evidenceos uvp init .uvp/session-1

# Announce
$ evidenceos uvp announce .uvp/session-1 --manifest pds_manifest.json

# Propose
$ evidenceos uvp propose .uvp/session-1 --causal causal.json --physhir physhir.json \
    --payload-hashes payload_hashes.json

# Evaluate
$ evidenceos uvp evaluate .uvp/session-1 "hypothesis" 1 --meta '{"note":"pass"}'

# Certify
$ evidenceos uvp certify .uvp/session-1 \
    --kernel-private-key-hex <hex> \
    --timestamp-utc "2024-01-01T00:00:00Z"
```
# Universal Verification Protocol (UVP)

This document describes the UVP syscall interface and how EvidenceOS builds a Verified Safety Case
into a Standardized Claim Capsule (SCC).

## UVP Syscalls

UVP defines four deterministic syscalls that append to a canonical transcript:

1. **announce** — declare the claim, safety properties, and adversarial hypotheses.
2. **propose** — provide evidence items and requested resources.
3. **evaluate** — apply Reality Kernel gating and evidence wealth updates before spending resources.
4. **certify** — record the decision trace and finalize the capsule.

Each syscall payload is hashed using canonical JSON, and the transcript preserves strict sequence
ordering to ensure deterministic replay.

## Verified Safety Case Pipeline

The Verified Safety Case pipeline:

1. Validates Reality Kernel inputs (PhysHIR + CausalCheck) before spending any resources.
2. Updates the Evidence Wealth Ledger (EWL) with the supplied e-value and enforces bankruptcy
   gating.
3. Produces a decision trace using the EvidenceOS Judge.
4. Emits a Standardized Claim Capsule (SCC) containing the claim, safety case inputs, Reality
   Kernel payloads, UVP transcript, EWL snapshot, and decision trace.

## SCC Contents

An SCC directory contains deterministic JSON artifacts:

- `claim.json`
- `safety_case.json`
- `reality_kernel.json`
- `uvp_transcript.json`
- `ewl.json`
- `decision_trace.json`
- `manifest.json`
- `capsule_root.txt`

All files are canonicalized for hashing, and the manifest hash is recorded in `capsule_root.txt`.
