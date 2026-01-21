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
