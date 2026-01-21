# UVP interoperability

This guide describes how to integrate with EvidenceOS UVP from external pipelines. The goal is
simple, deterministic file exchange: one session directory per UVP run, with JSON payloads that
match the UVP schemas and can be produced by any language.

## Session directory format

A UVP session is a directory containing immutable syscall records plus optional artifacts.
The only required convention is that filenames are stable and sortable so a verifier can replay
in order.

```text
session/
  session.json
  syscalls/
    0001-announce.json
    0002-propose.json
    0003-evaluate.json
    0004-certify.json
  inputs/
  outputs/
```

**Required files**

- `session.json`: session metadata (session id, protocol version, creation time, optional notes).
- `syscalls/`: append-only JSON records for UVP syscalls, ordered lexicographically.

**Optional files**

- `inputs/`: raw artifacts (datasets, configs, model cards) referenced by syscall payloads.
- `outputs/`: results, certificates, or standardized claim capsules emitted by UVP.

All JSON payloads must be **canonical and deterministic**. This means:

- UTF-8 encoding
- Sorted object keys
- No NaN/Infinity
- Stable integer/float formatting

## Syscalls and JSON payloads

UVP defines four syscalls. Each is written as a JSON file inside `syscalls/`. Payloads must
validate against the UVP JSON Schemas (Draft 2020-12).

### `announce`

Declare a session and its policy envelope.

```json
{
  "syscall": "announce",
  "session_id": "<uuid>",
  "protocol_version": "uvp-1",
  "policies": ["<policy-id>"]
}
```

### `propose`

Submit a hypothesis or claim to be evaluated.

```json
{
  "syscall": "propose",
  "session_id": "<uuid>",
  "claim": "<opaque claim string>",
  "evidence_refs": ["inputs/dataset-a.json"]
}
```

### `evaluate`

Record the evaluation trace and evidence spent.

```json
{
  "syscall": "evaluate",
  "session_id": "<uuid>",
  "judge": "deterministic",
  "evidence_spent": 0.25,
  "decision_trace": "<opaque trace string>"
}
```

### `certify`

Finalize the decision and emit the Standardized Claim Capsule (SCC).

```json
{
  "syscall": "certify",
  "session_id": "<uuid>",
  "status": "certified",
  "capsule_ref": "outputs/scc.json"
}
```

## Integrate from Python

Use the UVP syscalls module directly in your pipeline:

```python
from evidenceos.uvp import syscalls

session = syscalls.Session(root_dir="./session")
session.announce(
    session_id="<uuid>",
    protocol_version="uvp-1",
    policies=["policy/rlhf-safe"],
)
session.propose(claim="<opaque claim string>", evidence_refs=["inputs/dataset-a.json"])
session.evaluate(
    judge="deterministic",
    evidence_spent=0.25,
    decision_trace="<opaque trace string>",
)
session.certify(status="certified", capsule_ref="outputs/scc.json")
```

## Integrate from other languages

1. Create a session directory following the format above.
2. Write syscall payloads as canonical JSON matching the UVP schemas.
3. Run certification to validate and package the session:

```bash
evidenceos uvp certify --session ./session
```

The CLI reads `session.json` and `syscalls/`, validates schemas, and produces the SCC in
`outputs/`.
