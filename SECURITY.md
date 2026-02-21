# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately to **security@evidenceos.org**.

Do not file public GitHub issues for unpatched vulnerabilities or suspected 0-day findings.

Include, when possible:

- affected version/commit,
- impact summary,
- reproduction details,
- logs/artifacts sanitized of secrets,
- suggested mitigation (optional).

## Disclosure process

- We acknowledge receipt and begin triage.
- We may request additional technical details to validate impact.
- We coordinate fixes and release notes before public disclosure.
- Reporter credit is offered unless anonymity is requested.

This process describes workflow only and does not guarantee specific outcomes.

## Response expectations

Typical targets (not guarantees):

- acknowledgement within 3 business days,
- initial triage update within 7 business days,
- remediation timeline set according to severity and release risk.

## Scope and priorities

Primary scope includes:

- `evidenceos-core` and `evidenceos-daemon`,
- gRPC input validation and fail-closed behavior,
- deterministic execution/canonicalization,
- conservation ledger and ETL integrity.

High-priority classes include nondeterminism affecting certification, panic paths in daemon handling, and validation gaps in network-facing surfaces.

## HMAC request authentication

When daemon auth is configured with an HMAC key, clients MUST send:

- `x-request-id`: unique request identifier (printable ASCII, max 128 chars, `:` forbidden),
- `x-evidenceos-signature`: `sha256=<hex_hmac>`, where `<hex_hmac>` is lowercase/uppercase hex of HMAC-SHA256,
- `x-evidenceos-timestamp` (optional, recommended): UNIX seconds.

### Signing input

- Without timestamp: `{request_id}:{path}`
- With timestamp: `{request_id}:{path}:{timestamp}`

`path` is the canonical gRPC path (for example `/evidenceos.v1.EvidenceOS/Health`).

### Verification behavior

The daemon fails closed and rejects requests when:

- any required header is missing or malformed,
- signature does not match the computed HMAC,
- `x-request-id` has already been seen in the replay window,
- `x-evidenceos-timestamp` is present but outside allowed clock skew (currently ±300s).

### Threat model coverage

- **Path confusion mitigation:** signatures are bound to the exact gRPC path, so signatures for one RPC cannot be replayed against another RPC.
- **Replay mitigation:** request IDs are tracked in a bounded replay cache with TTL; duplicate IDs are rejected.
- **Freshness hardening (optional):** timestamp binding plus skew enforcement limits usefulness of captured traffic.
