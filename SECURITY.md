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
