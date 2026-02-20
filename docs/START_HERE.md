# START HERE: Reader Paths into EvidenceOS + DiscOS

EvidenceOS is the trusted verification kernel in the Universal Verification Protocol (UVP), while DiscOS is the untrusted discovery/userland layer that proposes what to evaluate. EvidenceOS enforces a narrow boundary: only admissible claim capsules run, all oracle outputs are canonicalized, and every interaction is metered and logged. This is designed to prevent adaptive probing from silently extracting holdout information across many low-signal interactions. The protocol tracks conserved evidence budgets (`W`) and bounded leakage (`k`) so safety claims remain auditable over time, identities, and interfaces. In practice, you can read the docs below without touching Rust code first and still understand what is enforced, what is out of scope, and how to deploy safely.

## If you’re an alignment researcher

Read in this order:
1. [Threat Model by Example (blackbox walkthrough)](THREAT_MODEL_BLACKBOX.md)
2. [Paper section overview in `README` (focus on discussion of §§3/5/10)](../README.md#technical-summary)
3. [Experiments summary (`README` case study + scenario matrix)](../README.md#case-study-distillation-style-probing-public-reporting)
4. [Alignment positioning: UVP vs capability spillover](ALIGNMENT_SPILLOVER_POSITIONING.md)

## If you’re a systems/security engineer

Read in this order:
1. [Protocol versioning and wire compatibility](PROTOCOL_VERSIONING.md)
2. [Daemon API surface (gRPC lifecycle and IPC methods)](../README.md#ipc-api)
3. [Determinism + durability notes (DLC/ETL + storage/ops)](OFFLINE_SETTLEMENT.md)

## If you’re deploying

Read in this order:
1. [Deployment security envelope (key handling, holdout/secret separation)](OPERATIONS.md)
2. [Transport/auth hardening (TLS, mTLS, auth)](OPERATIONS.md)
3. [Runbook and operational checklist](OPERATIONS.md)

## Terminology bridge

| Systems term | Alignment/security framing |
| --- | --- |
| kernel / userland | trusted boundary / untrusted agent |
| transcript | interactive eval history |
| leakage `k` | bounded info release |
