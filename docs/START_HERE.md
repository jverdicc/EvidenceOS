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
4. [ETL FAQ: append-only transparency log (not blockchain)](ETL_FAQ.md)
5. Coverage maps:
   - [Mechanism-level matrix](TEST_COVERAGE_MATRIX.md)
   - [Parameter-level appendix](TEST_COVERAGE_PARAMETERS.md)

## If you’re deploying

Read in this order:
1. [Deployment security envelope (key handling, holdout/secret separation)](OPERATIONS.md)
2. [Transport/auth hardening (TLS, mTLS, auth)](OPERATIONS.md)
3. [Runbook and operational checklist](OPERATIONS.md)

## Epistemic Trial Harness (quick orientation)

- **What it is:** a black-box, clinical-trial-style evaluation harness for DiscOS/EvidenceOS claims with pre-registered units/endpoints and competing-risk analysis expectations. Start with [Epistemic trial harness](EPISTEMIC_TRIAL_HARNESS.md).
- **How to enable:** configure trial arms in [`config/trial_arms.json`](../config/trial_arms.json) and optionally override with `EVIDENCEOS_TRIAL_ARMS_CONFIG=/path/to/trial_arms.json`; the daemon loads this at startup and records `trial_config_hash_hex` for auditability. Details: [Epistemic trial harness runtime configuration](EPISTEMIC_TRIAL_HARNESS.md#8-configuring-trial-arms-runtime).
- **Where logs/evidence go:** durable trial evidence is emitted under daemon `--data-dir`, primarily `etl.log` and `etl_governance_events.log`; observe structured daemon logs during reloads/operations. Ops reference: [Operations guide](OPERATIONS.md#deployment-checklist).
- **Analysis quickstart:** run the blessed reporting flow from [Trial harness analysis](TRIAL_HARNESS_ANALYSIS.md) and use [EPISTEMIC_TRIAL_HARNESS.md](EPISTEMIC_TRIAL_HARNESS.md) to keep endpoint mapping/competing-risks interpretation consistent.

## Dual-use / production mode guardrails

- [Dual-Use and Misuse Policy](DUAL_USE_AND_MISUSE.md)
- [Operation-Level Security](OPERATION_LEVEL_SECURITY.md)
- [Deployment security envelope (OPERATIONS)](OPERATIONS.md)

## Terminology bridge

| Systems term | Alignment/security framing |
| --- | --- |
| kernel / userland | trusted boundary / untrusted agent |
| transcript | interactive eval history |
| leakage `k` | bounded info release |
