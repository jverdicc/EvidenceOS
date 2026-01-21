# RFC-0015: Reality Kernel Gates

## Summary

Reality Kernel Gates define deterministic, fail-closed checks that must pass before claims are admitted: PhysHIR invariants, causal integrity, counterfactual canaries, and Bayesian prior adjustments.

## Requirements

- Gate execution **MUST** be deterministic and canonicalizable.
- Any invariant, certificate, signature, schema, or quorum failure **MUST** error or mark Invalid.
- Gate definitions **MUST** be fully specified by configuration (no implicit defaults).
- Gates **MUST NOT** rely on runtime network calls in unit tests.

## Schema

Gate configuration is defined in `schemas/reality/reality_kernel_config.schema.json`.

## Non-goals

- Implementing Judge decision logic.
- Defining external orchestration workflows.
