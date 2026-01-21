# RFC-0015: Reality Kernel Gates

## Summary

Defines the gating pipeline for EvidenceOS Reality Kernel validation and admissibility.

## Requirements (RFC 2119)

- Gates **MUST** be applied in a deterministic order.
- Any failed gate **MUST** mark the claim as Invalid or return an error.
- Gates **MUST** include PhysHIR validation, causal integrity checks, and Bayesian prior calibration.
- Unit tests **MUST NOT** perform runtime network calls.

## Schema

- `schemas/reality/reality_kernel_config.schema.json`

## Rationale

A unified gating pipeline ensures consistent fail-closed behavior across evidence types.
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
