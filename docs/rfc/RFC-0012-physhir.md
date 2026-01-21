# RFC-0012: PhysHIR (Physical Higher-Integrity Records)

## Summary

PhysHIR defines a deterministic, unit-aware schema for physical claims and invariants that the Reality Kernel can validate.

## Requirements (RFC 2119)

- PhysHIR data **MUST** be canonicalizable and hashable without ambiguity.
- Every HIR variable **MUST** include a `units` field expressed as an SI base vector or normalized unit token.
- PhysHIR validations **MUST** fail closed when any invariant, certificate, or schema check fails.
- Implementations **MUST NOT** make network calls during unit tests.

## Schema

- `schemas/physics/physhir.schema.json`
- `schemas/physics/unit_registry.schema.json`
- `schemas/physics/constraints.schema.json`

## Rationale

Physical quantities and conservation constraints provide deterministic, machine-verifiable grounding for evidence.
