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
# RFC-0012: PhysHIR (Physical HIR)

## Summary

PhysHIR defines a dimensional and conservation-aware representation for physical claims so that the Reality Kernel can deterministically validate units, invariants, and constraints.

## Requirements

- PhysHIR objects **MUST** be canonicalizable and deterministic for hashing and Judge decisions.
- Every PhysHIR variable **MUST** declare `units` as either an SI base-vector or normalized unit tokens.
- Conservation constraints **MUST** be explicit and verifiable; failures **MUST** be fail-closed (error or Invalid).
- Constraint evaluation **MUST NOT** rely on runtime network calls.

## Schema

PhysHIR data is described by `schemas/physics/physhir.schema.json`, with supporting registries in:

- `schemas/physics/unit_registry.schema.json`
- `schemas/physics/constraints.schema.json`

## Non-goals

- Implementing numerical solvers or automatic unit conversion.
- Defining inference policies for non-physical domains.
