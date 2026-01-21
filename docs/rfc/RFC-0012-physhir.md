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
