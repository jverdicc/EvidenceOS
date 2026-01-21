# RFC-0012: PhysHIR Constraint Guards (RK-04)

## Summary

This RFC defines the PhysHIR constraint guard layer that enforces pinned primaries,
range checks, and conservation checks during runtime evaluation. The guard layer is
intentionally minimal: it validates single records or batches without running a
simulator and fails closed when constraints are violated or missing data prevents
validation.

## Motivation

EvidenceOS needs deterministic and fail-closed constraint enforcement for physics-like
invariants. The RK-04 ticket introduces:

- Pinned primaries (e.g., speed of light `c`, absolute zero) that cannot be overridden.
- Range constraints for scalar variables with units.
- Conservation checks over flow DAGs or equation sets, with tolerance.

These checks are designed to support PhysHIR and downstream Reality Kernel logic while
remaining deterministic and auditable.

## Design

### Constraint Types

Pinned primary:

```json
{"name":"c","units":"m/s","value":299792458,"locked":true}
```

Range constraint:

```json
{"var":"T","min":0,"max":null,"units":"K"}
```

Conservation constraint:

```json
{
  "kind":"mass_conservation",
  "inputs":["m_in1","m_in2"],
  "outputs":["m_out"],
  "tolerance":1e-6,
  "units":"kg"
}
```

### Determinism + Fail-Closed

- Guards use exact comparisons for pinned primaries.
- Missing variables or non-numeric values are treated as violations.
- Tolerances must be non-negative; otherwise validation fails.

### API

The guard exposes three validation functions:

- `validate_pinned_primaries(physhir, constraints)`
- `validate_ranges(data_point, constraints)`
- `validate_conservation(data_point, constraints)`

Each function accepts either a single record (mapping) or a batch (sequence of mappings)
and raises a `ConstraintViolation` with a stable error code on failure.

## Testing

Unit tests cover:

- Pinned primary mismatch.
- Temperature below absolute zero.
- Conservation sum within tolerance pass; outside tolerance failure.

## Open Questions

- Expand conservation `kind` enum beyond `mass_conservation`.
- Should pinned primaries support optional tolerance for floating-point matches?
