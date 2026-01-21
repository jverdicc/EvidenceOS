# RFC-0012: PhysHIR AST + Dimensional Typechecker

- **Status**: Draft
- **Owner**: EvidenceOS Kernel
- **Created**: 2025-01-01
- **Ticket**: RK-03

## Summary

Introduce PhysHIR, a physics-focused intermediate representation with a deterministic
AST, JSON schema validation, and a dimensional typechecker. The typechecker infers
expression dimensions, enforces dimensionless-only functions where required, and
ensures expression outputs match target dimensions.

## Motivation

Physics-driven invariants must be deterministic and fail-closed. A consistent IR and
type system ensure canonical interpretation of expressions, support auditing, and
prevent silent dimension mismatches in the Reality Kernel.

## Goals

- Define a stable PhysHIR AST with deterministic parsing.
- Provide JSON schema validation for PhysHIR payloads.
- Implement dimension inference and target validation with explicit error codes.
- Keep strict typing and unit tests.

## Non-Goals

- Full unit conversion or numeric evaluation.
- Runtime network or external registry lookups.

## Design

### PhysHIR JSON Structure

```json
{
  "target": {"name": "Y", "units": "m/s^2"},
  "variables": [{"name": "X", "units": "m/s"}],
  "expression": {"type": "Div", "lhs": {"type": "Var", "name": "X"}, "rhs": {"type": "Const", "value": 2}}
}
```

### AST Nodes

- `Var(name)`
- `Const(value, units?)` (dimensionless if units omitted)
- `Add(lhs, rhs)` / `Sub(lhs, rhs)`
- `Mul(lhs, rhs)` / `Div(lhs, rhs)`
- `Pow(base, exponent:int)`
- `Exp(arg)` / `Log(arg)` / `Sin(arg)` / `Cos(arg)` (dimensionless-only arg)
- `Clamp(arg, min, max)` (unit-preserving)

### Type System

- Units are parsed into deterministic dimension exponent tuples.
- Addition/subtraction require identical dimensions.
- Multiplication/division combine exponents.
- Power scales exponents by integer exponent.
- Exp/Log/Sin/Cos require dimensionless input and produce dimensionless output.
- Clamp preserves the input dimension.

### Failure Modes

All mismatches raise `DimensionError` with explicit codes, including:

- `E_DIMENSIONAL_INVALID` (add/sub mismatch)
- `E_DIMENSIONLESS_REQUIRED` (exp/log/sin/cos inputs)
- `E_DIMENSIONAL_TARGET_MISMATCH` (expression vs target)
- `E_VARIABLE_UNKNOWN` (missing variable)
- `E_UNITS_INVALID` (malformed unit string)

## Determinism

The parsing and type inference operate on sorted exponent tuples. All errors are
raised deterministically with fixed error codes and messages.

## Testing

Unit tests cover valid expressions, dimensional mismatches, dimensionless-only
requirements, and target mismatches.

## Alternatives Considered

- External unit libraries: rejected to preserve determinism and avoid nonstandard
  dependencies.
- Floating point unit conversion: deferred for later RFC.

## Rollout Plan

1. Introduce PhysHIR schema, AST, and typechecker.
2. Expand into conservation invariants and causal checks in subsequent tickets.

## Open Questions

- Should unit normalization eventually support implicit unit aliases (e.g., "N")?
- Should we enforce bounds ordering for Clamp (min <= max)?
