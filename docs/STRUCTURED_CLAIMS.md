# Structured Claims

Structured claims are bounded, typed JSON objects that are validated against a named schema before any capsule is produced.

## Why typed + bounded

- **Determinism:** Canonical JSON has sorted keys and stable fixed-point encodings.
- **Safety:** Unknown fields, floats, deep nesting, and oversized payloads are rejected fail-closed.
- **Auditability:** Canonical output bytes are hashed into capsule records.

## PhysHIR dimension checking

PhysHIR parses quantity strings (for example `"12.3 mmol/L"`) into fixed-point values and normalized SI units.
Validation checks the resulting 7-axis SI dimension vector `(L, M, T, I, Θ, N, J)` against the schema expectation.
Dimension mismatch causes rejection.

## Canonical CBRN-SC wire format

Canonical encoding rules:

1. Include explicit `schema_id`.
2. Sort object keys lexicographically.
3. Encode fixed-point values as `{ "value": "<i128>", "scale": <i32> }`.
4. Encode quantities as `{ "value": "<i128>", "scale": <i32>, "unit": "<normalized-unit>" }`.
5. Enforce schema byte bounds before accept.

This format is schema-driven and intentionally excludes operational guidance content.

## Magnitude envelope enforcement (CBRN profile)

EvidenceOS enforces a built-in `cbrn.v1` magnitude envelope for `cbrn-sc.v1` structured claims.
After canonicalization, PhysHIR quantity fields are checked against a signed-envelope-compatible registry model.
Current default envelope bounds `measurement` to `[-1000000, 1000000]` in normalized `mmol/L` fixed-point units.

In HEAVY/SEALED execution paths, envelope violations fail closed by forcing a deferred decision with explicit kernel reason code `9205`.
This keeps CBRN profile behavior truthful: schema validation alone is not sufficient for certification.
