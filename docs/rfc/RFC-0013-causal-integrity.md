# RFC-0013: Causal Integrity

## Summary

Causal Integrity defines deterministic checks for causal graphs, temporal ordering, and backdoor paths.

## Requirements (RFC 2119)

- Causal graphs **MUST** be represented as a DAG with deterministic node ordering.
- Nodes **MUST** include stable identifiers and **MAY** include integer `time_index` values.
- Edges **MUST** reference existing node identifiers and be validated before inference.
- Validation **MUST** fail closed when structural, temporal, or backdoor checks fail.

## Schema

- `schemas/causal/causal_graph.schema.json`

## Rationale

Causal graphs act as admissibility constraints for evidence aggregation and counterfactual analysis.
