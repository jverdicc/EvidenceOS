# RFC-0013: Causal Integrity

## Summary

Causal Integrity defines a deterministic, fail-closed validation of causal graphs to guard against temporal violations, cyclic dependencies, and backdoor paths.

## Requirements

- Causal graphs **MUST** be directed acyclic graphs (DAGs).
- Nodes **MUST** have stable identifiers and **MAY** declare an integer `time_index`.
- Edges **MUST** reference existing node identifiers.
- Temporal ordering **MUST** be respected where `time_index` is provided.
- Backdoor and colliders checks **MUST** be explicit and fail-closed on invalidity.

## Schema

The canonical causal graph representation is defined in `schemas/causal/causal_graph.schema.json`.

## Non-goals

- Implementing full causal discovery or adjustment estimation.
- Defining statistical estimation algorithms.
