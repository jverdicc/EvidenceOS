# RFC-0012: Reality Kernel Gate Orchestration (Layer 0–2)

## Summary
This RFC introduces a single Reality Kernel orchestrator that validates evidence inputs through
three deterministic, fail-closed layers:

1. **Layer 0: PhysHIR** — dimensional checks and conservation constraints.
2. **Layer 1: Causal Integrity** — DAG validation, temporal ordering, and backdoor checks with
   optional canary invariance testing.
3. **Layer 2: e-process & Judge** — prior-aware thresholds that increase conservatism when priors
   are low.

## Goals
- Deterministic, fail-closed validation for Physical and Causal invariants.
- Schema-first inputs for PhysHIR, Causal graphs, and Reality Kernel configuration.
- Prior-aware e-value thresholds to reduce false positives under low priors.

## Non-Goals
- Runtime network calls.
- Automated DAG discovery.

## Layer 0: PhysHIR
PhysHIR inputs are validated against a JSON schema and then type-checked using deterministic unit
registries. Conservation constraints are evaluated with exact arithmetic for declared quantities.
Failures emit deterministic error codes.

## Layer 1: Causal Integrity
The causal graph must be a DAG with temporal ordering preserved (edges only forward in time). The
orchestrator checks for unadjusted confounders via backdoor criteria and, when enabled, verifies
canary invariance results.

## Layer 2: Prior-Aware e-process
Reality Kernel uses configuration priors to adjust the e-value threshold:

```
threshold = 1 / (alpha * prior)
```

Lower priors therefore require higher e-values to pass. Missing or invalid priors cause validation
failure.

## CLI
The `evidenceos reality validate` command runs all three layers and returns a non-zero exit code on
failure while printing a deterministic error code.

## Security & Determinism
All decisions are deterministic. Any schema, invariant, or integrity failure yields an explicit
error (fail-closed).
