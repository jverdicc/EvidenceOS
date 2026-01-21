# RFC-0014: E-Process Bayesian Infusion

## Summary

Defines how Bayesian priors influence e-values and admissibility thresholds in the Reality Kernel.

## Requirements (RFC 2119)

- Priors **MUST** be explicit, versioned, and deterministic.
- Low prior probabilities **MUST** raise the required evidence strength (more conservative thresholds).
- Priors **MUST NOT** be fetched from network sources during evaluation or tests.
- All updates **MUST** fail closed when schemas, signatures, or quorum checks fail.

## Schema

- `schemas/reality/reality_kernel_config.schema.json`

## Rationale

Explicit priors allow the Reality Kernel to calibrate evidence without sacrificing determinism.
