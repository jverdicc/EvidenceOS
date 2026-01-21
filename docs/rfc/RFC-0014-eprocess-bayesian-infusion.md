# RFC-0014: e-Process Bayesian Infusion

## Summary

This RFC introduces Bayesian priors that modulate e-value thresholds, making decisions more conservative when priors are low while preserving determinism.

## Requirements

- Prior inputs **MUST** be declared in configuration and logged.
- Threshold adjustments **MUST** be deterministic and canonicalizable.
- Low priors **MUST** result in more conservative acceptance thresholds.
- Missing or invalid priors **MUST** fail-closed.

## Schema

Reality Kernel configuration for priors is defined in `schemas/reality/reality_kernel_config.schema.json`.

## Non-goals

- Implementing probabilistic programming engines.
- Defining priors for all domains.
