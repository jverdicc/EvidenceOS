# RFC-0018: Verified Safety Case

## Summary

Defines the Verified Safety Case pipeline that produces a deterministic, auditable safety verdict for a claim.

## Requirements (RFC 2119)

- Safety properties **MUST** be treated as abstract policy strings.
- Adversarial hypotheses **MUST** be recorded as opaque attack descriptions.
- The pipeline **MUST** be fail-closed on schema, signature, or invariant failures.
- Deterministic hashing, canonical JSON, and transcript ordering **MUST** be enforced.
- Reality Kernel gating (PhysHIR + CausalCheck) **MUST** run before resources are spent.
- Unit tests **MUST NOT** perform runtime network calls.

## Pipeline Stages

1. **Intake**: Validate schema and signatures.
2. **Reality Kernel Gate**: Run PhysHIR and CausalCheck before any resource spend.
3. **Evidence Wealth Ledger (EWL)**: Enforce e-value wealth and bankruptcy gating.
4. **Decision Trace**: Produce a deterministic decision trace for the verdict.
5. **Claim Capsule**: Emit a Standardized Claim Capsule (SCC).

## Schema

- `schemas/uvp/safety_property.schema.json`
- `schemas/uvp/adversarial_hypothesis.schema.json`
- `schemas/scc/scc.schema.json`

## Non-goals

- Defining concrete safety policies or adversarial content.
- Implementing cryptographic primitives.
- Implementing evidence storage backends.
