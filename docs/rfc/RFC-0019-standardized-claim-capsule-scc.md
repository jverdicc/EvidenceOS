# RFC-0019: Standardized Claim Capsule (SCC)

## Summary

Defines the Standardized Claim Capsule (SCC) as the portable, deterministic artifact emitted by Verified Safety Case evaluation.

## Requirements (RFC 2119)

- SCCs **MUST** be deterministically hashable using canonical JSON.
- SCCs **MUST** include decision trace hashes and transcript hashes.
- SCCs **MUST** be invalidated on schema, signature, or causal integrity failures.
- Additional properties **MUST NOT** be accepted by SCC schemas.

## SCC Contents

- Claim metadata and identifiers.
- Safety properties and adversarial hypotheses.
- Decision verdict and decision trace hash.
- Transcript hash and canonical hash.
- Optional signatures and attestations.

## Schema

- `schemas/scc/scc.schema.json`

## Non-goals

- Defining signature verification algorithms.
- Specifying storage or transport mechanisms.
