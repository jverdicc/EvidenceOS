# RFC-0017: UVP Wire Protocol

## Summary

Defines the Universal Verification Protocol (UVP) wire-level syscall interface for deterministic, fail-closed verification sessions.

## Requirements (RFC 2119)

- UVP syscalls **MUST** be deterministic in serialization, hashing, and transcript ordering.
- Invalid schemas, broken signatures, or invariant violations **MUST** fail closed (error or mark Invalid).
- Syscalls **MUST** be recorded in an append-only transcript with canonical JSON hashing.
- No runtime network calls **MUST** be required in unit tests.

## Syscall Interface

UVP defines four syscall types, each with a canonical payload:

- `announce`: declare agent capabilities and supported protocol versions.
- `propose`: submit a safety case for evaluation.
- `evaluate`: return a decision trace and verdict for a proposed safety case.
- `certify`: issue a certificate and Standardized Claim Capsule (SCC) hash.

## Determinism

- Canonical JSON **MUST** be used for hashing (RFC 8785 by default).
- Hash algorithms **MUST** be explicitly declared in session metadata.
- Transcript ordering **MUST** be stable and reproducible across implementations.

## Schema

- `schemas/uvp/uvp_session.schema.json`
- `schemas/uvp/uvp_syscall.schema.json`
- `schemas/uvp/safety_property.schema.json`
- `schemas/uvp/adversarial_hypothesis.schema.json`

## Non-goals

- Defining cryptographic signature formats.
- Implementing runtime orchestration logic.
- Specifying evidence storage backends.
