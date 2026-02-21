# Differential Privacy (DP) Reintroduction Plan

## Current release status

DP host imports and per-claim DP budget knobs were removed from the runtime for this release.
There is no active DP execution lane, no DP syscall surface, and no claim-level DP budget wiring.

## Why DP was removed

The prior state exposed DP-related budget fields without a coherent, certifiable execution path under ASPEC policy controls. Shipping a half-implemented DP lane risks false assurance and unclear security boundaries.

## Requirements to safely reintroduce DP

A future DP-enabled release should satisfy all of the following before merge:

1. **Explicit laneing and policy binding**
   - Add a dedicated ASPEC lane for DP execution.
   - Permit DP imports only in that lane.
   - Ensure lane policy is reflected in claim metadata and audit artifacts.

2. **Strict per-call accounting**
   - Enforce bounded, validated `(epsilon, delta)` inputs.
   - Perform fail-closed budget checks for every DP primitive call.
   - Keep aggregate accounting canonical and transcript-visible.

3. **Cryptographic randomness commitments**
   - Use a CSPRNG-backed noise sampler.
   - Record non-secret commitments to DP noise generation inputs (e.g., seed commitment/hash) in capsule transcripts.
   - Avoid logging raw seeds or sensitive payloads.

4. **Certification constraints**
   - Disallow High Assurance certification for DP-lane claims by default.
   - Require explicit policy override with tests and review evidence.

5. **ABI and interoperability hardening**
   - Version guest ABI when DP imports are added.
   - Add conformance tests for allowed/forbidden import sets by lane.

6. **Test and fuzz coverage**
   - Unit tests for budget edge conditions and invalid input handling.
   - Integration tests for lane restrictions and transcript commitments.
   - Fuzz targets for DP host-call validation paths.

## Acceptance gate for future DP reintroduction

Reintroduction PRs must include:

- End-to-end tests showing runtime behavior matches docs.
- Updated implementation-status table entries from "Not implemented" to implemented/partial with citations.
- Security review notes covering nondeterminism, panic-safety, and policy boundaries.
