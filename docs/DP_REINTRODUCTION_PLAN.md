# Differential Privacy (DP) Reintroduction Plan

## Current release status

DP mechanisms remain disabled (no guest DP syscall surface, no host Laplace/Gaussian mechanism API), but minimum-conformance DP accounting is now active:
- claims may set optional `dp_epsilon_budget` / `dp_delta_budget` at create time;
- the conservation ledger meters `epsilon_total` / `delta_total`;
- configured DP budgets are enforced fail-closed (ledger freezes on budget overrun).

## Why DP was removed

## CODEX-E07 resolution (current state)

EvidenceOS currently enforces **host-managed DP only**:

- Guest DP primitives (`dp_laplace_i64`, `dp_gaussian_i64`) are forbidden imports.
- In sealed/high-assurance operation, no guest-callable entropy-bearing DP syscall surface exists.
- Any future DP behavior must be applied by trusted host logic over validated structured outputs, with explicit audit artifacts.

This keeps the verification plane deterministic and removes hidden entropy channels from guest code.

The prior state exposed DP-related budget fields without a coherent, certifiable execution path under ASPEC policy controls. Shipping a half-implemented DP lane risks false assurance and unclear security boundaries.


## What “DP lane implemented” means for minimum paper conformance

For this phase, **DP lane implemented** means:

1. **Accounting is implemented**: each DP-relevant action must increment ledger `epsilon_total` and `delta_total`.
2. **Enforcement is implemented**: optional per-claim `ε/δ` budgets are validated and enforced fail-closed by the kernel ledger.
3. **Serialization is implemented**: ledger snapshots include configured DP budgets so auditors can verify whether enforcement was active.

It explicitly does **not** yet mean a deployed DP mechanism exists. Noise generation and mechanism APIs remain a future step.

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
