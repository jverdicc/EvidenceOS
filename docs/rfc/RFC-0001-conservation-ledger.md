# RFC-0001: Conservation Ledger

## Summary

The Conservation Ledger is a kernel primitive that meters epistemic resources.

## Requirements (RFC 2119)

- The Ledger **MUST** track:
  - Evidence budget (e.g., e-wealth or alpha spending)
  - Adaptivity budget (e.g., holdout queries, adaptive rounds)
  - Privacy budget (epsilon, delta) if DP is enabled
  - Integrity state (Trusted / Unknown / Corrupted)
- The Ledger **MUST** be monotone: spent budgets never decrease.
- The Ledger **MUST** fail closed when a limit is exceeded.

## Canonicalization

Ledger snapshots **MUST** be serializable to canonical JSON and hashable.
