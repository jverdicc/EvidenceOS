# RFC-0011: Federated Evidence

## Summary

Federated Evidence evaluates a claim across multiple sovereign vaults.

## Requirements

- Each vault **MUST** enforce its own local ledger and oracle policy.
- Vault responses **MUST** be signed and hash-verified by the coordinator.
- A merger **MUST** combine local evidence into a GlobalLedger using an explicit MergerPolicy.
- Quorum rules **MUST** be enforced; fail-closed is the default.

## Default merge rules (v1)

- e-values: weighted arithmetic mean
- product merge: allowed only if independence is certified
- DP budgets: max if identity-disjoint certified else sum
- integrity: any Corrupted => Corrupted (fail closed)
