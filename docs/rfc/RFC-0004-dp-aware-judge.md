# RFC-0004: DP-Aware Deterministic Judge

## Summary

The Judge produces a deterministic decision from admissible evidence.

## Requirements

- The Judge **MUST** be deterministic for identical inputs.
- If integrity is Corrupted or ledger is violated, the Judge **MUST** return Invalid.
- When DP noise floor prevents a decisive conclusion, the Judge **MUST** return Inconclusive_DP_Limited.
