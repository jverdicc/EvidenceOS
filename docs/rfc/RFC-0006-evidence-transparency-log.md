# RFC-0006: Evidence Transparency Log (ETL)

## Summary

An append-only Merkle log that anchors Supported+ claims.

## Requirements

- The ETL **MUST** be append-only.
- The ETL **MUST** provide Signed Tree Heads (STH) and inclusion proofs.
- Clients **MUST** be able to verify inclusion without trusting the log operator.
