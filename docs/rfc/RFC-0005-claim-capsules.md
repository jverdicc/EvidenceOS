# RFC-0005: Claim Capsules

## Summary

A Claim Capsule is a proof-carrying artifact that can be verified offline.

## Requirements

- Capsules **MUST** include canonical JSON files for the contract, transcript, ledger summary, and decision trace.
- Capsules **MUST** include a manifest listing file hashes.
- Verification **MUST** fail if any file hash does not match the manifest.
