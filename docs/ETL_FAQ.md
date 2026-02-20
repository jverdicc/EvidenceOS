# ETL FAQ

## Is this a blockchain?
No. EvidenceOS uses an **Evidence Transparency Log (ETL)**: a CT-style, append-only Merkle transparency log. A blockchain is not required for UVP.

## What security property do we need?
The required property is **append-only transparency** with independent verifiability:
- inclusion proofs for committed entries,
- consistency proofs between tree heads over time, and
- signed tree heads (STHs) so verifiers can detect tampering or rollback claims.
