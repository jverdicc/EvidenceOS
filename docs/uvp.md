# Universal Verification Protocol (UVP)

This document describes the UVP syscall interface and how EvidenceOS builds a Verified Safety Case
into a Standardized Claim Capsule (SCC).

## UVP Syscalls

UVP defines four deterministic syscalls that append to a canonical transcript:

1. **announce** — declare the claim, safety properties, and adversarial hypotheses.
2. **propose** — provide evidence items and requested resources.
3. **evaluate** — apply Reality Kernel gating and evidence wealth updates before spending resources.
4. **certify** — record the decision trace and finalize the capsule.

Each syscall payload is hashed using canonical JSON, and the transcript preserves strict sequence
ordering to ensure deterministic replay.

## Verified Safety Case Pipeline

The Verified Safety Case pipeline:

1. Validates Reality Kernel inputs (PhysHIR + CausalCheck) before spending any resources.
2. Updates the Evidence Wealth Ledger (EWL) with the supplied e-value and enforces bankruptcy
   gating.
3. Produces a decision trace using the EvidenceOS Judge.
4. Emits a Standardized Claim Capsule (SCC) containing the claim, safety case inputs, Reality
   Kernel payloads, UVP transcript, EWL snapshot, and decision trace.

## SCC Contents

An SCC directory contains deterministic JSON artifacts:

- `claim.json`
- `safety_case.json`
- `reality_kernel.json`
- `uvp_transcript.json`
- `ewl.json`
- `decision_trace.json`
- `manifest.json`
- `capsule_root.txt`

All files are canonicalized for hashing, and the manifest hash is recorded in `capsule_root.txt`.
