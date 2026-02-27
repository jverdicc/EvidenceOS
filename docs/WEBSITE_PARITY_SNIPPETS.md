# Website parity snippets

## Scope & terminology (read this if you're thinking "runtime governance")

EvidenceOS is a **deterministic settlement kernel** for **discrete claim capsules** under adaptive interaction.
It enforces a one-way-door lifecycle (`CreateClaim -> Freeze -> Seal -> Execute`) and meters oracle outputs
so adaptivity leakage is budgeted rather than ignored.

**Terminology note:** when this project says **“real-time”** it means **deterministic, low-tail-latency, high-frequency
transaction processing of capsules** (matching-engine style). It does **not** mean EvidenceOS ingests or governs a
continuous, streaming agent behavior trace.

**Continuous agent governance** is supported via an **adapter/sidecar** (in DiscOS/OpenClaw) that:
1) watches for high-stakes agent actions/tool calls,
2) snapshots only the falsifiable artifact(s),
3) compiles them into an admissible capsule,
4) submits to EvidenceOS for settlement,
5) reinjects the signed receipt back into the agent loop.

This is the **adapter/sidecar for continuous agents** integration pattern.

## What EvidenceOS does today
- Deterministically settles discrete claim capsules with auditable receipts and ETL commitments.
- Enforces `CreateClaim -> Freeze -> Seal -> Execute` and metered oracle-output leakage budgets.
- Supports continuous agents through an adapter/sidecar that converts high-stakes runtime events into capsules.

## Roadmap
- Expand adapter reference implementations and conformance tests for continuous-agent integrations.
- Add ergonomic submission affordances that preserve identical settlement semantics and ledger effects.
- Maintain strict website/docs parity so external messaging tracks shipped kernel behavior.
