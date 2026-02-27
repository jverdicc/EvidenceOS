# Realtime vs Runtime Governance

This repo uses the word "real-time" in the systems sense: **deterministic, low-tail-latency settlement** of
**discrete transactions**. In LLM-agent discussions, "runtime governance" often means **continuous control of a
long-running agent loop**. These are different problems.

## What EvidenceOS means by "real-time"
EvidenceOS is designed to minimize nondeterminism and jitter in the kernel boundary. The kernel’s job is to:
- canonicalize kernel I/O,
- meter transcript capacity and adaptivity leakage,
- update the ledger deterministically,
- emit auditable receipts.

This enables **high-frequency usage** (many small settlements) without turning the governance boundary into a
high-bandwidth side channel.

## What EvidenceOS does *not* mean
EvidenceOS is not a streaming monitor that:
- sees every token the agent thinks,
- watches arbitrary internal memory updates,
- tries to “govern” every micro-step.

Attempting to stream an agent trace into the kernel would increase transcript capacity and undermine leakage bounds.

## How continuous agents are supported: event-driven settlement
For continuous agents, the intended architecture is:

**Agent loop (untrusted)** -> **Adapter/Sidecar (trusted integration boundary)** -> **EvidenceOS settlement (trusted kernel)**

The adapter chooses *events* that become capsules:
- tool calls that touch external state,
- requests that require certification,
- code/tool registration attempts,
- potentially dangerous actions (exfil, execution, persistence writes).

Each event is turned into a discrete capsule and settled.

## Why this resolves the "claim lifecycle doesn't map to agents" critique
The lifecycle is a **kernel safety property**. Continuous behavior is handled by:
- making the adapter responsible for chunking behavior into falsifiable events,
- keeping EvidenceOS deterministic + bounded,
- enforcing operation-level budgets across many events.

## Open engineering surface (explicitly acknowledged)
The adapter is a trust boundary and must be engineered and audited. EvidenceOS provides the settlement and budgeting
primitives; the adapter provides the behavioral-to-transaction translation.
