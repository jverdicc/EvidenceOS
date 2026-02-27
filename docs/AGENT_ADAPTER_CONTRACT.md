# Agent Adapter Contract (DiscOS/OpenClaw sidecar)

This document defines the **minimum contract** for any adapter that bridges a continuous agent loop to EvidenceOS.

## Why this exists
EvidenceOS enforces security via a discrete capsule lifecycle and ledger updates. A continuous agent does not
naturally produce capsules. The adapter is therefore a *first-class trust boundary*.

## Adapter responsibilities

### A. Event selection (what becomes a capsule)
At minimum, capsule submission should be triggered by:
- tool calls that query holdouts/oracles,
- tool calls that request certification/verdicts,
- any attempt to register or mutate executable tools,
- any write/persist action that would make behavior durable (memory/tooling persistence),
- any action routed to higher assurance lanes (CANARY/HEAVY).

### B. State snapping (what must be included vs excluded)
**Include (required):**
- the falsifiable artifact (code/model hash/config/inputs),
- declared interfaces/tools used,
- operation/topic identifiers for shared budgeting,
- requested oracle resolutions / output alphabets.

**Exclude (strongly recommended):**
- chain-of-thought / scratchpad,
- raw holdout internals,
- unconstrained free-form agent transcripts not needed to falsify the claim.

Rationale: avoid turning the adapter->kernel boundary into a high-bandwidth channel.

### C. Admissibility gate for agent-created tools
If the agent can create/edit tools, the adapter MUST gate tool registration:
- run the candidate tool through the admissibility profile (ASPEC/Wasm verifier),
- deny ambient capabilities, unbounded computation, nondeterminism,
- record the decision in the audit trail.

### D. Operation-level budgeting continuity
The adapter MUST maintain continuity across the whole run:
- stable TopicHash / MultiSignalTopicID mapping for a single operational objective,
- no “budget reset” per prompt/session,
- include lineage context (parent claim, descendants) when available.

### E. Receipt reinjection
The adapter MUST re-inject only:
- signed, canonical receipts,
- quantized oracle symbols,
- lane decisions and throttling signals.

It must not synthesize additional "soft" feedback from holdout behavior.

## Recommended interface to agents (single tool)
Expose a single high-level tool to the agent such as:
`submit_for_settlement(artifact, intent, topic_id, policy_profile) -> receipt`
and hide the lifecycle details.

## Non-goals
The adapter is not meant to perfectly interpret agent intent; it is meant to:
- preserve kernel security properties,
- reduce bandwidth,
- make settlement easy to call as a “tool” from continuous loops.
