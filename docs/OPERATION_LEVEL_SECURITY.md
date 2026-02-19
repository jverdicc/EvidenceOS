# Operation-Level Security (Swarms)

EvidenceOS applies the Universal Verification Protocol (UVP) to a practical problem that appears in multi-agent systems: attacks are often distributed over an **operation**, not concentrated in one prompt, one model invocation, or one account. In that environment, local request-level checks can pass while the aggregate interaction still produces unacceptable leakage. UVP addresses this by making operation-level accounting explicit and enforceable in the kernel, so security decisions can compose across time, identities, and channels (Paper: §2 Threat Model; Paper: §14 Cross-Claim Budgeting).

## Why operation-level accounting is required

Swarm orchestrators naturally parallelize work: different workers call different tools, at different times, with partially overlapping context. If controls only evaluate each request in isolation, attackers can split probing into many low-intensity interactions that each stay below local thresholds. Over time, that sequence can still recover holdout structure or validation boundary information (Paper: §3 Adaptive Leakage).

Identity-local controls are also weak against rotation. If each account receives an independent quota, an adversary can re-enter with new identities and continue the same campaign. UVP assumes this pressure and charges activity to topic-level operational objects (`TopicHash` / `MultiSignalTopicID`) so risk accounting follows the objective rather than the username (Paper: §11 Topic Coupling; Paper: §12 Multi-Identity Adaptation).

Finally, operation-level attacks often rely on **cross-channel** extraction (for example, comparing behavior across tools or verification surfaces). UVP’s joint ledger accounting is designed so these channels do not provide additive leakage beyond configured budgets when they are tied to the same operation (Paper: §14 Cross-Claim Budgeting).

## Core model in EvidenceOS

In EvidenceOS, an operation is represented by multiple linked kernel primitives:

- **Topic identity (`TopicHash` / `MultiSignalTopicID`)** to aggregate related claims and tool actions under shared budgets.
- **Lineage DAG** to preserve parent/child claim relationships and enforce recursive consequences.
- **Tool/action context** so accounting reflects not only *who* sent a request, but *what kind* of interaction was used.
- **DLC epochs** so settlement and timing-sensitive behavior occur in deterministic windows.
- **ETL commitments** so all meaningful state transitions are auditable and replay-verifiable.

These primitives support a simple rule: if behavior is part of the same operation, it spends from the same conserved budget regardless of how requests are split. This is the key reason UVP can remain defensive under swarm decomposition (Paper: §6 Kernel Invariants; Paper: §9 Transparency Log).

## Lane routing as graded intervention

UVP lane routing is the enforcement mechanism that turns operation telemetry into action. EvidenceOS uses PASS/CANARY/HEAVY/REJECT/FROZEN as a progressive control stack rather than a binary allow/deny system (Paper: §10 Lanes and Interventions).

- **PASS**: Normal low-risk flow with standard metering and logging.
- **CANARY**: Additional checks and tighter response shaping to test for instability.
- **HEAVY**: Higher-friction verification, stronger throttles, delayed settlement.
- **REJECT**: Request or claim denied when policy invariants fail.
- **FROZEN**: Containment state for branches or descendants that inherit taint/revocation risk.

Safe example language: a swarm may send many benign-looking requests that, in sequence, look like temporal staircase probing. Instead of returning increasingly informative outputs, lane policy can escalate from PASS to CANARY/HEAVY, reduce bandwidth, and freeze affected descendants when revocation triggers are met. This is a defensive control narrative, not an offensive recipe.

## End-to-end flow (ASCII)

```text
+---------------------------+
| DiscOS clients / workers  |
| (untrusted swarm userland)|
+-------------+-------------+
              |
              | validated gRPC calls
              v
+---------------------------+
| EvidenceOS daemon/kernel  |
| - topic+lineage budgets   |
| - lane routing            |
| - deterministic epochs    |
+-------------+-------------+
              |
              | append + commitments
              v
+---------------------------+
| Ledger + ETL Merkle log   |
| - joint accounting state  |
| - signed tree heads       |
| - revocation propagation  |
+-------------+-------------+
              |
              | exported heads/events
              v
+---------------------------+
| External exports          |
| SIEM / governance / audit |
+---------------------------+
```

## What UVP does NOT cover

UVP is a kernel-level verification and accounting framework. It does **not** replace organizational controls outside verifier I/O boundaries.

- **Human support processes**: helpdesk workflows, escalation playbooks, and analyst approvals remain enterprise responsibilities.
- **External channels outside verifier I/O**: side conversations, unmanaged messaging systems, and non-integrated data movement are out of scope unless explicitly bridged into the verifier boundary.
- **Endpoint and infrastructure compromise**: host hardening, key custody, and hardware side-channel defenses are required separately.

This boundary is important: operation-level accounting is strong only where activity is observable and metered by the kernel (Paper: §2 Threat Model).

## How to integrate with enterprise telemetry

1. **Export ETL heads and proof material** on a regular cadence so downstream systems can verify append-only consistency and detect rollback/fork conditions.
2. **Export lane events** (PASS/CANARY/HEAVY/REJECT/FROZEN transitions) with operation identifiers (`TopicHash`/`MultiSignalTopicID`) and lineage references.
3. **Export budget signals** (evidence spend, throttling triggers, revocation/taint markers) for policy analytics and case management.
4. **Correlate in SIEM** with identity, endpoint, and network telemetry. The key analytic is many-to-one: many principals or tools converging on one operation key.
5. **Drive response orchestration** so SIEM detections can enforce policy updates (for example, stricter lane defaults, temporary freezes, or mandatory heavy verification).

Maintain dashboards around operation keys rather than user IDs to align monitoring with UVP accounting and improve detection of distributed probing that evades per-agent heuristics.

## Mapping reference

Use the README table (“Operation signals → UVP enforcement surface”) as the compact control-plane mapping, and treat this document as implementation guidance for defensive operation-level governance.
