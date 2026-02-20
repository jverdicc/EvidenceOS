# Threat Model by Example (Blackbox Walkthrough)

This guide is an outsider-friendly explanation of the Universal Verification Protocol (UVP) as implemented by EvidenceOS. It treats EvidenceOS as a **blackbox service** with a narrow interface and focuses on defensive behavior, not offensive techniques.

## A) What problem UVP solves (one paragraph)

UVP addresses a core failure mode in AI/system evaluation: even when each individual response looks harmless, repeated adaptive interaction can gradually leak hidden evaluation data (holdouts, boundaries, or policy internals). EvidenceOS is designed to make that leakage **measurable, budgeted, auditable, and stoppable** by forcing interactions through metered interfaces, coarse responses, and deterministic settlement rules that fail closed when risk budgets are exhausted.

## B) Entities and trust boundaries

- **DiscOS (untrusted userland):** proposes claims/capsules and asks for verification.
- **EvidenceOS (trusted kernel):** validates admissibility, meters oracle responses, updates conservation budgets, and records receipts.
- **Holdout/evaluation assets (sensitive):** never exposed directly; only mediated through EvidenceOS outputs.
- **Auditors/operators (external):** inspect signed receipts/log heads and policy events.

```text
[DiscOS / callers] --(narrow API requests)--> [EvidenceOS kernel] --(controlled access)--> [holdout/oracles]
                                      \--(receipts + ETL proofs)--> [auditors / operators]
```

Trust boundary summary:
- Treat DiscOS and callers as potentially adversarial.
- Trust only kernel-enforced controls for leakage accounting.
- Assume endpoint/OS compromise is out-of-scope for UVP guarantees.

> **Glossary bridge**
>
> - **"leakage k"** means transcript support budget (how much information interaction can reveal), **not** a cryptocurrency token.
> - **"ETL"** means an append-only transparency log used for auditability, **not** cryptocurrency.

## C) Worked example #1: Adaptive evaluation leakage

### Scenario (toy model)

A client repeatedly submits candidate models to a scoring service.

- Hidden asset: a private holdout set.
- Observable output: score feedback each round.
- Adversary goal (high-level): use repeated feedback to infer holdout structure/decision boundary over time.

### Baseline system (without EvidenceOS-style controls)

Blackbox I/O pattern:

| Round | Input to service | Output from service | Security effect |
| --- | --- | --- | --- |
| 1 | Candidate `M1` | Score `s1` | Small information gain |
| 2 | Slightly modified `M2` | Score `s2` | Gain compounds via adaptation |
| ... | ... | ... | ... |
| N | Adapted `MN` | Score `sN` | Sequence leaks holdout structure |

Why it fails: the attacker learns from the **sequence** of outputs, not any one output.

### EvidenceOS blackbox behavior

EvidenceOS applies three controls together:

1. **Quantization + hysteresis on oracle outputs**
   - Nearby candidate changes can map to the same response bucket.
   - Tiny probing steps often produce no new signal.
2. **Ledger budgets for interaction leakage (`k`)**
   - Each interaction spends from a bounded budget.
   - Related interactions can be charged jointly instead of reset per request.
3. **Fail-closed freeze/escalation**
   - When policies detect budget exhaustion or probing posture, response lane tightens (e.g., HEAVY/REJECT/FROZEN).
   - The system stops yielding high-bandwidth feedback.

Blackbox I/O comparison:

| Round | Input | Baseline output | EvidenceOS output |
| --- | --- | --- | --- |
| 1 | `M1` | Fine score | Quantized bucket + receipt |
| 2 | near-`M1` | Slightly changed fine score | Same bucket (hysteresis stall) |
| 3..N | adaptive probes | Rich incremental signal | Budget/lane events, throttled or frozen responses |

Defensive result: adaptive probing no longer scales linearly with query count; information gain is compressed and eventually cut off under policy.

## D) Worked example #2 (optional): Cross-oracle probing on shared holdout

### Baseline

Two oracles (A and B) expose different metrics on the same hidden holdout. A caller probes Oracle A, then uses those clues to better decode Oracle B responses.

### EvidenceOS

With **joint budget entanglement** for correlated interfaces, information extracted through A and B spends the same underlying leakage budget. Cross-oracle "difference decoding" no longer creates a free second channel; success probability collapses as shared budget depletes.

## E) Worked example #3 (optional): Timing side-channel

### Baseline

Response latency varies with secret-dependent internal branches. A caller measures timing over many requests and infers hidden state.

### EvidenceOS

- **Epoch settlement (DLC):** settlement/release cadence is normalized to deterministic windows.
- **Optional PLN controls:** add policy constraints to reduce timing-encoded signal surfaces.

Result: timing becomes a lower-bandwidth signal, reducing practical leakage through per-request latency differences.

## F) What EvidenceOS guarantees vs does NOT guarantee

### In scope (what it guarantees)

- Leakage control for **kernel-visible transcripts** crossing the EvidenceOS interface.
- Deterministic, auditable accounting of interaction budgets and decisions.
- Policy-driven fail-closed behavior when risk exceeds configured bounds.

### Out of scope (what it does not guarantee)

- Full endpoint or organization-wide security.
- Protection against host/OS compromise that steals keys or raw holdout data directly.
- Elimination of all risk outside the measured interface (e.g., unmanaged side channels).

---

If you only remember one thing: **EvidenceOS is a defensive kernel that constrains what repeated interaction can leak, and proves what happened afterward.**

## G) Reproducible sanitized transcript demo

A concrete, precomputed walkthrough is available at:

- [`docs/generated/blackbox_demo.md`](generated/blackbox_demo.md)

Regenerate it with:

```bash
make blackbox-demo
```

The generated report shows, step-by-step:

- canonical oracle outputs returned to DiscOS,
- per-step and cumulative leakage charge (`k`),
- budget remaining, and
- the exact freeze/escalation point once budget is exhausted.
