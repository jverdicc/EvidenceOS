# EvidenceOS Positioning & Risk Matrix

This document outlines where EvidenceOS and the DiscOS userland bridge fit within the broader AI safety and evaluation landscape. It explicitly defines the threat models the Universal Verification Protocol (UVP) is designed to mitigate, and acknowledges the inherent dual-use nature of mathematical capability bounding.

## Section 1: Where EvidenceOS Operates

Standard AI safety evaluations largely focus on static intelligence or behavioral alignment. EvidenceOS operates on a fundamentally different layer: enforcing physical, mathematical bounds on dynamic, multi-step agentic state. 

Through its "Bring Your Own Oracle" (BYOO) architecture, EvidenceOS separates safety *detection* (handled by external specialized models) from safety *enforcement* (handled by the kernel's Conservation Ledger).

| Risk Category | Static Leaderboards | Behavioral Guardrails | EvidenceOS Status |
| :--- | :--- | :--- | :--- |
| **Toxicity / Bias** | 90% (RealToxicityPrompts) | 95% (Constitutional AI / RLHF) | **Enforced via BYOO** — Mathematically bounds external oracle vetoes. |
| **Single-Shot Hallucinations** | 80% (TruthfulQA) | 60% (System Prompts) | **Enforced via BYOO** — $W$ stagnation/depletion upon failed factual checks. |
| **Agentic Reward Hacking** | 10% | 30% | **85%** — Sealed Vault bounds execution state. |
| **Data Exfiltration / Privacy** | 0% | 20% | **95%** — Joint entropy ledger limits extraction. |
| **Capability Spillover** | 5% | 10% | **100%*** — Meters cumulative adaptivity leakage ($k$). |
| **CBRN Proliferation** | 0% | 15% | **100%*** — Mathematical halt via $W$ depletion & PhysHIR. |

*\* 100% coverage means EvidenceOS provides the only formal mechanism addressing this risk class. It does not mean deployment is complete or that all assumptions are resolved. Mechanism coverage is protocol-level. Sim-tested evidence is in `TEST_COVERAGE_MATRIX.md`. Live test evidence is in `TEST_EVIDENCE.md`.*

**Note on BYOO Enforcement:** For risks like Toxicity and Hallucinations, EvidenceOS does not natively *detect* the violation; the quality of detection is strictly bounded by the external policy oracle provided by the operator. However, EvidenceOS guarantees that the *enforcement* of that oracle is non-bypassable. An agent cannot adaptively brute-force a hallucination detector without exhausting its $k$-budget and facing deterministic termination (`FROZEN`).

---

## Section 2: Industry Applications

The enforcement of a Conservation Ledger introduces novel defensive capabilities, but simultaneously creates vectors for adversarial optimization.

| Industry | Protective Application (Defense) | Dual-Use Risk (Weaponization) |
| :--- | :--- | :--- |
| **Intelligence / Cyber** | Zero-trust LLM containment over classified data. | Stealth extraction swarms staying under detection thresholds. |
| **Bio-Pharma / CBRN** | Synthesis gatekeeper preventing restricted sequence discovery. | Boundary-optimized probing (EvidenceOS's CBRN hardening specifically addresses this vector via TopicHash budgeting and PhysHIR envelopes). |
| **Quantitative Finance** | HFT flash-crash guardrails via $W$ depletion. | Regulatory evasion through bounded-intent certification. |
| **Consumer Privacy** | $\epsilon, \delta$ budget enforcement on personal agent queries. | Maximum PII extraction calibrated to OS privacy thresholds. |
| **AI Evaluation Infrastructure** | Adaptive benchmark gaming prevention. | NullSpec manipulation to inflate certified performance. |
| **Agentic Economy / Swarms** | Multi-agent cascade prevention via operation-scoped $W/k$ budgets. | Distributed attack coordination staying below per-agent detection thresholds. |

---

## Section 3: Dual-Use Acknowledgment

EvidenceOS is inherently dual-use. Any mechanism that mathematically meters and bounds information extraction can be inverted to optimize extraction right up to that boundary. A DiscOS agent operating under a Conservation Ledger could, in principle, be used to guarantee its own probing stays beneath network anomaly detection thresholds rather than to prevent probing.

The authors acknowledge this reality. We note that deployment in high-risk domains requires strict governance controls outside the protocol itself—specifically NullSpec pre-commitment, operator key management, and cryptographic audit transparency—to close the dual-use gap. This open-source release is intended to advance foundational defensive systems research, not to provide a blueprint for offensive use.

---

## Section 4: Connection to Active Research

The **Capability Spillover** vector mapped above is the focus of active, global research programs (such as SPAR) studying how highly capable AI systems might accumulate disproportionate influence or forbidden knowledge through incremental, individually innocuous steps.

EvidenceOS addresses this gap at the protocol level: rather than attempting to detect spillover behaviorally *after* the fact, it meters cumulative adaptivity leakage ($k$) as a physically conserved resource. By enforcing a hard boundary, it makes capability spillover mathematically expensive and ultimately impossible to execute past the predefined budget, shifting the paradigm from behavioral detection to architectural prevention.

---

## Section 5: Detailed Use Cases (Defense + Dual-Use)

### 5.1 Intelligence / Cyber

- **Defense path:** Deploy EvidenceOS as an execution choke-point between untrusted analyst copilots and classified retrieval/oracle systems. Every query and response burns budget, making repeated extraction attempts deterministic and auditable.
- **Dual-use risk:** Adversaries can intentionally budget their extraction strategy to remain just below anomaly triggers, using ledger constraints as optimization targets rather than safeguards.
- **Operational mitigation:** Enforce topic-level shared budgets, strict NullSpec policy pre-commitment, and short settlement epochs with independent ETL review.

### 5.2 Bio-Pharma / CBRN

- **Defense path:** Gate sequence-design assistants through constrained UVP interfaces so candidate generation is metered, canonicalized, and terminated when risk budgets are exhausted.
- **Dual-use risk:** A malicious operator can explore near-threshold sequence spaces with mathematically tuned probing to maximize dangerous insight per unit budget.
- **Operational mitigation:** Pair EvidenceOS with PhysHIR-style envelope constraints, deny-by-default schema policies, and independent revocation authorities.

### 5.3 Quantitative Finance (HFT / MFT)

In quantitative finance, the line between a highly optimized strategy and market manipulation can become razor-thin. UVP applies in both directions: as a hard safety brake and as a potential optimization shell for adversarial behavior.

#### Defense: Flash-crash guardrails via $W$ depletion

- **Problem:** Runaway feedback loops in algorithmic execution can issue extreme bursts of order modifications before conventional software guardrails react.
- **Mechanism:** Place EvidenceOS between strategy agent and execution gateway. Each order mutation consumes evidence wealth ($W$).
- **Outcome:** If the agent enters a pathological loop, rapid budget depletion deterministically drives the kernel to a `FROZEN` state and halts downstream order flow.

#### Dual-use risk: Regulatory evasion via bounded-intent framing

- **Problem:** Market-manipulation investigations often hinge on proving intent around spoofing, layering, or quote stuffing.
- **Weaponization pattern:** A malicious desk can tune UVP limits to sit just under known surveillance thresholds, then present cryptographic logs as evidence of “bounded” behavior while still extracting toxic microstructure edge.
- **Outcome risk:** Cryptographic attestations are reframed as compliance theater unless governance, policy pre-commitment, and external audit rules are mandatory.

### 5.4 Consumer Privacy

- **Defense path:** Budget personal-agent data access under explicit $\epsilon, \delta$-like leakage envelopes so sensitive profile reconstruction becomes costly and capped.
- **Dual-use risk:** Product teams may optimize to the maximum allowable data extraction while claiming mathematical privacy compliance.
- **Operational mitigation:** Require transparent policy disclosure, user-visible budget burn-down, and independent auditability of ETL roots.

### 5.5 AI Evaluation Infrastructure

- **Defense path:** Prevent adaptive benchmark gaming by forcing all trial interactions through metered, canonicalized channels that preserve statistical validity under repeated probing.
- **Dual-use risk:** If NullSpec and holdout schemas are manipulable, actors can still overfit to known constraints and inflate certified performance.
- **Operational mitigation:** Commit benchmark policies and holdout governance before runs, with post-hoc consistency proofs and revocation support.

### 5.6 Agentic Economy / Swarms

- **Defense path:** Allocate operation-scoped budgets across multi-agent workflows so emergent cascades fail closed when collective leakage exceeds policy.
- **Dual-use risk:** Distributed operators can coordinate many low-noise agents to maximize total extraction while preserving innocuous per-agent traces.
- **Operational mitigation:** Use shared topic accounting across identity boundaries and enforce cross-agent linkage in anomaly and revocation pipelines.

---

*Reference: Universal Verification Protocol: Bounding AI Adaptivity Leakage via Conservation Ledgers (DOI: [10.5281/zenodo.18685556](https://zenodo.org/records/18685556)).*
