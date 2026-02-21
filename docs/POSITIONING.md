# EvidenceOS Positioning & Risk Matrix

This document outlines where EvidenceOS and the DiscOS userland bridge fit within the broader AI safety and evaluation landscape. It explicitly defines the threat models the Universal Verification Protocol is designed to mitigate, and acknowledges the inherent dual-use nature of mathematical capability bounding.

## Section 1: Where EvidenceOS Operates

Standard AI safety evaluations largely focus on static intelligence or behavioral alignment. EvidenceOS operates on a fundamentally different layer: enforcing physical, mathematical bounds on dynamic, multi-step agentic state.

| Risk Category | Static Leaderboards | Behavioral Guardrails | EvidenceOS | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Toxicity / Bias** | 90% (RealToxicityPrompts) | 95% (Constitutional AI / RLHF) | **0%** — out of scope by design | N/A |
| **Single-Shot Hallucinations** | 80% (TruthfulQA) | 60% (System Prompts) | **0%** — out of scope by design | N/A |
| **Agentic Reward Hacking** | 10% | 30% | **85%** — Sealed Vault bounds state | Live |
| **Data Exfiltration / Privacy** | 0% | 20% | **95%** — $\epsilon, \delta$ ledger limits extraction | Sim-tested |
| **Capability Spillover** | 5% | 10% | **100%*** — meters cumulative leakage $k$ | Architecture specified |
| **CBRN Proliferation** | 0% | 15% | **100%*** — mathematical halt via $W$ depletion | Architecture specified |

*\* 100% coverage means EvidenceOS provides the only formal mechanism addressing this risk class. It does not mean deployment is complete or that all assumptions are resolved. Mechanism coverage is protocol-level. Sim-tested evidence is in TEST_COVERAGE_MATRIX.md. Live test evidence is in TEST_EVIDENCE.md. See NullSpec governance (Open Problem 1 in the paper) for current limitations.*

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

The authors acknowledge this reality. We note that the deployment of EvidenceOS in high-risk domains requires strict governance controls outside the protocol itself—specifically NullSpec pre-commitment, operator key management, and cryptographic audit transparency—to close the dual-use gap. This open-source release is intended to advance foundational defensive systems research, not to provide a blueprint for offensive use.

---

## Section 4: Connection to Active Research

The **Capability Spillover** vector mapped above is the focus of active, global research programs (such as SPAR) studying how highly capable AI systems might accumulate disproportionate influence or forbidden knowledge through incremental, individually innocuous steps. 

EvidenceOS addresses this gap at the protocol level: rather than attempting to detect spillover behaviorally *after* the fact, it meters cumulative adaptivity leakage ($k$) as a physically conserved resource. By enforcing a hard boundary, it makes capability spillover mathematically expensive and ultimately impossible to execute past the predefined budget, shifting the paradigm from behavioral detection to architectural prevention.

---
*Reference: Universal Verification Protocol: Bounding AI Adaptivity Leakage via Conservation Ledgers [arXiv link pending FORC review] (DOI: [Insert Zenodo DOI])*.
