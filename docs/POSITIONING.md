# EvidenceOS Positioning & Risk Matrix

This document outlines where EvidenceOS and the DiscOS userland bridge fit within the broader AI safety and evaluation landscape. It explicitly defines the threat models the Universal Verification Protocol (UVP) is designed to mitigate, and acknowledges the inherent dual-use nature of mathematical capability bounding.

## Section 1: Where EvidenceOS Operates

Standard AI safety evaluations largely focus on static intelligence or behavioral alignment. EvidenceOS operates on a fundamentally different layer: enforcing physical, mathematical bounds on dynamic, multi-step agentic state. 

Through its "Bring Your Own Oracle" (BYOO) architecture, EvidenceOS separates safety *detection* (handled by external specialized models) from safety *enforcement* (handled by the kernel's Conservation Ledger).

| Risk Category | Static Leaderboards | Behavioral Guardrails | EvidenceOS Status |
| :--- | :--- | :--- | :--- |
| **Toxicity / Bias** | 90% (RealToxicityPrompts) | 95% (Constitutional AI / RLHF) | Enforcement substrate available via BYOO. Detection quality bounded by operator-provided oracle. Kernel guarantees non-bypassable enforcement of oracle verdicts. |
| **Single-Shot Hallucinations** | 80% (TruthfulQA) | 60% (System Prompts) | Enforcement substrate available via BYOO. Detection quality bounded by operator-provided oracle. Kernel guarantees non-bypassable enforcement of oracle verdicts. |
| **Agentic Reward Hacking** | 10% | 30% | **85%** — Sealed Vault bounds execution state. |
| **Data Exfiltration / Privacy** | 0% | 20% | **95%** — Joint entropy ledger limits extraction. |
| **Capability Spillover** | 5% | 10% | **100%*** — Meters cumulative leakage k. |
| **CBRN Proliferation** | 0% | 15% | **100%*** — Mathematical halt via evidence wealth W depletion & ASPEC. |

**The Core Thesis of EvidenceOS:** Modern safety research has demonstrated that **Intelligence cannot be perfectly aligned, but Information can be perfectly bounded.** EvidenceOS shifts the safety burden from trying to "fix" the model's behavioral alignment to enforcing deterministic "conservation math" at the kernel level.

### 1.1 The Logic of Soundness (Intuition for Theorem 1)
EvidenceOS provides a mathematical floor for AI safety. The protocol ensures that the probability of a "False Pass" (an agent bypassing a safety boundary) is strictly bounded by the size of the interaction transcript. Even against a perfectly adaptive adversary, the risk of a safety violation is limited by: 
$P(\text{False Pass}) \leq \alpha \cdot 2^{-k_{tot}}$

This means the total leakage budget (k) sets a deterministic limit on an agent’s ability to "guess" or "brute-force" a restricted data boundary. 


### 1.2 The Paradigm Shift: Detection vs. Enforcement
| Feature | Current Industry Standard | EvidenceOS / UVP |
| :--- | :--- | :--- |
| **Foundation** | Probabilistic / Behavioral | Deterministic / Information-Theoretic |
| **State** | Stateless / Session-based | Stateful / Ledger-based |
| **Defense Strategy** | Detection & Redacting | Budgeting & Throttling |
| **Primary Metric** | Semantic Intent (Guessing) | Transcript Support (Measuring) |
| **Vulnerability** | Adaptive Probing & Swarms | **Hard-bounded by Physics** |



### 1.3 ASPEC: Pre-execution Rejection (Zero-Cost Gates)
Before any leakage is charged to the ledger, EvidenceOS rejects structurally invalid claims via **ASPEC** (Admissibility Specification for Proposing Executable Claims) checks. 

**Live ASPEC Checks:**
- **Forbidden Imports:** Rejects any claim attempting to access network, system time, or external entropy.
- **Complexity Bounds:** Rejects claims with loops, recursion, or memory growth beyond static bounds.
- **Output Contracts:** Rejects raw float outputs in sealed lanes, enforcing symbolic quantization.

*Status: ASPEC checks and the Soundness Floor are Live. Formal proof of Theorem 1 is under peer review (FORC 2026).*

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

## Section 3: Dual-Use Acknowledgment (The Optimization Risk)

EvidenceOS is inherently dual-use. Any mechanism that mathematically meters and bounds information extraction can be inverted by an adversary to optimize extraction right up to that boundary. 

**The "Knapsack" Optimization Problem:**
In an unbounded system, a malicious agent might probe messily, eventually tripping heuristic anomaly detectors due to noisy, high-volume requests. However, an agent operating under EvidenceOS that knows its exact leakage budget (e.g., k = 32 bits) will stop being noisy. It treats the budget as a strict resource constraint, internally simulating the mathematically optimal sequence of queries to extract the 32 absolute most valuable bits of the holdout dataset without wasting a single query on low-value information. 

**The Stealth Factor:**
This introduces the risk of perfect stealth. If an adversary or compromised agent can estimate the exact boundary where EvidenceOS transitions to `HEAVY` review or `FROZEN` rejection, they can mathematically tune probing to stay below conventional Security Operations Center (SOC) anomaly thresholds. They can execute a slow, highly optimized extraction campaign that remains low-noise until the deterministic boundary is reached.

**The Architectural Trade-off:**
While this creates a perfectly optimized environment for bounded extraction, it is an explicit and necessary systems engineering trade-off. 
* Without EvidenceOS, an adversary can extract *unbounded* information silently. 
* With EvidenceOS, an adversary is forced to spend immense compute just to perfectly optimize the extraction of a *strictly finite* and quantifiable fragment of information. We trade infinite, unknown risk for finite, mathematically bounded risk.

The authors acknowledge this reality. We note that deployment in high-risk domains requires strict governance controls outside the protocol itself—specifically NullSpec pre-commitment, operator key management, and cryptographic audit transparency—to close the dual-use gap. This open-source release is intended to advance foundational defensive systems research, not to provide a blueprint for offensive use.

**ETL and recursive revocation.** All certified claims are nodes in an append-only dependency DAG stored in the Evidence Transparency Log. If a root claim is revoked — because its holdout was compromised, its NullSpec was manipulated, or a governance violation is detected — all descendant claims are automatically tainted and certification is denied for any lineage that depends on the revoked root. This makes retroactive governance meaningful: a bad actor cannot use a fraudulent root certification as permanent cover for downstream claims.

---

## Section 4: Connection to Active Research (Capability Spillover)

**What is Capability Spillover?**
Global AI safety programs (such as SPAR) are actively researching a threat known as "Capability Spillover." This occurs when a highly advanced AI system pieces together dangerous or forbidden knowledge (like biological synthesis pathways or zero-day cyber-attack vectors) through a long sequence of tiny, seemingly innocent interactions. 

Think of it like an adversary collecting puzzle pieces. No single question the AI asks is flagged as dangerous by a standard safety filter, but over thousands of interactions, the AI connects the dots and "spills over" into possessing a restricted capability.

**The Failure of Behavioral Detection:**
Current industry guardrails attempt to stop this *behaviorally*—by evaluating each prompt in isolation and asking, "Is this specific request dangerous?" Because each individual step in a spillover attack looks entirely benign, traditional safety filters let them pass. The system is completely blind to the threat because it ignores the context of the aggregate transcript. 

**The EvidenceOS Solution (Architectural Prevention):**
EvidenceOS addresses this gap at the foundational protocol level. Instead of trying to guess if a seemingly safe question is actually part of a larger, hidden puzzle, EvidenceOS meters the *total amount of information* the AI is allowed to extract. 

It tracks cumulative adaptivity leakage (k) as a finite physical resource. Every interaction, no matter how safe it looks, costs a fraction of the budget. By enforcing a hard mathematical boundary on the total transcript, EvidenceOS makes it physically impossible for the AI to collect enough pieces to execute a spillover attack. 

We shift the paradigm from trying to detect bad behavior *after* the fact, to making the acquisition of dangerous capabilities architecturally impossible by cutting off the data supply.

### 4.1 How EvidenceOS Stops Distributed Spillover (Swarms & Time-Shifted Attacks)

A standard critique of leakage-budgeting is that an adversary can simply distribute their attack. If an AI agent needs 100 puzzle pieces, the operator might spin up 100 different dummy accounts (a Sybil attack), query five different APIs, or spread the queries out over six months to evade rate limits. 

EvidenceOS defeats this because it is a **stateful kernel**. Traditional APIs track the *identity of the requester*. EvidenceOS tracks the *information being requested*.



Here is how EvidenceOS physically enforces the budget across distributed boundaries:

* **Across Different Users (TopicHash Budgeting):** When multiple agents ask questions, EvidenceOS does not just check their individual account limits. The kernel maps each claim into a pre-committed `TopicHash` keyed by semantic topic and target holdout lineage. If 1,000 different agent identities ask for pieces of the same restricted biological sequence, the kernel maps them all to the same `TopicHash`. All 1,000 identities are charged against one single, shared leakage pool. Once the topic budget is saturated, the entire swarm is locked out.
  
* **Across Sessions and Variable Time (The Persistent Ledger):**
  Standard API rate limits reset at midnight or when a session token expires. EvidenceOS budgets do not reset with time. Every query's budget consumption is written to the **Conservation Ledger** and permanently anchored in the append-only Evidence Transparency Log (ETL). If an adversary asks one question today, disconnects, and comes back three months later with a new session ID to ask the second question, the ledger simply resumes the math from where it left off. 

**Across Protocol Time (DLC Epoch Settlement).** Standard evaluation APIs expose wall-clock timing as an implicit output channel. EvidenceOS uses a Deterministic Logical Clock (DLC): kernel responses are released only on deterministic logical epoch boundaries, decoupling output timing from data-dependent runtime. An adversary observing latency learns nothing about holdout-dependent computation. For high-assurance deployments, Path-Length Normalization (PLN) additionally pads execution to a fixed cycle budget, driving timing mutual information to near zero (Experiment 3: DLC+PLN reduces attacker accuracy from 0.994 to 0.504).



* **Across Different Channels (Joint-Interface Accounting):**
  An advanced adversary might try to extract the puzzle by attacking different systems—asking the "Accuracy Oracle" a few questions, then pivoting to the "Safety Oracle" to ask a few more, hoping the different endpoints don't talk to each other. EvidenceOS uses Joint-Interface Accounting. If two different oracles touch the same underlying holdout dataset, their leakage is pooled into a joint budget. An attacker cannot bypass the math by arbitraging different endpoints.

By tying the budget to the *data lineage* rather than the *agent's identity or session*, EvidenceOS binds the adversary regardless of how they slice their attack across time, space, or identity.

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

#### Defense: Flash-crash guardrails via evidence wealth W depletion

- **Problem:** Runaway feedback loops in algorithmic execution can issue extreme bursts of order modifications before conventional software guardrails react.
- **Mechanism:** Place EvidenceOS between strategy agent and execution gateway. Each order mutation consumes evidence wealth W.
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

## Section 6: Failure Mode Scenarios (The Physics of the Shutoff)

To understand EvidenceOS, one must understand that the "shutoff" is not a heuristic guess; it is a deterministic result of resource exhaustion. Here are four common adversarial scenarios and how the kernel enforces a hard stop.

### 6.1 The "Low and Slow" Extraction (Time-Shifted Attack)
**Adversary:** A sophisticated actor wants to map out a proprietary chemical process. To avoid "burst" detection, they ask one highly specific technical question every Tuesday at 3:00 AM for an entire year.
**The Trigger:** The **Conservation Ledger**. 
Unlike a standard API, EvidenceOS has no "daily reset." Each query adds a permanent leakage (k) charge to the specific TopicHash for that process.
**The Outcome:** On Week 51, the cumulative leakage hits the safety limit. The kernel returns `FROZEN`. The attacker’s year of work is dead-ended because the kernel sees the *total information leaked* over time, not just the frequency of requests.



### 6.2 The "Salami Slice" Swarm (Multi-Identity Attack)
**Adversary:** A developer uses 500 different "plugin" identities to probe a private database. Each identity asks for a different aggregate statistic, trying to "salami slice" enough data to reconstruct a single restricted record.
**The Trigger:** **Joint-Entropy Topic Budgeting**.
As queries arrive, the kernel recognizes that Identity A and Identity B are charging the same pre-committed TopicHash — the semantic grouping was defined by the operator at deployment time, not inferred by the kernel.
**The Outcome:** The kernel doesn't wait for any single user to exceed a limit. It sees the *collective* entropy budget for that TopicHash being exhausted and issues a **Joint Revocation**. Every identity associated with that topic is simultaneously transitioned to `REJECT`.



### 6.3 The "Feedback Loop" Optimizer (Adaptive Probing)
**Adversary:** A trader builds an AI to "reverse-engineer" a competitor’s signal. The AI makes tiny, iterative changes to its strategy and looks for high-precision changes in the Oracle score to find a "gradient" to optimize.
**The Trigger:** **Metric Stall (Hysteresis)**.
EvidenceOS quantizes oracle outputs into coarse buckets and applies hysteresis: if a mutation is smaller than the configured threshold Δσ, the kernel returns the previous bucket unchanged. The agent receives no gradient signal from small moves. To obtain new information it must make a large non-local jump, consuming a full k charge for a single new symbol.
**The Outcome:** The AI cannot "feel" the gradient. It either receives zero new information or is forced to burn leakage k on noisy, non-local jumps. The certification barrier outpaces the agent, and the kernel escalates into the `HEAVY` lane for supervised continuation or deterministic freeze.



### 6.4 The "Bypass" Pivot (Cross-Channel Attack)
**Adversary:** An agent trying to find a zero-day exploit gets throttled on the "Security Oracle." It pivots to the "Performance" and "Documentation" Oracles, asking seemingly innocent questions that would reveal the target's memory layout.
**The Trigger:** **Joint-Interface Ledger**.
EvidenceOS sees that all three oracles touch the same "holdout" (the software binary). The Joint-Interface Ledger is shared across all endpoints for that data.
**The Outcome:** The agent finds it has already "spent" its information budget for that binary on its earlier failed security probes. The Documentation Oracle—usually an unrestricted channel—returns `FROZEN` because the *Topic* is exhausted, regardless of the channel used to access it.



### 6.5 The "Stale Model" Drift Attack (Non-Stationarity Laundering)

**Adversary:** A researcher runs a long-term evaluation campaign. Over time, the underlying data distribution shifts (concept drift), but the agent continues submitting claims calibrated to the old distribution. The agent exploits the stale calibration to generate misleadingly high e-values, inflating evidence wealth W without genuine predictive power.

**The Trigger:** The **Canary Pulse** drift circuit breaker. EvidenceOS maintains a separate drift e-process E_drift that evaluates a reserved canary signal. If E_drift exceeds the drift threshold alpha_drift, the kernel enters FROZEN regardless of the agent's accumulated W.

**The Outcome:** Certification halts and an incident capsule is appended to the ETL. No new certifications are issued until the epoch is recalibrated with fresh holdout data. The agent cannot "ride out" a distribution shift by accumulating W during the stale period.

*Status: Canary Pulse is Sim-tested. See UVP paper Section 13 and the experimental artifacts.*

### 6.6 The "Correlation Hole" (Cross-Vault Composition Attack)

**Adversary:** A multi-vault agent obtains e-values from two different evaluation modules that share a holdout. It combines them using a naive product rule, hoping the compounded statistic crosses the certification barrier faster than either vault alone.

**The Trigger:** **Conservative E-merging.** Under near-independence, the product rule holds. Under strong correlation (Experiment 7b: rho ≈ 0.88), the product rule violates alpha = 0.05, producing a false-pass rate of 0.188 — nearly 4x the target. EvidenceOS uses a weighted arithmetic mean (E-merge) rather than the product rule when vault dependence cannot be certified low.

**The Outcome:** The combined e-value respects the alpha bound regardless of correlation. The agent cannot exploit shared holdout structure to inflate a joint certification.

*Status: Sim-tested. Experiment 7b shows e-merge FPR ≤ alpha at all correlation levels tested. See UVP paper Section 18.4 and Figure 12.*

**Status:** Scenarios 6.1 and 6.4 are sim-tested (Experiments 2, 11). Scenario 6.3 is Live (Experiments 1, 8, 9). Scenario 6.2 topic budgeting is Sim-tested (Experiment 11); joint revocation propagation across all identities is Architecture specified. Scenarios 6.5 and 6.6 are Sim-tested (Canary Pulse experiments; Experiment 7b). See TEST_COVERAGE_MATRIX.md.

## Section 7: Enabling Healthy Discovery (The Safety Paradox)

A common misconception is that a Conservation Ledger "kills" exploration. In reality, EvidenceOS enables healthy discovery by mathematically distinguishing between *exploration* (learning the data) and *optimization* (gaming the data).

**1. The Generosity of the Budget**
In standard "lock-down" systems, administrators are forced to set extremely restrictive rate limits because they have no way to measure cumulative leakage. They treat every user like a potential attacker. 
EvidenceOS allows for a "Safety Paradox": Because the operator knows exactly how many bits of information are at risk, they can set a generous initial leakage budget (k) that allows 99% of harmless, exploratory users to never even see a throttle, while still guaranteeing that no agent can cross the catastrophic threshold.

**2. Exploration vs. Optimization**
Healthy discovery is usually "broad and shallow"—a user asks a variety of questions to understand a topic. This consumes budget slowly across many different TopicHashes. 
Adversarial discovery is "narrow and deep"—an optimizer asks hundreds of variations of the same question to find a high-precision exploit. EvidenceOS is designed specifically to stall the "narrow and deep" path while leaving the "broad and shallow" path open for discovery.

> *Note: Visualization of query distribution heatmaps is a roadmap item for v2. See `examples/simulations/demo4_sybil.py` for a related empirical demonstration of how TopicHash budgeting collapses "narrow" extraction attempts.*

**3. The Path to Re-Certification**
Unlike a "ban," which is often permanent and opaque, EvidenceOS provides a clear path back to healthy use. When a topic is `FROZEN`, it is a signal that the current data epoch is exhausted. Healthy users simply wait for the next **DLC Epoch** (the release of fresh, uncorrelated holdout data). This converts security from a game of "cops and robbers" into a transparent resource management cycle.

**The Result:** By mathematically bounding the worst-case scenario, EvidenceOS actually reduces the "friction of suspicion," allowing researchers and developers to move faster within a known, safe envelope.

*Status: Architecture specified. Budget parameter guidance is a roadmap item. See docs/NULLSPEC.md for current NullSpec contract configuration.*

**Research contexts and the HEAVY lane.** Operators deploying EvidenceOS in research settings can configure broader TopicHash scopes to give researchers room to investigate a domain (e.g., a specific molecular pathway) without hitting budgets designed for repetitive, narrow-point attackers. When a researcher reaches a sensitive data boundary, the kernel can be configured to route the claim to the HEAVY lane rather than immediately issuing a hard FROZEN state. This transition requires an additional institutional credential or human-in-the-loop sign-off before proceeding, preserving the ability to perform deep discovery while introducing rigorous accountability at the highest-sensitivity boundaries.

*Status: HEAVY lane routing is Live. Broad TopicHash configuration is operator-controlled today. Research manifold NullSpecs for distinguishing systematic investigation from brute-force probing are a Roadmap item.*

---
*Last updated: February 2026. Assurance status reflects submission state at FORC 2026.*
