<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# EvidenceOS (Rust)

[![CI](https://github.com/jverdicc/EvidenceOS/actions/workflows/ci.yml/badge.svg)](https://github.com/jverdicc/EvidenceOS/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18685556.svg)](https://doi.org/10.5281/zenodo.18685556)
[![Paper](https://img.shields.io/badge/paper-FORC%202026-orange.svg)](https://doi.org/10.5281/zenodo.18685556)

EvidenceOS is a production-oriented verification kernel for the Universal Verification Protocol (UVP).

## What UVP is (in 60 seconds)

UVP is a kernel + userland architecture for certifying claims under adaptive interaction.
DiscOS (separate repo) is untrusted discovery/userland that proposes claim capsules.
EvidenceOS (this repo) is the trusted kernel that executes capsules on holdouts.
Every oracle response is canonicalized, metered, and logged so leakage is budgeted rather than ignored.
The protocol tracks evidence wealth (W) and adaptivity leakage (k) across time, identities, and interfaces.
This makes coordinated probing measurable, expensive, and auditable instead of silently cumulative.
The result is a verification system with explicit risk posture, deterministic settlement, and revocation-ready evidence trails.

## Start here (2-minute on-ramp)

1. **Worked threat-model example (recommended first read):** [`docs/threat_model_worked_example.md`](docs/threat_model_worked_example.md)
2. **Black-box UVP interface explainer:** [`docs/uvp_blackbox_interface.md`](docs/uvp_blackbox_interface.md)
3. **Hands-on adversarial demo:** [`examples/exfiltration_demo/`](examples/exfiltration_demo/)
4. **Epistemic Trial Harness (clinical-trial style evaluation):** [`docs/EPISTEMIC_TRIAL_HARNESS.md`](docs/EPISTEMIC_TRIAL_HARNESS.md) ([analysis pipeline](docs/TRIAL_HARNESS_ANALYSIS.md))
5. **Role-based reader map:** [`docs/reader_map.md`](docs/reader_map.md)
6. **Security implementation docs:** [`docs/HOLDOUT_ENCRYPTION.md`](docs/HOLDOUT_ENCRYPTION.md), [`docs/TEE.md`](docs/TEE.md), [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md)

> 🚩 **Read this for risk posture and dual-use analysis:** [`docs/POSITIONING.md`](docs/POSITIONING.md)
> 🚩 **Dual-use / misuse policy (deployment requirements):** [`docs/DUAL_USE_AND_MISUSE.md`](docs/DUAL_USE_AND_MISUSE.md)

New to the project or coming from outside systems engineering? Start with [`docs/START_HERE.md`](docs/START_HERE.md) for additional guided reading paths.

## Clinical trial harness

EvidenceOS includes an **Epistemic Trial Harness** for clinical-trial-style evaluation.

- Harness specification: [`docs/EPISTEMIC_TRIAL_HARNESS.md`](docs/EPISTEMIC_TRIAL_HARNESS.md)
- Analysis pipeline: [`docs/TRIAL_HARNESS_ANALYSIS.md`](docs/TRIAL_HARNESS_ANALYSIS.md)
- Analysis workspace overview: [`analysis/README.md`](analysis/README.md)

This repository contains:

- `evidenceos-core`: Conservation Ledger primitives, deterministic logical clock, ETL Merkle log, and ASPEC-like Wasm verifier.
- `evidenceos-daemon`: gRPC service exposing the kernel API.
- **[DiscOS](https://github.com/jverdicc/DiscOS)** (separate repo): untrusted discovery/userland orchestrator that proposes claim capsules and consumes kernel responses.

## Technical Summary

EvidenceOS + DiscOS implement the Universal Verification Protocol (UVP): a kernel–userland architecture for certifying claims under adaptive interaction. DiscOS is untrusted “discovery” userland that proposes executable claim capsules; EvidenceOS is a kernel that executes capsules on holdouts, controls all kernel I/O, and emits auditable receipts.

UVP’s core idea is conservation: certification is treated as a scarce resource. Every oracle reply and every byte of output is (1) canonicalized, (2) metered, and (3) logged so that security arguments compose across time, identities, and correlated query streams. The paper formalizes this with conserved evidence budgets: evidence wealth W (truth currency accumulated by a claim lineage) and adaptivity leakage k (information revealed about the holdout through interaction). Theorem 1 bounds false certification as a function of transcript support size, assuming the kernel enforces canonical realization, admissible execution, and metered oracles.

EvidenceOS operationalizes the envelope with several primitives:

• Quantized oracles with hysteresis. Oracles return discretized symbols (OracleResolution) rather than high-precision scores. Output hysteresis adds “metric stall” for local mutations: if a new submission’s true metric change is below a configured Δσ threshold, the kernel returns the previous bucket. This collapses bucket-probing precision in the paper’s stress tests and forces any would‑be attacker to pay for non‑local “jumps” to obtain new information.

• Conserved, joint accounting. The Conservation Ledger charges each query/settlement to k and W. When multiple interfaces share secrets (e.g., accuracy + safety on the same holdout), the ledger uses joint-interface accounting so cross-oracle probing can’t extract more bits by “differential” attacks across metrics.

• Safe composition under dependence. Where naïve product composition can fail under correlation, EvidenceOS provides conservative e-merging combiners intended to remain valid without independence assumptions.

• Sybil resistance via topic budgeting. Per-account limits are breakable by identity rotation; UVP charges a shared topic pool (TopicHash / MultiSignalTopicID) so extraction does not scale with identities.

• Non-bypassable admissibility (ASPEC). ASPEC is a decidable admissibility profile for claim Wasm that forbids ambient capabilities (time, randomness, network, files), forbids guest DP syscalls (`dp_laplace_i64`, `dp_gaussian_i64`) in sealed/high-assurance operation, enforces static resource bounds, and prevents hidden internal search. This ensures hypothesis selection happens through metered oracle calls, not inside submitted code.

• Deterministic, auditable settlement. A Deterministic Logical Clock (DLC) and epoch settlement reduce timing leakage. The Evidence Transparency Log (ETL) is an append-only Merkle log that publishes signed tree heads, supports inclusion/consistency proofs, and feeds revocations. Claims form a lineage DAG; recursive revocation taints descendants when a root is slashed.

UVP uses lanes (PASS/CANARY/HEAVY/REJECT) to trade latency for assurance. As risk targets tighten (α → 10⁻⁶ and beyond), systems hit a “verification wall”: more work is diverted to HEAVY verification and delayed settlement rather than allowing high-bandwidth interaction.

For the highest-risk profiles (e.g., CBRN), UVP recommends restricting outputs to Structured Claims: schema-bounded, typed fields with deterministic canonicalization. This collapses transcript capacity and reduces steganographic/manipulative bandwidth, making strict assurance targets tractable.

EvidenceOS is best understood as a verification kernel inside a larger secure system: host compromise, key theft, and hardware side-channels require standard isolation and deployment controls in addition to the protocol.

## Threat model (summary)

EvidenceOS assumes adaptive callers can use repeated interactions to extract holdout signal over time, even when each individual response appears harmless. The defensive posture is to canonicalize and meter interactions, maintain shared leakage/evidence budgets, and fail closed through escalation and freezing when risk posture is exceeded.

For the full narrative walkthrough and examples, see [`docs/THREAT_MODEL_BLACKBOX.md`](docs/THREAT_MODEL_BLACKBOX.md).

## Architecture diagrams

For high-level visual references of the vault/oracle internals and end-to-end UVP flow, see [`docs/ARCHITECTURE_DIAGRAMS.md`](docs/ARCHITECTURE_DIAGRAMS.md).
For a compact index of docs, see [`docs/README.md`](docs/README.md).


## Architecture: The Language Trade-off Matrix

For the EvidenceOS kernel, language choice is a security and determinism decision, not a developer preference. The Universal Verification Protocol (UVP) requires a strict **Trifecta**:

1. **Memory safety by construction** (to preserve the kernel threat boundary and prevent memory-corruption escapes).
2. **Deterministic low-latency execution** (to avoid runtime jitter that can distort settlement and verification behavior).
3. **Modern systems ecosystem fit** (to integrate directly with gRPC/Protobuf and contemporary AI-agent orchestration stacks).

No mainstream language besides Rust provides all three simultaneously.

| Language | What it does well | Why it fails the UVP kernel requirement |
|---|---|---|
| **C++** | Exceptional performance; dominant in MFT/HFT infrastructure where latency is critical. | In our threat model, manual memory management leaves room for buffer overflows and memory-corruption classes that can become “Sealed Vault” boundary escapes. That risk is incompatible with kernel-grade verification. |
| **Go / Java** | Strong memory safety and mature production tooling. | Their GC runtime introduces non-deterministic pause behavior and tail-latency spikes. For algorithmic trading-class timing and hard-real-time verification constraints, that execution jitter is unacceptable. |
| **Ada / SPARK** | Strong safety and formal assurance posture. | It does not currently offer the same modern ecosystem ergonomics we need (especially frictionless gRPC/Protobuf integration) to interface with current AI agent workflows at velocity. |

**Why Rust is the viable kernel language:** Rust’s **Ownership and Borrowing** model enforces memory safety and data-race freedom at compile time, while preserving predictable performance with zero garbage-collector runtime overhead. That is exactly the UVP Trifecta: safety, determinism, and practical integration in one systems language.

## Operation-Level Security (Swarms)

In swarm settings, per-prompt or per-agent monitoring breaks down because each individual exchange can look harmless while the aggregate sequence still extracts sensitive holdout structure (Paper: §2 Threat Model; Paper: §3 Adaptive Leakage). A swarm can distribute probing across many identities, tools, and time windows, so controls that only score one request at a time miss the operation-level trajectory (Paper: §12 Multi-Identity Adaptation). UVP therefore treats an **operation** as a first-class accounting object rather than assuming agent boundaries are meaningful security boundaries (Paper: §14 Cross-Claim Budgeting). In EvidenceOS, operation identity is represented by shared topic keys (`TopicHash`/`MultiSignalTopicID`) plus lineage context and tool/action metadata, so correlated activity is charged to a common budget even when the source account rotates (Paper: §14 Cross-Claim Budgeting; Paper: §11 Topic Coupling). This makes extraction cost cumulative across the whole operation, not reset per prompt, per session, or per worker process. Lineage DAG links and ETL commitments preserve the history required to enforce these shared budgets deterministically and to prove decisions after the fact (Paper: §7 Lineage and Revocation; Paper: §9 Transparency Log). UVP then applies lane routing to operational risk, moving traffic through PASS, CANARY, HEAVY, REJECT, and FROZEN states as evidence budgets deplete or anomaly signals increase (Paper: §10 Lanes and Interventions). These lanes implement graded interventions: low-friction allow in PASS, higher scrutiny and throttling in CANARY/HEAVY, hard denial in REJECT, and containment with taint propagation in FROZEN. Safe example: if multiple benign-looking requests collectively show temporal staircase probing across channels, the system escalates lanes and may freeze descendants rather than emitting high-bandwidth feedback. The result is defensive operation-level control that constrains swarm adaptivity without publishing offensive playbooks.

### Operation signals → UVP enforcement surface

| Operation signal | UVP primitive | Expected system response |
|---|---|---|
| Temporal staircase probing across many small requests | `TopicHash` / `MultiSignalTopicID` cross-claim budget | Lane escalation (PASS → CANARY/HEAVY) and tighter response resolution |
| Cross-channel differential probing (same objective via multiple tools/oracles) | Joint ledger accounting + shared topic pool | Throttling plus shared-budget debits to prevent channel arbitrage |
| Identity rotation against one operational objective | Topic-coupled accounting + lineage-aware attribution | Escalation or reject despite account churn |
| Rapid descendant branching after risky parent claim | Lineage DAG + ETL-backed revocation propagation | Taint descendants and optionally freeze branch (`FROZEN`) |
| Burst activity near settlement boundaries | DLC epochs + deterministic settlement windows | Delay/queue into HEAVY lane; restrict timing side-channel value |
| Suspicious validation canary failures | Canary pulse checks + revocation feed | Immediate lane raise, possible REJECT/FROZEN, publish revocation signal |

See [`docs/OPERATION_LEVEL_SECURITY.md`](docs/OPERATION_LEVEL_SECURITY.md) for a deeper operational model and enterprise integration guidance.

## Architecture at a glance

```text
DiscOS (untrusted discovery/userland)
            |
            | gRPC (canonicalized, validated, metered)
            v
EvidenceOS daemon + kernel (ASPEC, W/k accounting, DLC lanes)
            |
            | append-only commits + signatures
            v
ETL (Merkle log, STH/inclusion/consistency proofs)
            |
            | references
            v
Claim Capsules (lineage DAG, revocation-aware settlement)
```

## Plain-English Overview (Why this exists)

EvidenceOS and DiscOS implement the Universal Verification Protocol (UVP): a way to certify “claims” (machine-checkable outputs) even when an adversary can adapt their strategy across many interactions.

If you’ve ever seen a system where each individual request looks normal — but the aggregate behavior across time, accounts, or channels is clearly probing — that’s the failure mode UVP is designed to close. We treat the *operation* (the coordinated campaign) as the object that gets metered and controlled, not just the single request.

**What you get:**
- A hardened verifier daemon (EvidenceOS) that executes claims in a sealed sandbox, meters oracle access, and publishes auditable evidence (ETL log + inclusion/consistency proofs).
- An untrusted client/tooling layer (DiscOS) that prepares claims deterministically and consumes verifier responses without expanding the trust boundary.
- A reproducible test/evidence story: system tests, fuzzing, coverage gates, and scenario artifacts under `artifacts/`.

**What you do *not* get:**
- A content moderation system.
- A guarantee about “human-led physical execution quality.”
- A way to make unsafe capabilities safe by policy alone (UVP is about verifiable certification + evidence conservation + measurable leakage control).

### What happens when someone probes the system?

EvidenceOS is designed to make probing:
1) measurable (k-bits / budget consumption, lane transitions, rejects),
2) expensive (budgets and throttles are operation-scoped),
3) auditable (ETL evidence), and
4) stoppable (graded response that can fail-closed).

## Scope and Non-Goals

EvidenceOS addresses **evaluation integrity and adaptive leakage control**. It does not:
- Evaluate model toxicity, bias, or hallucination rates
- Replace content moderation or RLHF-based alignment
- Provide safety guarantees for single-shot interactions

EvidenceOS is designed for settings where an AI system is assumed to be capable, possibly deceptive, and operating across many interactions over time. Its guarantees are protocol-level and mathematical, not behavioral.

See [`docs/POSITIONING.md`](docs/POSITIONING.md) for a full capability and risk matrix.

## Practical Use Cases and Outcomes

| Use case category | Adversarial vector (plain English) | EvidenceOS mechanism | Mitigation / outcome | Reproducible evidence |
| --- | --- | --- | --- | --- |
| Transport/auth probing | Credential stuffing, missing token, invalid token attempts | TLS/mTLS + bearer/HMAC auth gates + fail-closed interceptor | REJECT / UNAUTHENTICATED | `crates/evidenceos-daemon/tests/transport_hardening_system.rs`, `crates/evidenceos-daemon/src/auth.rs::tests::wrong_token_rejected` |
| Oversized payload / decode limits probing | Oversized protobuf payloads intended to exhaust decode/memory paths | Bounded decode (`decode_with_max_size`) + strict gRPC size checks | REJECT (`RESOURCE_EXHAUSTED`) | `fuzz/fuzz_targets/fuzz_daemon_decode_limits.rs`, `crates/evidenceos-daemon/src/auth.rs` |
| Schema alias probing / topic-drift attempt | Alternate schema aliases or drift attempts to bypass canonical topic binding | Schema canonicalization + `topic_id` derivation from canonical metadata/signals | PASS only for canonicalized aliases; otherwise REJECT | `crates/evidenceos-daemon/tests/schema_aliases_system.rs`, `docs/TEST_COVERAGE_MATRIX.md` |
| Distillation-like high-volume probing | Many diverse claim attempts to learn internal behavior over time | Operation/token-scoped probe detector over request volume + semantic diversity + topic diversity, with k-bits/accounting visibility | THROTTLE → ESCALATE → FROZEN/REJECT | `crates/evidenceos-daemon/tests/probing_detection_system.rs`, `artifacts/probing/probing_detection_system.json`, `fuzz/fuzz_targets/fuzz_probe_detector.rs` |
| ETL tamper attempt | Bad inclusion/consistency proof or fork-history claim | ETL Merkle inclusion/consistency verification + signed tree heads | REJECT / incident | `crates/evidenceos-daemon/tests/etl_verification_system.rs`, `crates/evidenceos-daemon/tests/etl_proofs_system.rs` |
| Sealed-vault escape attempts | Excess oracle calls, oversized output, forbidden runtime behavior (and float-op policy rejection where configured) | Sealed vault limits + ASPEC policy + lane controls + deterministic settlement checks | THROTTLE/REJECT/FROZEN depending on violation | `crates/evidenceos-daemon/tests/vault_execution.rs`, `crates/evidenceos-daemon/tests/aspec_rejections.rs`, `fuzz/fuzz_targets/fuzz_aspec_verify.rs` |

For domain-specific integration guides showing how UVP maps onto electronic trading, FDA submissions, disease surveillance, and other high-stakes systems, see [docs/INTEGRATION_PATTERNS.md](docs/INTEGRATION_PATTERNS.md).

### Case study: distillation-style probing (public reporting)

A commonly reported class of incidents is high-volume prompting campaigns intended to clone model behavior and coerce internal reasoning traces. EvidenceOS treats this as an operation-level security event at the verifier boundary: it detects high-volume/high-diversity probing patterns in real time, applies graded response (THROTTLE, then ESCALATE, then FROZEN/REJECT), and records auditable ETL evidence that the response occurred.

### Threat Horizon: Post-Quantum Considerations

EvidenceOS's core guarantee (Theorem 1) is information-theoretic and invariant to quantum speedup—a quantum computer cannot extract more than k bits from a k-bit budget. However, the system faces two specific shifts in a post-quantum environment:

1. **Cryptographic Exposure:** The current cryptographic layer (ETL signatures, TopicHash) carries standard quantum exposure. Shor's algorithm threatens Ed25519 signing keys, and Grover's algorithm reduces effective hash security by half. Migration to CRYSTALS-Dilithium for signatures and SHA-3/512 for topic hashing is a roadmap item that requires zero changes to the underlying conservation ledger logic.
  
2. **Quantum Optimization Risk:** The more acute risk is adversarial efficiency. A quantum agent using QAOA (Quantum Approximate Optimization Algorithm) could find the maximally efficient extraction path within a fixed budget, making the adversarial model significantly tighter. While the information-theoretic wall remains, the agent's ability to "perfectly pack" its extraction backpack increases. Operators in post-quantum threat environments should configure conservative k-budgets accordingly.

*Status: Roadmap. Core theorem is quantum-resistant by construction. Cryptographic migration is architecture-specified.*

## Assurance status

- **Proven (paper-level model):** UVP conservation framing, transcript accounting, and theorem-backed risk bounds under stated kernel assumptions.
- **Sim-tested (repo evidence):** deterministic behavior, ledger transitions, ETL proofs/consistency, gRPC lifecycle paths, and fuzzed parser/state surfaces.
- **Architecture specified:** DiscOS↔EvidenceOS split, ASPEC admissibility boundary, topic-budget anti-sybil model, and lane-based settlement controls.
- **Roadmap:** stronger production hardening around key lifecycle/rotation, expanded policy packs, and additional end-to-end adversarial simulation suites.
- **PLN implementation scope:** current production PLN is runtime fuel normalization + deterministic epoch rounding; compile-time CFG branch equalization is not yet implemented (see `docs/PLN_PRODUCTION_PROFILE.md`).

## Implementation status (paper ↔ code)

To avoid review-time ambiguity between paper artifact snapshots and current mainline code, use:

- [`docs/PAPER_VS_CODE.md`](docs/PAPER_VS_CODE.md) for the living parity matrix (paper claim → repo implementation → status).
- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) for additional implementation guardrail notes.

## Verification Matrix

| Use case category | Adversarial vector (high-level) | EvidenceOS mechanism(s) | Mitigation / outcome | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| Adaptive metric probing | Repeated near-threshold probing to infer holdout internals | Quantization (`epsilon`/bucketing), hysteresis (`delta` stall), W/k charging | THROTTLE or HEAVY as k budget rises; reduced bit leakage | Live | [docs/TEST_COVERAGE_MATRIX.md](docs/TEST_COVERAGE_MATRIX.md), [docs/TEST_EVIDENCE.md](docs/TEST_EVIDENCE.md), [`fuzz_oracle_roundtrip`](fuzz/fuzz_targets/fuzz_oracle_roundtrip.rs) |
| Cross-interface differential extraction | Combining outputs across related oracle interfaces | Joint-interface accounting, conserved W/k budgets, topic pooling | PASS only under budget; otherwise THROTTLE/HEAVY | Sim-tested | [docs/TEST_COVERAGE_MATRIX.md](docs/TEST_COVERAGE_MATRIX.md), [`fuzz_ledger_ops`](fuzz/fuzz_targets/fuzz_ledger_ops.rs) |
| Sybil amplification | Identity rotation to bypass per-account limits | TopicHash / MultiSignalTopicID shared budgets | THROTTLE or REJECT once topic budget exhausted | Architecture specified | [docs/TEST_COVERAGE_MATRIX.md](docs/TEST_COVERAGE_MATRIX.md) |
| Hidden in-capsule search | Submitting code that smuggles unmetered optimization/search | ASPEC admissibility and bounded execution profile | REJECT inadmissible capsules before settlement | Live | [docs/TEST_EVIDENCE.md](docs/TEST_EVIDENCE.md), [`fuzz_aspec_verify`](fuzz/fuzz_targets/fuzz_aspec_verify.rs) |
| Timing/order manipulation | Exploiting race/order non-determinism for inconsistent receipts | Deterministic Logical Clock (DLC), canonicalization, deterministic ETL commits | PASS with reproducible receipts; divergent flows rejected/frozen | Live | [docs/TEST_EVIDENCE.md](docs/TEST_EVIDENCE.md), [`fuzz_etl_ops`](fuzz/fuzz_targets/fuzz_etl_ops.rs), [`fuzz_etl_read_entry`](fuzz/fuzz_targets/fuzz_etl_read_entry.rs) |
| Proven bad-root propagation | Downstream claims continue after root invalidation | Lineage DAG + recursive revocation feed | FROZEN/REJECT for tainted descendants | Sim-tested | [docs/TEST_EVIDENCE.md](docs/TEST_EVIDENCE.md), [docs/TEST_COVERAGE_MATRIX.md](docs/TEST_COVERAGE_MATRIX.md) |

## Threat model & out-of-scope

EvidenceOS addresses protocol-level verification integrity under its kernel assumptions. It does **not** by itself eliminate deployment-layer compromise classes.

Out-of-scope without additional deployment controls:

- **Host compromise:** a compromised host/VM can alter process memory, binaries, or runtime controls; use hardened hosts, isolation, and measured boot/attestation.
- **Key theft/misuse:** stolen ETL signing or service keys can produce convincing but malicious artifacts; use HSM/KMS, key rotation, and strict operational controls.
- **Hardware side-channels:** microarchitectural leakage and physical side channels are not neutralized by protocol accounting; use workload isolation and platform hardening.

These are deployment responsibilities. UVP/EvidenceOS should be combined with standard production security controls.

## Quickstart

### 1) Build

```bash
cargo build --workspace
```

### 2) Run the kernel

```bash
cargo run -p evidenceos-daemon -- \
  --listen 127.0.0.1:50051 \
  --data-dir ./data \
  --nullspec-registry-dir ./data/nullspec-registry \
  --nullspec-authority-keys-dir ./data/trusted-nullspec-keys
```

> `--etl-path` is deprecated; use `--data-dir` for all daemon launches.

### 3) Test

```bash
cargo test --workspace
```

## Reproducibility & evidence

EvidenceOS keeps test evidence and coverage mapping in-repo:

- Test evidence procedures/results: [`docs/TEST_EVIDENCE.md`](docs/TEST_EVIDENCE.md)
- Coverage matrix (mechanism-level): [`docs/TEST_COVERAGE_MATRIX.md`](docs/TEST_COVERAGE_MATRIX.md)
- Coverage matrix (parameter-level appendix): [`docs/TEST_COVERAGE_PARAMETERS.md`](docs/TEST_COVERAGE_PARAMETERS.md)
- FORC paper artifact path index/status: [`docs/ARTIFACT_INDEX.md`](docs/ARTIFACT_INDEX.md)
- Fetch missing FORC paper artifacts from Zenodo DOI `10.5281/zenodo.18685556`: `bash scripts/fetch_forc_artifacts.sh`

Baseline reproducibility commands:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Fuzz entry points (requires `cargo-fuzz`):

```bash
cargo fuzz run fuzz_aspec_verify
cargo fuzz run fuzz_ledger_ops
cargo fuzz run fuzz_oracle_roundtrip
cargo fuzz run fuzz_etl_ops
cargo fuzz run fuzz_etl_read_entry
cargo fuzz run fuzz_structured_claim_validate
cargo fuzz run fuzz_probe_detector
```

## IPC API

EvidenceOS exposes gRPC/Protobuf APIs defined in:

- `crates/evidenceos-protocol/proto/evidenceos.proto` (`evidenceos.v2`, canonical)
- `crates/evidenceos-protocol/proto/evidenceos_v1.proto` (`evidenceos.v1`, compatibility)

Versioning and deprecation policy are documented in `docs/PROTOCOL_VERSIONING.md`.

Compatibility statement: DiscOS clients should call `GetServerInfo` during connect and verify both protocol major-version compatibility and `proto_hash` equality before issuing lifecycle RPCs. EvidenceOS exposes deprecated `Freeze`/`Seal` aliases that route to `FreezeGates`/`SealClaim` for backward compatibility.

The [DiscOS repository](https://github.com/jverdicc/DiscOS) includes:

- a Rust client
- a Python client example
- safe demonstration scenarios that use synthetic/toy data and avoid operational harmful instructions

When using DiscOS demos with EvidenceOS, keep demonstrations non-operational and policy-aligned; see [`docs/DUAL_USE_AND_MISUSE.md`](docs/DUAL_USE_AND_MISUSE.md).

If you are following older DiscOS docs/examples that reference `--etl-path`, update those invocations to EvidenceOS's current `--data-dir` flag.

## Claim lifecycle API

The daemon exposes a one-way claim lifecycle:

`CreateClaim -> CommitArtifacts -> FreezeGates -> SealClaim -> ExecuteClaim`

Read APIs are available for capsule retrieval, daemon public-key retrieval (`GetPublicKey`), signed tree heads, inclusion proofs, consistency checks, and revocation feeds.

Signature verification is in-band: clients fetch the Ed25519 public key and `key_id` (`sha256(public_key)`) via `GetPublicKey`, then verify SignedTreeHead and revocation-feed signatures against domain-separated prehashes (`evidenceos:sth:v1` and `evidenceos:revocations:v1`).

Key rotation strategy: the daemon supports keyrings under `<data-dir>/keys/` and signs new STHs with the active `key_id` while preserving historical verification via `GetPublicKey(key_id=...)` for prior keys.

## Research & Citation

This repository is part of the **Universal Verification Protocol (UVP)** research project.

* **Paper:** "The Conservation of Epistemic Integrity: A Kernel–Userland Protocol for Verifiable Reality" (Under Review at FORC 2026).
* **Citation DOI (all versions):** Cite all versions using [DOI: 10.5281/zenodo.18685556](https://doi.org/10.5281/zenodo.18685556), which always resolves to the latest release.

If you use this code in your research, please cite the Zenodo archive or the forthcoming FORC 2026 paper.

## License

Apache-2.0

## Protobuf toolchain

This repo uses a **vendored protoc** (`protoc-bin-vendored`) so contributors and CI do not need to install `protoc`.

## Container / deployment

A `Dockerfile`, `docker-compose.yml`, and a hardened `systemd` unit are provided under `deploy/systemd/`.

All deployment entrypoints should pass `--data-dir` (not the removed `--etl-path`) so the daemon manages `etl.log` and state files under one directory.

For HMAC-authenticated agents, production deployments should configure key rotation through `EVIDENCEOS_HMAC_KEYS` and optional compatibility fallback `EVIDENCEOS_HMAC_SHARED_SECRET`:

- `EVIDENCEOS_HMAC_KEYS` format: `"kid1:hexsecret1,kid2:hexsecret2"`.
- Requests may set `x-evidenceos-key-id`; if omitted, the daemon uses `default`.
- `EVIDENCEOS_HMAC_SHARED_SECRET` remains supported and maps to key id `default` for backward compatibility.
- Do not define the `default` key in both places simultaneously.

### Credit and Admission

EvidenceOS enforces credit spending at claim execution.
Credit minting and stake management are operator-provided.
See [docs/CREDIT_AND_ADMISSION.md](docs/CREDIT_AND_ADMISSION.md)
for the external service contract and configuration.

## Migration notes (V2 claim execution)

- New secure RPCs are available: `CreateClaimV2` and `ExecuteClaimV2`.
- Legacy `ExecuteClaim` (v1) is disabled by default and can be re-enabled only with `EVIDENCEOS_ENABLE_INSECURE_V1=true`.
- `topic_id` should now be kernel-computed from V2 metadata and topic signals.
- CI and local validation are standardized via `./scripts/test_evidence.sh` with a 95% line-coverage gate.

## What-if Scenarios Matrix

| Scenario | Adversarial vector | Mechanism | Expected outcome | Evidence link | Status |
|---|---|---|---|---|---|
| Deterministic lifecycle succeeds | Valid claim through full lifecycle | ASPEC + lifecycle guards + ETL inclusion/consistency/signature proofs | PASS | `scenarios_produce_deterministic_public_evidence` + `artifacts/scenarios/lifecycle_pass.json` | Live |
| Invalid claim input rejected | Malformed create request (`oracle_num_symbols=1`, empty name) | gRPC validation fail-closed | REJECT | `scenarios_produce_deterministic_public_evidence` + `artifacts/scenarios/reject_invalid_claim.json` | Live |
| Plaintext against TLS-only daemon | Transport downgrade attempt | TLS enforcement | REJECT | `transport_hardening_system::tls_required_rejects_plaintext` | Live |
| Missing mTLS client cert | Unauthorized client identity | mTLS authN | UNAUTHENTICATED | `transport_hardening_system::mtls_rejects_no_client_cert` | Live |
| Missing bearer token | API call without authorization | Request interceptor authN | UNAUTHENTICATED | `transport_hardening_system::auth_rejects_missing_token` | Live |
| Wrong bearer token | Credential guessing/replay | Request interceptor authN | UNAUTHENTICATED | `auth.rs::tests::wrong_token_rejected` | Live |
| Oversized decode payload | Input amplification | `decode_with_max_size` guard | RESOURCE_LIMIT | `fuzz_daemon_decode_limits` + auth decode unit tests | Experimental |
| Pre-seal execution attempt | Lifecycle bypass | claim state machine checks | REJECT | `lifecycle_v2::cannot_execute_before_seal` | Live |
| ETL inclusion tampering | Fake inclusion path | Merkle inclusion verifier | REJECT | `etl_verification_system::verifies_inclusion_consistency_and_sth_signature` | Live |
| ETL consistency tampering | Forked tree-history claim | Merkle consistency verifier | REJECT | `etl_verification_system::verifies_inclusion_consistency_and_sth_signature` | Live |
| Key rotation historical verification | Trust confusion across signing-key changes | key_id-indexed keyring lookup | PASS | `etl_verification_system::key_rotation_preserves_old_head_verification` | Live |
| Randomized rotation sequence | Repeated rotate+append stress | historical key verification + STH signature checks | PASS | `etl_verification_system::property_random_rotation_and_append_stays_verifiable` | Experimental |

### How to reproduce scenario evidence

```bash
./scripts/run_scenarios.sh
cat artifacts/scenarios/summary.json
```

For CI-equivalent outputs (coverage/fuzz logs plus scenario artifacts):

```bash
make test-evidence
```

## External Policy Oracles (Super Judges)

EvidenceOS supports externally provided “Super-Judge” policy oracles that operators can deploy without modifying kernel source. These plugins are intended for third-party safety policy overlays (for example, independent AI safety firms), and are intentionally constrained to preserve kernel safety and conservation guarantees.

Policy oracles are **veto-only**: they can only make outcomes more conservative (`DEFER`/`REJECT`). They cannot certify claims and cannot increase evidence wealth. In particular, oracle vetoes never upgrade a reject path, and veto-driven outcomes clamp settlement behavior so positive evidence is not minted from policy intervention.

Oracles run as untrusted Wasm in a deterministic sandbox: no imports, strict fuel and memory limits, fixed ABI exports, and fail-closed behavior on any trap, OOM, invalid return code, or malformed module. Oracle outputs are low-bandwidth by construction (single integer decision code) and receipts are canonicalized and embedded in claim capsules for verifier auditability.

The daemon loads manifests and Wasm blobs from `<data_dir>/policy-oracles/`, verifies pinned `sha256` hashes, enforces manifest schema/range constraints, and optionally verifies Ed25519 publisher signatures against `trusted_keys.json`.

Minimal policy oracle (WAT):

```wat
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) i32.const 0)
  (func (export "policy_oracle_decide") (param i32 i32) (result i32)
    i32.const 1)) ;; 1 = DeferToHeavy
```

Sample manifest:

```json
{
  "schema": "evidenceos.v1.policy_oracle_manifest",
  "oracle_id": "acme.superjudge.v1",
  "vendor": "Acme Safety",
  "version": "1.0.0",
  "description": "Conservative policy veto",
  "wasm_filename": "acme_superjudge.wasm",
  "wasm_sha256_hex": "<sha256>",
  "reason_code": 9001,
  "decision_mode": "veto_only",
  "max_fuel": 100000,
  "max_memory_bytes": 65536,
  "max_input_bytes": 4096,
  "require_signature": false,
  "signer_pubkey_ed25519_hex": null,
  "signature_ed25519_hex": null
}
```

See `docs/ORACLE_PLUGINS.md` for deployment and ABI details. UVP references: (Module B: Oracle Resolution… §10.1–10.5) and Canonical Realization §5.1.

## Bring Your Own Oracle (WASM bundles)

EvidenceOS supports third-party oracle plugins so specialized safety or compliance firms can ship judges without modifying kernel code.

Security model:
- Plugins are untrusted computation.
- Identity is pinned with signed manifests + wasm hashes.
- Execution runs in a deterministic wasm sandbox with bounded fuel/memory and no ambient network/fs/time/rng imports.
- Kernel owns canonical realization bytes, leakage charging, and ledger settlement.

Bundle layout:
- `oracles/<oracle_id>/<version>/manifest.json`
- `oracles/<oracle_id>/<version>/oracle.wasm`
- optional calibration blob and README.

To configure trusted signers, pass `--trusted-oracle-keys <path>` where JSON maps key ids to ed25519 public keys (hex). Set `--oracle-dir` to the bundle root. The daemon validates signature, ABI, ASPEC lane, and hash before loading.

Clients reference an `oracle_id` only; external raw metric values are never surfaced as protocol outputs. The kernel emits only canonical bucket symbols.

Warning: Oracle++ only makes sense under remote+attested deployment. Local plugins are still constrained by transcript and ledger controls, but host compromise assumptions differ.

## Oracle++ (remote attested oracle)

Oracle++ is optional and intended for **remote, non-bypassable** oracle deployments only. A local in-process clone can be copied or bypassed and does not provide the UVP remote trust assumptions.

EvidenceOS validates Oracle++ by:
- verifying signed attestation from trusted authorities,
- pinning oracle identity and measured runtime hash,
- pinning the kernel-expected `OracleResolution` hash,
- enforcing signed monotonic sequence numbers (`seq_no`) for replay/fork protection,
- enforcing canonical `bucket_bytes` validation (`no hidden bits`).

Attestation binds measured runtime state and protocol signing key material to the declared oracle identity. Query replies are accepted only when signatures validate and counters progress monotonically per `(oracle_id, session_id)`.

Oracle++ does **not** replace ledger controls. It complements transcript canonicalization, leakage accounting (`k`), and settlement controls already enforced by the kernel.

## NullSpec governance

EvidenceOS now requires an active NullSpec contract per `(oracle_id, holdout_handle)` before claim execution. Missing, expired, or resolution-hash-mismatched NullSpecs fail closed and emit incident records.

### Non-parametric e-process option

Operators can select a non-parametric `DirichletMultinomialMixture` e-process over discrete buckets (from calibration counts), or keep parametric Bernoulli/fixed-alt contracts where applicable.

See [docs/NULLSPEC.md](docs/NULLSPEC.md) and `evidenceosctl nullspec *` commands.

Example contract fields:

```json
{
  "schema": "evidenceos.nullspec.v1",
  "oracle_id": "settle",
  "kind": {"DiscreteBuckets": {"p0": [0.25, 0.25, 0.25, 0.25]}},
  "eprocess": {"DirichletMultinomialMixture": {"alpha": [1.0, 1.0, 1.0, 1.0]}}
}
```


## Structured Claims + PhysHIR

EvidenceOS supports strict structured-claim schemas with deterministic 
canonicalization:

- typed and bounded fields (reject unknown keys and floats),
- canonical JSON encoding with sorted keys,
- PhysHIR unit parsing and SI-dimension checks for quantity fields.

### What PhysHIR does

Every quantity field in a structured claim carries a Physical Dimension 
Signature (PDS):
[L]^a [M]^b [T]^c [I]^d [Θ]^e [N]^f [J]^g
where each bracket is an SI base dimension and each exponent is its power:

| Symbol | Dimension        | SI Base Unit  | Example exponent meaning     |
|--------|-----------------|---------------|------------------------------|
| [L]    | Length           | metre (m)     | a=2 → square metres          |
| [M]    | Mass             | kilogram (kg) | b=1 → kilograms              |
| [T]    | Time             | second (s)    | c=-1 → per second (Hz)       |
| [I]    | Electric current | ampere (A)    | d=1 → amperes                |
| [Θ]    | Temperature      | kelvin (K)    | e=1 → kelvin                 |
| [N]    | Amount of substance | mole (mol) | f=1 → molar quantities      |
| [J]    | Luminous intensity | candela (cd) | g=1 → candela               |

When a claim is submitted, the kernel:

1. Parses the quantity string ("12.3 mmol/L") into fixed-point form
2. Resolves its PDS signature ([L]^-3 [N]^1 for molar concentration)
3. Checks the resolved PDS against the schema-declared required dimension
4. Rejects the claim if the dimensions do not match

### Why this matters for leakage control

Without PDS, all numeric outputs are dimensionally equivalent. A topic 
budget applied to "concentration queries" can be bypassed by reformulating 
the same query as a ratio or a rate. PhysHIR closes this by making the 
kernel dimension-aware: leakage budgets (k) can be scoped to specific PDS 
signatures. A tight budget on [N] (molar quantities) is not consumed by 
requests about [T] (timing) or [L] (distance). Probing across physically 
unrelated dimensions yields no informational advantage against a 
dimension-specific budget.

### Example (non-sensitive)

{
  "schema_id": "cbrn-sc.v1",
  "claim_id": "claim-001",
  "event_time_unix": 1700000000,
  "sensor_id": "sensor-a",
  "location_id": "zone-1",
  "measurement": "12.3 mmol/L",
  "confidence_bps": 9800,
  "reason_code": "WATCH"
}

Field notes:
- measurement: parsed to fixed-point, PDS resolved to [L]^-3 [N]^1, 
  checked against schema before acceptance
- confidence_bps: integer basis points (0–10000), not a float — 
  avoids floating-point non-determinism in canonicalization
- event_time_unix: [T]^1, unix epoch seconds, integer only
- reason_code: bounded enum, unknown values rejected at schema layer
