<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18685556.svg)](https://zenodo.org/records/18685556)

# EvidenceOS (Rust)

**EvidenceOS** is a production-oriented verification kernel for the Universal Verification Protocol (UVP).

- **EvidenceOS** (this repo): trusted kernel that enforces admissibility, deterministic execution, metered oracle access, and auditable settlement.
- **[DiscOS](https://github.com/jverdicc/DiscOS)** (separate repo): untrusted discovery/userland orchestrator that proposes claim capsules and consumes kernel responses.
- **UVP**: protocol model for certifying claims under adaptive interaction while conserving verification evidence across time and interfaces.

Why this matters: verification systems fail when adaptive querying, side channels, or weak accounting allow attackers to extract holdout information faster than assurance can be maintained. EvidenceOS is designed to constrain this extraction channel, provide auditable receipts, and make risk posture explicit.

This repository contains:

- `evidenceos-core`: Conservation Ledger primitives, deterministic logical clock, ETL Merkle log, and ASPEC-like Wasm verifier.
- `evidenceos-daemon`: gRPC service exposing the kernel API.

## Technical Summary

EvidenceOS + DiscOS implement the Universal Verification Protocol (UVP): a kernel–userland architecture for certifying claims under adaptive interaction. DiscOS is untrusted “discovery” userland that proposes executable claim capsules; EvidenceOS is a kernel that executes capsules on holdouts, controls all kernel I/O, and emits auditable receipts.

UVP’s core idea is conservation: certification is treated as a scarce resource. Every oracle reply and every byte of output is (1) canonicalized, (2) metered, and (3) logged so that security arguments compose across time, identities, and correlated query streams. The paper formalizes this with conserved evidence budgets: evidence wealth W (truth currency accumulated by a claim lineage) and adaptivity leakage k (information revealed about the holdout through interaction). Theorem 1 bounds false certification as a function of transcript support size, assuming the kernel enforces canonical realization, admissible execution, and metered oracles.

EvidenceOS operationalizes the envelope with several primitives:

• Quantized oracles with hysteresis. Oracles return discretized symbols (OracleResolution) rather than high-precision scores. Output hysteresis adds “metric stall” for local mutations: if a new submission’s true metric change is below a configured Δσ threshold, the kernel returns the previous bucket. This collapses bucket-probing precision in the paper’s stress tests and forces any would‑be attacker to pay for non‑local “jumps” to obtain new information.

• Conserved, joint accounting. The Conservation Ledger charges each query/settlement to k and W. When multiple interfaces share secrets (e.g., accuracy + safety on the same holdout), the ledger uses joint-interface accounting so cross-oracle probing can’t extract more bits by “differential” attacks across metrics.

• Safe composition under dependence. Where naïve product composition can fail under correlation, EvidenceOS provides conservative e-merging combiners intended to remain valid without independence assumptions.

• Sybil resistance via topic budgeting. Per-account limits are breakable by identity rotation; UVP charges a shared topic pool (TopicHash / MultiSignalTopicID) so extraction does not scale with identities.

• Non-bypassable admissibility (ASPEC). ASPEC is a decidable admissibility profile for claim Wasm that forbids ambient capabilities (time, randomness, network, files), enforces static resource bounds, and prevents hidden internal search. This ensures hypothesis selection happens through metered oracle calls, not inside submitted code.

• Deterministic, auditable settlement. A Deterministic Logical Clock (DLC) and epoch settlement reduce timing leakage. The Evidence Transparency Log (ETL) is an append-only Merkle log that publishes signed tree heads, supports inclusion/consistency proofs, and feeds revocations. Claims form a lineage DAG; recursive revocation taints descendants when a root is slashed.

UVP uses lanes (PASS/CANARY/HEAVY/REJECT) to trade latency for assurance. As risk targets tighten (α → 10⁻⁶ and beyond), systems hit a “verification wall”: more work is diverted to HEAVY verification and delayed settlement rather than allowing high-bandwidth interaction.

For the highest-risk profiles (e.g., CBRN), UVP recommends restricting outputs to Structured Claims: schema-bounded, typed fields with deterministic canonicalization. This collapses transcript capacity and reduces steganographic/manipulative bandwidth, making strict assurance targets tractable.

EvidenceOS is best understood as a verification kernel inside a larger secure system: host compromise, key theft, and hardware side-channels require standard isolation and deployment controls in addition to the protocol.


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

## Practical Use Cases and Outcomes

| Use case category | Adversarial vector (plain English) | EvidenceOS mechanism | Mitigation / outcome | Reproducible evidence |
| --- | --- | --- | --- | --- |
| Transport/auth probing | Credential stuffing, missing token, invalid token attempts | TLS/mTLS + bearer/HMAC auth gates + fail-closed interceptor | REJECT / UNAUTHENTICATED | `crates/evidenceos-daemon/tests/transport_hardening_system.rs`, `crates/evidenceos-daemon/src/auth.rs::tests::wrong_token_rejected` |
| Oversized payload / decode limits probing | Oversized protobuf payloads intended to exhaust decode/memory paths | Bounded decode (`decode_with_max_size`) + strict gRPC size checks | REJECT (`RESOURCE_EXHAUSTED`) | `fuzz/fuzz_targets/fuzz_daemon_decode_limits.rs`, `crates/evidenceos-daemon/src/auth.rs` |
| Schema alias probing / topic-drift attempt | Alternate schema aliases or drift attempts to bypass canonical topic binding | Schema canonicalization + `topic_id` derivation from canonical metadata/signals | PASS only for canonicalized aliases; otherwise REJECT | `crates/evidenceos-daemon/tests/schema_aliases_system.rs`, `docs/TEST_COVERAGE_MATRIX.md` |
| Distillation-like high-volume probing | Many diverse claim attempts to learn internal behavior over time | Operation/token-scoped probe detector over request volume + semantic diversity + topic diversity, with k-bits/accounting visibility | THROTTLE → ESCALATE → FROZEN/REJECT | `crates/evidenceos-daemon/tests/probing_detection_system.rs`, `artifacts/probing/probing_detection_system.json`, `fuzz/fuzz_targets/fuzz_probe_detector.rs` |
| ETL tamper attempt | Bad inclusion/consistency proof or fork-history claim | ETL Merkle inclusion/consistency verification + signed tree heads | REJECT / incident | `crates/evidenceos-daemon/tests/etl_verification_system.rs`, `crates/evidenceos-daemon/tests/etl_proofs_system.rs` |
| Sealed-vault escape attempts | Excess oracle calls, oversized output, forbidden runtime behavior (and float-op policy rejection where configured) | Sealed vault limits + ASPEC policy + lane controls + deterministic settlement checks | THROTTLE/REJECT/FROZEN depending on violation | `crates/evidenceos-daemon/tests/vault_execution.rs`, `crates/evidenceos-daemon/tests/aspec_rejections.rs`, `fuzz/fuzz_targets/fuzz_aspec_verify.rs` |

### Case study: distillation-style probing (public reporting)

A commonly reported class of incidents is high-volume prompting campaigns intended to clone model behavior and coerce internal reasoning traces. EvidenceOS treats this as an operation-level security event at the verifier boundary: it detects high-volume/high-diversity probing patterns in real time, applies graded response (THROTTLE, then ESCALATE, then FROZEN/REJECT), and records auditable ETL evidence that the response occurred.

## Assurance status

- **Proven (paper-level model):** UVP conservation framing, transcript accounting, and theorem-backed risk bounds under stated kernel assumptions.
- **Sim-tested (repo evidence):** deterministic behavior, ledger transitions, ETL proofs/consistency, gRPC lifecycle paths, and fuzzed parser/state surfaces.
- **Architecture specified:** DiscOS↔EvidenceOS split, ASPEC admissibility boundary, topic-budget anti-sybil model, and lane-based settlement controls.
- **Roadmap:** stronger production hardening around key lifecycle/rotation, expanded policy packs, and additional end-to-end adversarial simulation suites.

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
  --data-dir ./data
```

> `--etl-path` is deprecated; use `--data-dir` for all daemon launches.

### 3) Test

```bash
cargo test --workspace
```

## Reproducibility & evidence

EvidenceOS keeps test evidence and coverage mapping in-repo:

- Test evidence procedures/results: [`docs/TEST_EVIDENCE.md`](docs/TEST_EVIDENCE.md)
- Coverage matrix by mechanism and parameter class: [`docs/TEST_COVERAGE_MATRIX.md`](docs/TEST_COVERAGE_MATRIX.md)

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

The [DiscOS repository](https://github.com/jverdicc/DiscOS) includes:

- a Rust client
- a Python client example

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
