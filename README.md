<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18685556.svg)](https://zenodo.org/records/18685556)

# EvidenceOS (Rust)

**EvidenceOS** is a production-oriented verification kernel for the Universal Verification Protocol (UVP).

- **EvidenceOS** (this repo): trusted kernel that enforces admissibility, deterministic execution, metered oracle access, and auditable settlement.
- **DiscOS** (separate repo): untrusted discovery/userland orchestrator that proposes claim capsules and consumes kernel responses.
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
```

## IPC API

EvidenceOS exposes gRPC/Protobuf APIs defined in:

- `proto/evidenceos.proto`

The DiscOS repository includes:

- a Rust client
- a Python client example

If you are following older DiscOS docs/examples that reference `--etl-path`, update those invocations to EvidenceOS's current `--data-dir` flag.

## Claim lifecycle API

The daemon exposes a one-way claim lifecycle:

`CreateClaim -> CommitArtifacts -> FreezeGates -> SealClaim -> ExecuteClaim`

Read APIs are available for capsule retrieval, daemon public-key retrieval (`GetPublicKey`), signed tree heads, inclusion proofs, consistency checks, and revocation feeds.

Signature verification is in-band: clients fetch the Ed25519 public key and `key_id` (`sha256(public_key)`) via `GetPublicKey`, then verify SignedTreeHead and revocation-feed signatures against domain-separated prehashes (`evidenceos:sth:v1` and `evidenceos:revocations:v1`).

Key rotation strategy: rotation is not supported yet. The daemon persists a single signing key under `keys/etl_signing_ed25519`; replacing this key changes `key_id` and will invalidate verification for signatures produced under the previous key unless clients retain historical keys keyed by `key_id`.

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
