<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18685556.svg)](https://zenodo.org/records/18685556)

# EvidenceOS (Rust)

**EvidenceOS** is a *verification-kernel* reference implementation written in Rust.

It is designed around the UVP paper's kernel/userland split:

- **EvidenceOS**: small trusted kernel exposing *quantized, metered* oracle access plus an append-only **Evidence Transparency Log (ETL)**.
- **DiscOS** (separate repo): untrusted discovery/userland that interacts with the kernel via IPC.

This repository contains:

- `evidenceos-core`: Conservation Ledger primitives, deterministic logical clock, ETL Merkle log, and an ASPEC-like Wasm verifier.
- `evidenceos-daemon`: a gRPC service exposing the kernel API.

## Technical Summary

EvidenceOS is designed as a verification kernel that enforces a narrow set of protocol guarantees while leaving fast-moving orchestration outside the trusted boundary. At a high level, the system separates **admissibility**, **deterministic execution**, **conservation accounting**, and **audit transparency** so each can be reasoned about independently and tested through public interfaces. This keeps the kernel small enough to review while still supporting practical claim-processing pipelines.

The first layer is **ASPEC admissibility**. Instead of treating any arbitrary computation as valid policy logic, EvidenceOS runs constrained verification programs and applies explicit acceptance criteria. The intent is to fail closed when inputs, structure, or verifier behavior do not meet policy constraints. In other words, admissibility is not “did code run,” but “did a bounded verifier produce an acceptable, typed outcome under kernel rules.” This distinction matters for outside contributors because safety depends on preserving those acceptance boundaries, not expanding implicit behavior.

The second layer is **sealed deterministic execution**. Claims move through a lifecycle that freezes relevant inputs before execution, making later verification reproducible. Determinism here means equivalent inputs should produce equivalent canonical bytes, hashes, and outcomes independent of runtime accidentals (for example iteration order drift). Deterministic execution is paired with explicit checks in tests for ordering and repeatability, because reproducibility is a protocol property rather than a performance optimization.

The third layer is the **conservation ledger**. Certification-relevant state transitions are metered and recorded so support cannot be “created” by orchestration shortcuts. Kernel decisions are tied to tracked accounting transitions rather than hidden side effects. This gives contributors a concrete rule of thumb: if a change influences certification-relevant state, it must remain conserved, monotone where required, and observable through the same public behavior expected by existing tests.

The fourth layer is **oracle quantization and hysteresis**. Oracle-related signal is intentionally discretized and guarded against unstable threshold oscillation. Quantization provides predictable stepwise behavior; hysteresis prevents noisy back-and-forth transitions near boundaries. Together they reduce ambiguity in repeated evaluations and make boundary-case testing (exact cutoffs, near-cutoffs, invalid numeric values) central to review quality.

The fifth layer is **ETL auditability and revocation**. EvidenceOS appends signed transparency entries to a Merkle-backed log, allowing clients to verify inclusion and consistency over time. Revocation is modeled as additive signed disclosure rather than history mutation, preserving audit trails while allowing invalidation signals to propagate. This supports “verify what changed and when” without rewriting prior log state.

Across all layers, the motivation is **structured claims**: machine-checkable claim capsules with canonicalized content and explicit provenance hooks. Structured claims reduce interpretation ambiguity, make deterministic verification feasible, and improve independent reproducibility for downstream auditors. They do not replace legal or institutional judgment; rather, they provide a stable technical substrate that external processes can inspect, replay, and challenge with cryptographic and accounting evidence.

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

### 3) Test

```bash
cargo test --workspace
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
