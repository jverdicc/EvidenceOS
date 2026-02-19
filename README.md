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

EvidenceOS + DiscOS are intended to be read as one protocol split across trust boundaries. EvidenceOS is the verification kernel: a small, stateful service that owns conserved accounting, append-only transparency state, and policy-verification primitives. DiscOS is userland: orchestration, retrieval, ranking, and UX logic that can evolve rapidly without inheriting kernel trust. In practice, DiscOS gathers candidate evidence and prepares claims, while EvidenceOS decides what can be certified, under explicit metering and deterministic state transitions.

At execution time, claims flow through a lifecycle (`CreateClaim -> CommitArtifacts -> FreezeGates -> SealClaim -> ExecuteClaim`) so inputs are fixed before certification decisions are made. Structured claims are represented as capsules: immutable bundles containing canonicalized claim content, metadata, and artifact commitments. Canonicalization is designed to produce deterministic bytes for semantically identical structured claims (e.g., stable ordering and normalized encodings), so signatures, hashes, and inclusion proofs are reproducible across independent verifiers.

The ASPEC verifier in `evidenceos-core` is the policy-checking surface. It runs a constrained verification program (Wasm) against the sealed claim context and returns typed verifier outcomes rather than arbitrary side effects. This gives userland flexibility in policy expression while keeping kernel enforcement narrow: userland proposes, the kernel verifies and records. The verifier result is therefore one input to certification, not a bypass around conserved accounting.

Oracle interaction is quantized: instead of unconstrained confidence accumulation, the kernel meters epistemic contribution as discrete e-value-relevant units under fixed rules. The key idea is that evidence can increase support only through accounted steps; it cannot be minted ad hoc by orchestration code. This is where the Conservation Ledger matters: every certified outcome must clear a certification barrier backed by tracked state transitions and bounded contributions. If the required conservation conditions are not satisfied, the claim can be processed but not certified.

Transparency is provided by the ETL (Evidence Transparency Log), an append-only Merkle log maintained by the daemon. Clients can obtain Signed Tree Heads, request inclusion proofs for specific leaves, and perform consistency checks between tree sizes to detect equivocation or history rewrites. Revocations are published as signed feed entries, so prior certified material can be marked invalid without deleting historical log data. Operationally, this supports “append + disclose + prove” rather than mutable audit records.

Certification therefore has a precise meaning: a claim passed kernel policy checks, satisfied conservation constraints, and was committed into auditable transparency state with verifiable proofs. Certification does **not** mean legal adjudication, factual omniscience, or regulatory endorsement by itself; downstream legal or institutional interpretation remains external. For citation, use the project DOI for software artifacts (Zenodo concept DOI) and separately cite the paper as **Under review at FORC 2026** until proceedings metadata is finalized. Avoid language implying acceptance, legal finality, or guarantees beyond the protocol’s cryptographic and accounting scope.

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
