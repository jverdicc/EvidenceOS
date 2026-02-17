<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# EvidenceOS (Rust)

**EvidenceOS** is a *verification-kernel* reference implementation written in Rust.

It is designed around the UVP paper's kernel/userland split:

- **EvidenceOS**: small trusted kernel exposing *quantized, metered* oracle access plus an append-only **Evidence Transparency Log (ETL)**.
- **DiscOS** (separate repo): untrusted discovery/userland that interacts with the kernel via IPC.

This repository contains:

- `evidenceos-core`: Conservation Ledger, OracleResolution + hysteresis, deterministic logical clock, ETL Merkle log, and an ASPEC-like Wasm verifier.
- `evidenceos-daemon`: a gRPC service exposing the kernel API.

## Quickstart

### 1) Build

```bash
cargo build --workspace
```

### 2) Run the kernel

```bash
cargo run -p evidenceos-daemon -- \
  --listen 127.0.0.1:50051 \
  --etl-path ./data/etl.log
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

## Notes on security & determinism

This is a **reference implementation**. Production deployments must:

- treat simulation endpoints (`InitHoldout`) as dev-only
- isolate kernel execution (sandbox, seccomp, VM, etc.)
- harden storage, auditing, and key management

## License

Apache-2.0

## Protobuf toolchain

This repo uses a **vendored protoc** (`protoc-bin-vendored`) so contributors and CI do not need to install `protoc`.

## Container / deployment

A `Dockerfile`, `docker-compose.yml`, and a hardened `systemd` unit are provided under `deploy/systemd/`.
