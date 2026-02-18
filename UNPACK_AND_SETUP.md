<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Unpack & setup (EvidenceOS)

## 1) Unpack

```bash
unzip EvidenceOS.zip -d EvidenceOS
cd EvidenceOS
```

## 2) Initialize git and push

```bash
git init
git add -A
git commit -m "Initial EvidenceOS Rust kernel"

# then add your GitHub remote
# git remote add origin git@github.com:<your-org>/EvidenceOS.git
# git push -u origin main
```

## 3) Build / test

```bash
cargo test --workspace
cargo run -p evidenceos-daemon -- --listen 127.0.0.1:50051 --data-dir ./data
```

## 4) Protobuf

This repo uses a **vendored protoc** via `protoc-bin-vendored`, so you do not need a system `protoc`.

If you edit `proto/evidenceos.proto`, rebuild:

```bash
cargo build -p evidenceos-daemon
```

## 5) Remove legacy Python (if migrating)

See `MIGRATION_REMOVE_PYTHON.md`.
