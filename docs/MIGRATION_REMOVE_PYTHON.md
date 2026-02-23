<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Migration note: remove Python from runtime path (future optional)

This repository is **Rust-first at runtime**: the verification kernel and daemon are implemented in Rust.

Python still exists in this repo for non-runtime workflows:

- `analysis/` for paper reproduction and analysis tooling.
- `artifacts/forc10/original_python/` for archival comparison material.

## Current state

- **Runtime/kernel path:** Rust-only.
- **Research/reproduction path:** Rust + Python support artifacts.

## What “remove Python” would mean

A complete Python removal would require all of the following:

1. Port or retire analysis/reproduction scripts currently under `analysis/`.
2. Replace or archive `artifacts/forc10/original_python/` outside the main repo.
3. Update all docs and reproducibility instructions that depend on Python tooling.
4. Ensure CI and release evidence remain reproducible without Python.

Until those are complete, this document remains a planning note rather than an active migration command.
