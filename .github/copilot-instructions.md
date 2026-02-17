# GitHub Copilot instructions for EvidenceOS

This repository is a Rust workspace. When making changes:

1. **Do not introduce Python** into the kernel implementation. EvidenceOS is Rust-only.
2. Keep the *kernel surface small*: prefer changes in `evidenceos-core` and keep `evidenceos-daemon` thin.
3. Always update and compile the protobuf API when changing `proto/evidenceos.proto`.
   - Run: `cargo build -p evidenceos-daemon` (this regenerates code via `build.rs`).
4. Keep IPC outputs **canonical and stable**:
   - Oracle replies must remain fixed-meaning bucket indices.
   - Avoid adding variable-length fields to `OracleReply`.
5. Testing discipline:
   - Unit tests live next to modules in `evidenceos-core/src/*`.
   - gRPC smoke tests live in `evidenceos-daemon/src/server.rs` under `#[cfg(test)]`.
   - CI must pass `cargo fmt`, `cargo clippy -D warnings`, and `cargo test`.
6. Determinism:
   - Avoid using wall-clock time.
   - Do not add randomness unless it is explicitly seeded/deterministic.

## Local dev commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p evidenceos-daemon -- --listen 127.0.0.1:50051 --etl-path ./data/etl.log
```
