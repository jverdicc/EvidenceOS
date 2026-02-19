# Protocol Versioning

## Canonical protocol version

EvidenceOS canonical gRPC package is **`evidenceos.v2`**.

- Canonical proto source: `crates/evidenceos-protocol/proto/evidenceos.proto`.
- Rust generated modules: `evidenceos_protocol::pb::v2::*`.

## `evidenceos.v1` compatibility and deprecation

EvidenceOS currently serves `evidenceos.v1` for DiscOS compatibility.

- Compatibility package source: `crates/evidenceos-protocol/proto/evidenceos_v1.proto`.
- Rust generated modules: `evidenceos_protocol::pb::v1::*`.
- Server behavior: v1 RPCs are translated to the same internal implementation used by v2.

Deprecation policy:

1. v1 remains available for a minimum of **two minor releases** after a published deprecation notice.
2. Removal requires:
   - release notes entry,
   - migration guidance in README/docs,
   - integration test updates proving v2 parity.

## Compatibility guarantee window

EvidenceOS maintains a rolling compatibility window:

- Current major (`v2`): full support.
- Previous major (`v1`): compatibility mode with bug/security fixes only.
- Older majors: unsupported.

Within the window, wire compatibility is preserved for existing fields and RPCs.

## Safe proto regeneration workflow

1. Edit only files under `crates/evidenceos-protocol/proto/`.
2. Regenerate via Cargo build (uses vendored `protoc` via `build.rs`).
3. Run:

```bash
cargo test -p evidenceos-protocol
cargo test -p evidenceos-daemon protocol_compat_system
cargo test -p evidenceos-daemon daemon_protocol_v1_and_v2_smoke
```

4. Confirm compatibility tests pass before merge.
5. If proto files changed intentionally, update protocol snapshot checks.
