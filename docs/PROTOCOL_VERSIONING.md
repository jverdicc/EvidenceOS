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


## Server self-identification and drift checks

EvidenceOS exposes `GetServerInfo` on both `evidenceos.v2` and compatibility `evidenceos.v1`.

`GetServerInfoResponse` includes:

- `protocol_semver`: semantic version for the canonical protocol contract (currently `2.1.0`).
- `proto_hash`: SHA-256 of canonical `crates/evidenceos-protocol/proto/evidenceos.proto`.
- `build_git_commit`: daemon build commit (or `unknown` when omitted at build-time).
- `build_time_utc`: daemon build timestamp (or `unknown` when omitted at build-time).
- `daemon_version`: binary crate version.
- `feature_flags`: runtime hardening feature gates (TLS/mTLS/registry/insecure toggles).

Client policy (DiscOS):

1. Hard-fail on protocol major mismatch.
2. Hard-fail on `proto_hash` mismatch unless explicitly overridden (for example, `--allow-protocol-drift`).
3. Validate `daemon_version` is within the pinned compatibility range published by `evidenceos-protocol` (`>=0.1.0-alpha, <0.2.0` in this release).
4. In production mode, fail closed on daemon-version mismatch with an actionable upgrade/downgrade message; in development mode, continue with an explicit warning.
5. Log the returned metadata for auditability.

## Dependency source pinning (DiscOS + EvidenceOS)

`evidenceos-protocol` is the canonical shared dependency for both daemon and DiscOS clients.

- Preferred source: crates.io release of `evidenceos-protocol`, pinned by semver.
- Fallback source: git dependency pinned to the exact commit corresponding to the EvidenceOS release tag.
- Do **not** depend on a different upstream repo copy of protocol definitions when validating compatibility, to avoid protocol drift.
