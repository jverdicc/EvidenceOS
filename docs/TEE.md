# TEE integration status

EvidenceOS includes runtime-selectable TEE attestation backends. This is not roadmap-only: backend selection and attestation collection are active code paths.

## TeeBackend values implemented today

`TeeBackend` currently supports:

- `disabled` (default): no attestation backend loaded.
- `noop`: development/test backend that emits synthetic attestations.
- `amd-sev-snp` (alias `sev-snp`): AMD SEV-SNP helper-backed backend.

These values are selected with `EVIDENCEOS_TEE_BACKEND`.

## Backend behavior and readiness

### 1) disabled

- No attestation is collected.
- Suitable for environments where TEE attestation is intentionally unavailable.

### 2) noop (**development-only; not production-safe**)

- Requires explicit opt-in: `EVIDENCEOS_TEE_ALLOW_NOOP=1` (or `true`).
- Returns synthetic payload with `NOOP_ATTESTATION_DO_NOT_USE_IN_PRODUCTION` prefix.
- Daemon logs a warning when enabled.

Security posture: **experimental/dev-only**. No hardware trust guarantees.

### 3) amd-sev-snp (**experimental integration path**)

- Invokes an external helper executable.
- Expected helper path:
  - from `EVIDENCEOS_SEV_SNP_HELPER`, or
  - default `/usr/local/bin/evidenceos-sev-snp-attest`.
- Helper is called as:
  - `<helper> --report-data <measurement_sha256_hex>`

#### Output contract

- Helper must exit `0` on success.
- Helper must write a non-empty attestation blob to `stdout`.
- Any non-zero exit status or empty `stdout` is treated as backend failure.
- EvidenceOS base64-encodes returned bytes into `attestation_blob_b64`.

#### Security assumptions

- The helper binary and its filesystem path are trusted and protected from tampering.
- Host/OS compromise that can replace/interpose helper execution is out of scope for this backend.
- Returned blob authenticity/chain validation is deployment-dependent and must be verified by policy tooling (e.g., `evidenceos-attest` workflows).

Security posture: **experimental** until deployment-specific verification and hardening are complete.

## Measurement binding behavior

- EvidenceOS computes `measurement_sha256_hex` from the input measurement bytes.
- For SEV-SNP backend, that hex digest is passed as `--report-data` to helper.
- Final report object includes:
  - `backend_name`
  - `measurement_hex`
  - `attestation_blob_b64`

## Operational guidance

- Use `disabled` unless you have a validated attestation verification pipeline.
- Use `noop` only in local/dev environments.
- Treat `amd-sev-snp` as experimental integration and gate promotion behind attestation verification tests.

## Code references

- `crates/evidenceos-core/src/tee.rs`
- `crates/evidenceos-daemon/src/server/core.rs`
- `crates/evidenceos-attest/src/lib.rs`
