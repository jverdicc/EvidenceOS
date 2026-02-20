# TEE integration roadmap (interface-only)

This repository does **not** claim active TEE protection today.

Current status:

- Added a placeholder interface in `evidenceos-core::tee` (`TeeAttestor`, `TeeError`).
- No runtime TEE backend is linked.
- No security guarantees are implied by this placeholder.

Planned direction:

1. Feature-flagged backend adapters (e.g. SGX/TDX/SEV where appropriate).
2. Measurement binding for kernel binaries and critical config.
3. Attestation embedding in capsule/settlement metadata.
4. Verification policy hooks in daemon startup and settlement import paths.

Until implemented and audited, deployment should treat TEE as unavailable.
