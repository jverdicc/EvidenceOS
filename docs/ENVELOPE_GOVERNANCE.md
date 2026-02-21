# Envelope Governance

Magnitude envelope policy is governed through signed `EnvelopePack` documents (`evidenceos.magnitude-envelope-pack.v1`).

## EnvelopePack fields

- `metadata.pack_id`: SHA-256 of canonical unsigned pack payload.
- `metadata.version`: monotonic issuer version.
- `metadata.valid_from_unix` / `metadata.valid_to_unix`: validity window used by runtime verification.
- `metadata.issuer`: key id looked up in trusted issuer keyring.
- `metadata.signature_ed25519_b64`: detached Ed25519 signature over canonical unsigned pack payload.
- `envelopes[]`: policy entries with stable `envelope_id`, target `profile_id`, `schema_id`, and quantity constraints.

## Operational flow

1. Author an unsigned pack JSON.
2. Sign it with `evidenceos-envelope sign --in pack.json --key issuer.key --out pack.signed.json`.
3. Verify with `evidenceos-envelope verify --pack pack.signed.json --trusted-keys keys.json`.
4. Place verified packs under daemon `envelope_packs_dir`.
5. Send SIGHUP to daemon to reload packs without downtime.

## Production requirements

- In production (`EVIDENCEOS_PRODUCTION_MODE=1`), daemon defaults `require_signed_envelopes=true`.
- Unsigned packs are rejected when `require_signed_envelopes` is enabled.
- Runtime validates issuer trust, signature, pack id, and validity window before accepting policy.

## Rotation

Key rotation is handled by overlapping validity windows:

- Keep old and new issuer keys in `trusted_envelope_issuer_keys` during transition.
- Publish old and new signed packs with overlap in validity ranges.
- Reload via SIGHUP; verification accepts both packs in overlap window.
- After transition window, remove old key and expired old pack.
